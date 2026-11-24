"""Aegis shell analyzer: quote-aware, allowlist-based command inspection.

Instead of matching dangerous strings, every command line is parsed into segments
(split on ; && || | & and newlines, respecting quotes), and each segment's binary is
looked up in an explicit table. Known binaries have their path / URL arguments checked
against the workspace and the network allowlist; anything unknown is routed to the owner.

Handles POSIX sh, PowerShell and cmd.exe spellings, command substitution, heredocs,
redirects, wrappers (env, xargs, timeout, nohup ...), nested shells (bash -c, cmd /c,
powershell -Command) and the working directory changes made by cd within one command.
"""

from __future__ import annotations

import base64
import glob
import itertools
import os
import re
import shlex
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from . import boundaries
from .core import DecisionLevel, Verdict
from .canonicalizer import home_dir, is_inside, looks_windows_path, normalize_text, resolve_path
from .policy import (
    DEFAULT_POLICY,
    AegisPolicy,
    classify_sensitive,
    glob_component_matches,
    has_glob,
    is_catastrophic_target,
    is_exfil_sink,
    is_generic_wildcard,
)

NAME = "Tartarus"
L = DecisionLevel
MAX_DEPTH = 6

# ---------------------------------------------------------------------------
# Binary tables
# ---------------------------------------------------------------------------

NO_PATH_BINARIES = {
    "echo", "printf", "true", "false", ":", "pwd", "date", "whoami", "id", "uname", "hostname",
    "which", "sleep", "[[", "]]", "test", "[", "seq", "expr", "clear", "tput", "nproc", "uptime",
    "locale", "groups", "tty", "basename", "dirname", "exit", "return", "read", "wait", "jobs",
    "fg", "bg", "alias", "unalias", "shopt", "umask", "ulimit", "trap", "local", "readonly",
    "unset", "hash", "getconf", "arch", "cal", "yes", "free", "ps", "top", "htop", "df",
    "write-output", "write-host", "write", "get-date", "get-location", "gl",
    "get-process", "gps", "get-computerinfo", "get-command", "gcm", "get-help", "help", "measure-object", "measure",
    "select-object", "select", "sort-object", "where-object", "foreach-object",
    "format-table", "ft", "format-list", "fl", "out-string", "out-null", "out-default",
    "convertto-json", "convertfrom-json", "convertto-csv", "convertfrom-csv",
    "split-path", "join-path", "get-host", "cls", "ver", "systeminfo",
    "get-service", "gsv", "get-nettcpconnection", "test-netconnection", "tnc",
    "get-volume", "get-disk", "get-pnpdevice", "get-ciminstance", "gcim",
    "nvidia-smi", "lscpu", "lspci", "lsblk", "lsusb",
}

READ_BINARIES = {
    "ls", "cat", "head", "tail", "less", "more", "wc", "file", "stat", "du", "tree", "diff",
    "cmp", "md5sum", "sha1sum", "sha256sum", "sha512sum", "shasum", "realpath", "readlink",
    "sort", "uniq", "cut", "paste", "join", "comm", "column", "nl", "od", "xxd", "hexdump",
    "strings", "base64", "tac", "rev", "fold", "fmt", "expand", "unexpand", "iconv", "zcat",
    "bat", "fd", "exa", "eza", "lsof", "type",
    # PowerShell / cmd read-only
    "get-childitem", "gci", "dir", "get-content", "gc", "get-item", "gi", "get-itemproperty",
    "gp", "test-path",
    "resolve-path", "get-filehash", "get-acl", "findstr", "where", "fc", "comp", "certutil-hash",
}

PATTERN_FIRST = {"grep", "egrep", "fgrep", "rg", "ag", "ack", "jq", "yq", "select-string", "sls"}

WRITE_BINARIES = {
    "mkdir", "touch", "cp", "mv", "ln", "install", "truncate", "tee", "split",
    "csplit", "patch", "gzip", "gunzip", "xz", "unxz", "bzip2", "bunzip2", "zstd", "unzstd",
    "7z", "7za", "zip", "unzip", "chown", "chgrp", "rename",
    # PowerShell / cmd
    "set-content", "add-content", "ac", "out-file", "new-item", "ni", "md", "copy-item", "copy",
    "cpi", "move-item", "move", "mi", "rename-item", "ren", "rni", "expand-archive",
    "compress-archive", "xcopy", "mklink",
}

DELETE_BINARIES = {"rm", "rmdir", "unlink", "shred", "srm", "remove-item", "ri", "del", "erase", "rd"}

SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "ash", "busybox"}
POWERSHELLS = {"powershell", "pwsh"}
INTERPRETERS = {
    "python", "python2", "python3", "pythonw", "py", "pypy", "pypy3", "node", "nodejs", "deno",
    "bun", "perl", "ruby", "php", "lua", "luajit", "rscript", "tclsh", "julia", "ts-node", "tsx",
    "groovy", "scala", "irb",
}
INLINE_FLAGS_BY = {
    "python3": {"-c"}, "python": {"-c"}, "python2": {"-c"}, "pythonw": {"-c"}, "py": {"-c"},
    "pypy": {"-c"}, "pypy3": {"-c"},
    "node": {"-e", "--eval", "-p", "--print"}, "nodejs": {"-e", "--eval", "-p", "--print"},
    "ts-node": {"-e", "--eval", "-p", "--print"}, "tsx": {"-e", "--eval", "-p", "--print"},
    "perl": {"-e", "-E"}, "php": {"-r"}, "julia": {"-e", "--eval"},
}
VALUE_OPTS_BY = {
    "python3": {"-X", "-W", "--check-hash-based-pycs"},
    "node": {"-r", "--require", "--import", "--loader", "--experimental-loader", "--input-type", "--env-file"},
    "ruby": {"-I", "-r", "-C"}, "perl": {"-I", "-M", "-m"}, "php": {"-c", "-d", "-z"},
}
PS_VERBS = {"get", "set", "new", "remove", "copy", "move", "rename", "invoke", "start", "stop",
            "restart", "add", "out", "select", "where", "foreach", "test", "write", "clear",
            "format", "import", "export", "convertto", "convertfrom", "measure", "sort",
            "resolve", "split", "join", "expand", "compress", "initialize", "enable", "disable",
            "install", "uninstall", "update", "register", "unregister", "push", "pop", "read",
            "send", "receive", "connect", "disconnect", "suspend", "resume", "wait", "show"}

PROJECT_TOOLS = {
    "make", "cmake", "ninja", "meson", "cargo", "rustc", "go", "gcc", "g++", "cc", "clang",
    "clang++", "javac", "java", "mvn", "gradle", "gradlew", "dotnet", "msbuild", "tsc", "vite",
    "next", "jest", "vitest", "mocha", "eslint", "prettier", "ruff", "black", "isort", "mypy",
    "pylint", "flake8", "pytest", "tox", "nox", "poetry", "pipenv", "hatch", "uv", "pdm",
    "npm", "pnpm", "yarn", "pip", "pip3", "pipx", "gem", "bundle", "composer", "swift",
    "xcodebuild", "webpack", "rollup", "esbuild", "turbo", "nx", "lerna", "playwright",
    "cypress", "storybook", "astro", "nuxt", "svelte-kit", "coverage", "pre-commit", "tsc",
    "uvicorn", "gunicorn", "hypercorn", "flask", "django-admin", "streamlit", "alembic", "celery",
    "prisma", "drizzle-kit", "sqlite3", "jupyter", "nodemon", "corepack", "gofmt", "golangci-lint",
    "rustfmt", "clippy-driver", "wasm-pack", "biome", "stylelint", "sass", "postcss", "tailwindcss",
    "pyright", "bandit", "pip-compile", "pip-sync", "maturin", "sphinx-build", "mkdocs", "hugo",
}
NETWORK_FETCHERS = {"curl", "wget", "http", "https", "aria2c", "invoke-webrequest", "iwr",
                    "invoke-restmethod", "irm", "start-bitstransfer"}
REMOTE_TOOLS = {"ssh", "scp", "sftp", "nc", "ncat", "netcat", "socat", "telnet", "ftp", "tftp",
                "nmap", "ssh-copy-id", "mosh", "rclone", "smbclient"}
SYSTEM_LOCK = {
    "mkfs", "fdisk", "sfdisk", "gdisk", "sgdisk", "parted", "wipefs", "mkswap", "shutdown",
    "reboot", "poweroff", "halt", "format", "diskpart", "stop-computer", "restart-computer",
    "format-volume", "clear-disk", "remove-partition", "initialize-disk",
}
PRIVILEGE = {"sudo", "su", "doas", "pkexec", "runas", "gsudo", "sudo.exe"}
DENY_BINARIES = {"useradd", "userdel", "usermod", "passwd", "chpasswd", "visudo", "groupadd",
                 "groupdel", "adduser", "deluser", "chroot", "insmod", "rmmod", "modprobe"}
ASK_BINARIES = {
    "kill", "pkill", "killall", "stop-process", "spps", "taskkill", "crontab", "at", "batch",
    "launchctl", "schtasks", "systemd-run", "iptables", "ip6tables", "nft", "ufw",
    "firewall-cmd", "netsh", "mount", "umount", "losetup", "chattr", "setfacl", "icacls",
    "cacls", "takeown", "attrib", "reg", "regedit", "sc", "wmic", "bcdedit", "wevtutil",
    "net", "setx", "powercfg", "cipher", "history", "open", "xdg-open", "start", "explorer",
    "invoke-item", "ii", "invoke-expression", "iex", "invoke-command", "icm", "start-process",
    "saps", "start-job", "add-type", "set-executionpolicy", "set-itemproperty",
    "new-itemproperty", "remove-itemproperty", "new-service", "strace", "ltrace", "gdb",
    "osascript", "docker", "podman", "kubectl", "helm", "terraform", "aws", "gcloud", "az",
    "gh", "npx", "bunx", "pnpx", "uvx", "conda", "mamba", "brew", "apt", "apt-get", "dnf",
    "yum", "pacman", "snap", "choco", "winget", "scoop",
}
WRAPPERS = {"command", "builtin", "exec", "nohup", "time", "nice", "ionice", "stdbuf", "timeout",
            "watch", "unbuffer", "caffeinate", "call"}
CMD_BUILTINS = {"dir", "type", "copy", "move", "del", "erase", "rd", "rmdir", "md", "mkdir",
                "ren", "rename", "xcopy", "robocopy", "cls", "findstr", "where", "fc", "attrib",
                "mklink", "start", "call", "ver", "set"}

SAFE_PY_MODULES = {"pip", "venv", "virtualenv", "pytest", "unittest", "doctest", "json.tool",
                   "py_compile", "compileall", "ensurepip",
                   "mypy", "black", "ruff", "flake8", "pylint", "isort", "coverage",
                   "tox", "nox", "site", "sysconfig", "platform", "this", "pyflakes"}
# Modules that execute workspace code or load workspace plugins/hooks via config files
# even when Python is invoked with -I or -P.
ALWAYS_PROJECT_EXEC_PY_MODULES = {"pytest", "unittest", "tox", "nox", "doctest", "coverage",
                                  "mypy", "pylint", "flake8"}

# Per-binary option and positional-output rules for READ_BINARIES so output flags
# (including attached -oPATH and bundled -uoPATH) and positional outputs (uniq/xxd)
# are checked in "write" mode and exec flags (sort --compress-program, fd -x) ask.
_READ_TOOL_SPEC: Dict[str, Dict[str, object]] = {
    "sort": {
        "write_opts": {"-o", "--output", "-T", "--temporary-directory"},
        "read_opts": {"--files0-from", "--random-source"},
        "ask_opts": {"--compress-program"},
        "value_opts": {"-k", "--key", "-t", "--field-separator", "-S", "--buffer-size", "--batch-size", "--parallel"},
    },
    "iconv": {
        "write_opts": {"-o", "--output"},
        "value_opts": {"-f", "--from-code", "-t", "--to-code"},
    },
    "tree": {
        "write_opts": {"-o"},
        "value_opts": {"-L", "-P", "-I", "--filelimit", "-H", "-T", "--charset", "--timefmt", "--sort"},
    },
    "base64": {
        "write_opts": {"-o", "--output"},
        "read_opts": {"-i", "--input"},
        "value_opts": {"-w", "--wrap", "-b", "--break"},
    },
    "less": {
        "write_opts": {"-o", "-O", "--log-file", "--LOG-FILE"},
        "read_opts": {"-k", "--lesskey-file", "--lesskey-src"},
        "value_opts": {"-p", "-P", "-j", "-x", "-z", "-h", "-y", "-b", "-#"},
    },
    "more": {
        "write_opts": {"-o", "-O", "--log-file", "--LOG-FILE"},
        "value_opts": {"-n"},
    },
    "uniq": {
        "write_from_pos": 1,
        "value_opts": {"-f", "--skip-fields", "-s", "--skip-chars", "-w", "--check-chars"},
    },
    "xxd": {
        "write_from_pos": 1,
        "value_opts": {"-c", "-cols", "--cols", "-g", "-groupsize", "--groupsize",
                       "-l", "-len", "--len", "-o", "-s", "-seek", "-n", "-name"},
    },
    "file": {
        "read_opts": {"-f", "--files-from", "-m", "--magic-file"},
        "value_opts": {"-F", "--separator", "-P", "--parameter", "-e", "--exclude"},
    },
    "du": {
        "read_opts": {"--files0-from"},
        "value_opts": {"-d", "--max-depth", "-B", "--block-size", "-t", "--threshold", "--exclude"},
    },
    "wc": {"read_opts": {"--files0-from"}},
    "diff": {
        "read_opts": {"-X", "--exclude-from"},
        "value_opts": {"-U", "-C", "-x", "--exclude", "-I", "-L", "--label", "-W", "--width"},
    },
    "hexdump": {"read_opts": {"-f"}, "value_opts": {"-e", "-n", "-s"}},
    "fd": {
        "ask_opts": {"-x", "--exec", "-X", "--exec-batch"},
        "value_opts": {"-d", "--max-depth", "-t", "--type", "-e", "--extension", "-E", "--exclude", "--search-path"},
    },
    "findstr": {"win_read_prefixes": ("/f:", "/g:", "/d:")},
}

SAFE_PS_MEMBERS = frozenset({
    "tostring", "touniversaltime", "tolocaltime", "toshortdatestring", "tolongdatestring",
    "toshorttimestring", "tolongtimestring", "tofiletime", "tofiletimeutc",
    "tounixtimeseconds", "tounixtimemilliseconds", "trim", "trimstart", "trimend",
    "tolower", "toupper", "tolowerinvariant", "toupperinvariant", "substring",
    "replace", "split", "contains", "startswith", "endswith", "indexof",
    "padleft", "padright", "length", "count", "path", "fullname", "name",
    "basename", "extension", "directoryname", "exists", "psversion", "psedition",
    "version", "versionstring", "major", "minor", "build", "revision",
    "year", "month", "day", "hour", "minute", "second", "millisecond",
    "dayofweek", "dayofyear", "date", "timeofday", "ticks", "totalmilliseconds",
    "totalseconds", "totalminutes", "totalhours", "totaldays", "keys", "values", "value",
})
SAFE_PS_AUTO_VARS = frozenset({
    "$psversiontable", "$pwd", "$pid", "$psculture", "$psuiculture",
    "$iswindows", "$islinux", "$ismacos", "$true", "$false", "$null",
})
SAFE_PS_STATIC_ROOTS = frozenset({
    "[datetime]::now", "[datetime]::utcnow", "[datetime]::today",
    "[datetimeoffset]::now", "[datetimeoffset]::utcnow",
    "[guid]::newguid", "[environment]::osversion", "[environment]::processorcount",
    "[environment]::version", "[environment]::is64bitos",
    "[environment]::is64bitprocess", "[environment]::newline",
})

DANGEROUS_ENV_OVERRIDES = {"PATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES",
                           "DYLD_LIBRARY_PATH", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME",
                           "PYTHONUSERBASE", "PYTHONINSPECT", "PYTHONBREAKPOINT", "PYTHONEXECUTABLE",
                           "PYTHONPLATLIBDIR", "NODE_OPTIONS", "NODE_PATH", "NODE_EXTRA_CA_CERTS",
                           "BASH_ENV", "ENV", "PROMPT_COMMAND", "GIT_SSH_COMMAND", "GIT_SSH",
                           "GIT_EXEC_PATH", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
                           "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT", "GIT_EXTERNAL_DIFF",
                           "GIT_PAGER", "GIT_DIR", "GIT_WORK_TREE", "GIT_EDITOR", "GIT_ASKPASS",
                           "GIT_TEMPLATE_DIR", "PERL5OPT", "PERL5LIB", "RUBYOPT", "RUBYLIB",
                           "TAPE", "TAR_OPTIONS", "AWKPATH", "AWKLIBPATH",
                           "LESSOPEN", "LESSCLOSE", "PAGER", "MANPAGER", "EDITOR", "VISUAL",
                           "BROWSER", "SHELL", "COMSPEC", "IFS", "CDPATH", "GLOBIGNORE",
                           "GCONV_PATH", "LOCPATH", "ZDOTDIR", "HOME", "USERPROFILE",
                           "XDG_CONFIG_HOME"}

_BENIGN_GIT_ENV_VARS = frozenset({
    "GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL", "GIT_AUTHOR_DATE",
    "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL", "GIT_COMMITTER_DATE",
    "GIT_TERMINAL_PROMPT",
})

_SENSITIVE_CONTROL_DIRS = frozenset({".git", ".githooks", ".husky", ".vscode", ".github", ".devcontainer", ".idea"})


def _is_dangerous_env_var(name: str) -> bool:
    up = (name or "").strip().upper()
    if not up:
        return False
    if up in DANGEROUS_ENV_OVERRIDES:
        return True
    if up.startswith(("LD_", "DYLD_")):
        return True
    if up.startswith("GIT_") and up not in _BENIGN_GIT_ENV_VARS:
        return True
    return False


def _touches_sensitive_control_dir(path_str: str) -> bool:
    if not path_str:
        return False
    parts = [p.rstrip(". ").lower() for p in path_str.replace("\\", "/").split("/") if p]
    for p in parts:
        if p in _SENSITIVE_CONTROL_DIRS:
            return True
        if has_glob(p) and not is_generic_wildcard(p) and any(glob_component_matches(p, d) for d in _SENSITIVE_CONTROL_DIRS):
            return True
    return False
SECRET_VAR_RE = re.compile(
    r"(?:\$\{?|\$env:|%)([A-Za-z_][A-Za-z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|PRIVATE|AUTH)[A-Za-z0-9_]*)",
    re.IGNORECASE,
)
DESTRUCTIVE_CODE_RE = re.compile(
    r"rmtree|rmsync|rmdirsync|remove-item\s+.*-r|format-volume|os\.removedirs|fs\.rm\s*\(|"
    r"shutil\.rmtree|deltree|rimraf",
    re.IGNORECASE,
)
REVERSE_SHELL_RE = re.compile(r"socket\.|\bsocket\(|net\.connect|net\.socket|tcpsocket|fsockopen|/dev/tcp/", re.IGNORECASE)
SYSTEM_BIN_DIRS = ("/usr/bin/", "/bin/", "/usr/local/bin/", "/usr/sbin/", "/sbin/",
                   "/opt/homebrew/bin/", "c:/windows/system32/", "c:/program files/")
SPECIAL_DEVICES = {"/dev/null", "/dev/stdout", "/dev/stderr", "/dev/stdin", "/dev/tty",
                   "/dev/zero", "/dev/urandom", "/dev/random", "nul", "con", "-", "$null"}
BLOCK_DEVICE_RE = re.compile(r"^/dev/(?:sd[a-z]|nvme\d|hd[a-z]|disk\d|mmcblk\d|xvd[a-z]|vd[a-z]|mapper/|md\d)")

_SUBST = "\ue000S{}\ue001"          # placeholder for $(...) / `...` (stripped from real input)
_SUBST_RE = re.compile("\ue000S(\\d+)\ue001")
_SEMI = "\ue000SEMI\ue001"          # escaped/quoted ';' (find -exec terminator)
_OPS = set(";&|()\n")
STDIN_PATHS = {"-", "/dev/stdin", "/dev/fd/0", "/proc/self/fd/0", "/dev/tty"}
SHELL_KEYWORDS = {"if", "then", "else", "elif", "fi", "do", "done", "while", "until", "{", "}",
                  "!", "function", "coproc"}
SKIP_SEGMENT_KEYWORDS = {"for", "select", "case", "esac", "in", ";;"}


@dataclass
class Segment:
    words: List[str] = field(default_factory=list)
    redirects: List[Tuple[str, str]] = field(default_factory=list)
    piped_in: bool = False
    heredoc: Optional[str] = None
    herestring: Optional[str] = None


@dataclass
class _Ctx:
    base_dir: Optional[str]
    cwd: Optional[str]
    policy: AegisPolicy
    depth: int = 0
    findings: List[Tuple[DecisionLevel, str]] = field(default_factory=list)
    untrusted_download: bool = False
    exec_after_download: bool = False
    substitutions: Dict[int, str] = field(default_factory=dict)
    safe_substitutions: set = field(default_factory=set)
    variables: Dict[str, str] = field(default_factory=dict)
    force_windows: bool = False
    # What the command would do, for Minotaur's session view: read_private, fetch, egress ...
    effects: set = field(default_factory=set)
    # Blast-radius measurements of deletes (aegis/impact.py)
    impact: List[dict] = field(default_factory=list)
    destructive: List[dict] = field(default_factory=list)
    boundary: Optional[str] = None


class _Lock(Exception):
    def __init__(self, reason: str, boundary: Optional[str] = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.boundary = boundary


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def analyze_command(
    command: str,
    base_dir: Optional[str] = None,
    cwd: Optional[str] = None,
    policy: Optional[AegisPolicy] = None,
    _depth: int = 0,
    windows: bool = False,
) -> Verdict:
    """windows=True forces cmd/PowerShell parsing (backslashes are path separators)."""
    if not command or not command.strip():
        return Verdict(L.PASS, ["Empty command"], NAME)
    ctx = _Ctx(base_dir=base_dir, cwd=cwd or base_dir, policy=policy or DEFAULT_POLICY, depth=_depth,
               force_windows=windows)
    text = normalize_text(command)
    try:
        hit = boundaries.check_text(text)
        if hit:
            raise _Lock(hit[1], hit[0])
        _analyze(text, ctx)
    except _Lock as lk:
        return Verdict(L.LOCK, [lk.reason], NAME, metadata=_meta(ctx, lk.boundary))
    if ctx.untrusted_download and ctx.exec_after_download:
        ctx.findings.append((L.DENY, "Download-and-execute chain from a non-allowlisted host"))
    if not ctx.findings:
        return Verdict(L.PASS, ["Command passed Tartarus inspection"], NAME, metadata=_meta(ctx))
    top = max(level for level, _ in ctx.findings)
    reasons = list(dict.fromkeys(r for level, r in ctx.findings if level == top))
    from .approval import bind_confirmation
    return bind_confirmation(Verdict(top, reasons, NAME, metadata=_meta(ctx, ctx.boundary)),
                             {"command": command, "cwd": ctx.cwd, "windows": windows})


def _meta(ctx: "_Ctx", boundary: Optional[str] = None) -> dict:
    meta: dict = {"effects": sorted(ctx.effects)}
    if boundary:
        meta["boundary"] = boundary
    if ctx.impact:
        meta["impact"] = ctx.impact
    if ctx.destructive:
        meta["destructive"] = ctx.destructive
    return meta


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _add(ctx: _Ctx, level: DecisionLevel, reason: str) -> None:
    if level >= L.LOCK:
        raise _Lock(reason)
    if level > L.PASS:
        ctx.findings.append((level, reason))


def _extract_heredocs(text: str) -> Tuple[str, List[str], List[bool]]:
    """Remove heredoc bodies; replace each '<<DELIM' marker with '<< HEREDOC_n'."""
    lines = text.split("\n")
    out_lines: List[str] = []
    bodies: List[str] = []
    quoted: List[bool] = []
    pat = re.compile(r"<<(-?)[ \t]*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\2")
    i = 0
    while i < len(lines):
        line = lines[i]
        pending: List[Tuple[str, bool, bool]] = []

        def repl(m: "re.Match[str]") -> str:
            if m.start() > 0 and line[m.start() - 1] == "<":       # '<<<' here-string
                return m.group(0)
            idx = len(bodies) + len(pending)
            pending.append((m.group(3), m.group(1) == "-", bool(m.group(2))))
            return f"<< HEREDOC_{idx}"

        out_lines.append(pat.sub(repl, line))
        i += 1
        for delim, strip_tabs, is_quoted in pending:
            body: List[str] = []
            while i < len(lines):
                ln = lines[i]
                i += 1
                if (ln.lstrip("\t") if strip_tabs else ln).strip() == delim:
                    break
                body.append(ln)
            bodies.append("\n".join(body))
            quoted.append(is_quoted)
    return "\n".join(out_lines), bodies, quoted


def _scan_balanced_parens(text: str, open_idx: int, windows: bool) -> Tuple[str, int, bool]:
    """Scan balanced '(...)' from *open_idx*, respecting quotes and shell escapes."""
    depth = 1
    j = open_idx + 1
    n = len(text)
    in_s = False
    in_d = False
    while j < n:
        c = text[j]
        if in_s:
            if windows and c == "'" and j + 1 < n and text[j + 1] == "'":
                j += 2
                continue
            if c == "'":
                in_s = False
            j += 1
            continue
        if in_d:
            if windows and c == "`" and j + 1 < n:
                j += 2
                continue
            if (not windows) and c == "\\" and j + 1 < n:
                j += 2
                continue
            if c == '"':
                in_d = False
            j += 1
            continue
        if windows and c == "`" and j + 1 < n:
            j += 2
            continue
        if (not windows) and c == "\\" and j + 1 < n:
            j += 2
            continue
        if c == "'":
            in_s = True
            j += 1
            continue
        if c == '"':
            in_d = True
            j += 1
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1 : j], j + 1, True
        j += 1
    return text[open_idx + 1 :], n, False


def _extract_substitutions(text: str, ctx: _Ctx, windows: bool = False) -> str:
    """Replace $(...), `...`, <(...), >(...) outside single quotes with placeholders.

    Each inner command is analyzed recursively right away.
    """
    out: List[str] = []
    i, n = 0, len(text)
    in_single = in_double = False
    while i < n:
        ch = text[i]
        if in_single:
            if windows and ch == "'" and i + 1 < n and text[i + 1] == "'":
                out.append("''")
                i += 2
                continue
            if ch == "'":
                in_single = False
            out.append(ch)
            i += 1
            continue
        if ch == "'" and not in_double:
            in_single = True
            out.append(ch)
            i += 1
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            out.append(ch)
            i += 1
            continue
        if (not windows) and ch == "\\" and i + 1 < n:
            out.append(text[i : i + 2])
            i += 2
            continue
        if windows and ch == "`":
            if i + 1 >= n:
                i += 1
                continue
            nxt = text[i + 1]
            if nxt == "$":
                out.append("$")
                i += 2
                continue
            if nxt == '"':
                out.append("'" if in_double else '"')
                i += 2
                continue
            if nxt == "n":
                out.append("\n")
                i += 2
                continue
            if nxt == "r":
                out.append("\r")
                i += 2
                continue
            if nxt == "t":
                out.append("\t")
                i += 2
                continue
            if nxt == "0":
                i += 2
                continue
            out.append(nxt)
            i += 2
            continue
        if text.startswith("$((", i):
            inner_one, end_one, closed_one = _scan_balanced_parens(text, i + 1, windows)
            if (not windows) and closed_one and inner_one.startswith("(") and inner_one.endswith(")"):
                _, inner_end, inner_closed = _scan_balanced_parens(inner_one, 0, windows)
                if inner_closed and inner_end == len(inner_one):
                    arith_inner = inner_one[1:-1]
                    if re.fullmatch(r"[0-9+\-*/%&|^~<>!=\s()]+", arith_inner):
                        out.append("0")
                        i = end_one
                        continue
        if text.startswith("$(", i) or ((text.startswith("<(", i) or text.startswith(">(", i)) and not in_double):
            inner, end_idx, _ = _scan_balanced_parens(text, i + 1, windows)
            out.append(_register_subst(inner, ctx))
            i = end_idx
            continue
        if (not windows) and ch == "`":
            j = text.find("`", i + 1)
            inner = text[i + 1 : j] if j != -1 else text[i + 1 :]
            out.append(_register_subst(inner, ctx))
            i = (j + 1) if j != -1 else n
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _register_subst(inner: str, ctx: _Ctx) -> str:
    idx = len(ctx.substitutions)
    ctx.substitutions[idx] = inner
    sub = _analyze_nested(inner, ctx)
    first = (inner.strip().split() or [""])[0].lower()
    if sub == L.PASS and first in {"date", "git", "uname", "whoami", "hostname", "basename", "dirname", "nproc", "id"}:
        ctx.safe_substitutions.add(idx)
    return _SUBST.format(idx)


def _lex(text: str, windows: bool) -> List[str]:
    lex = shlex.shlex(text, posix=True, punctuation_chars=";&|()<>\n")
    lex.whitespace = " \t\r"
    lex.whitespace_split = True
    lex.commenters = ""
    if windows:
        lex.escape = ""
    return list(lex)


def _is_safe_ps_arg_token(tok: str) -> bool:
    if not tok or len(tok) > 128:
        return False
    if all(c in "<>&|;()\n" for c in tok):
        return False
    if "$" in tok or _has_subst(tok) or "/" in tok or "\\" in tok:
        return False
    return True


def _is_safe_member_chain(chain: str) -> bool:
    if not chain.startswith("."):
        return False
    parts = chain[1:].split(".")
    return bool(parts) and all(
        bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", p)) and p.lower() in SAFE_PS_MEMBERS
        for p in parts
    )


def _consume_safe_ps_call_args(tokens: List[str], idx: int) -> Optional[int]:
    """If tokens[idx:] starts with '()' or '( <safe args> )', return index after closing ')'."""
    n = len(tokens)
    if idx >= n:
        return None
    if tokens[idx] == "()":
        return idx + 1
    if tokens[idx] != "(":
        return None
    k = idx + 1
    while k < n:
        tok = tokens[k]
        if tok == ")":
            return k + 1
        if tok != "," and not _is_safe_ps_arg_token(tok):
            return None
        k += 1
    return None


def _is_seg_start_op(tok: str) -> bool:
    return tok == _SEMI or (bool(tok) and all(c in ";&|(\n" for c in tok))


def _is_seg_end_op(tok: str) -> bool:
    return tok == _SEMI or (bool(tok) and all(c in "<>&|;)\n" for c in tok))


def _split_ps_root_token(tok: str) -> Tuple[str, str]:
    if "::" in tok:
        idx = tok.find(".", tok.find("::") + 2)
    else:
        idx = tok.find(".")
    if idx == -1:
        return tok, ""
    return tok[:idx], tok[idx:]


def _consume_safe_member_suffix(tokens: List[str], j: int) -> int:
    n = len(tokens)
    while j < n and _is_safe_member_chain(tokens[j]):
        next_idx = _consume_safe_ps_call_args(tokens, j + 1)
        if next_idx is not None:
            j = next_idx
            continue
        if j + 1 < n and tokens[j + 1].startswith("("):
            break
        j += 1
    return j


def _strip_safe_ps_member_chains(tokens: List[str]) -> List[str]:
    """Strip safe read-only PowerShell formatting/member tails while preserving inner commands."""
    out: List[str] = []
    i, n = 0, len(tokens)
    while i < n:
        tok = tokens[i]
        if tok.endswith(")") and all(c == ")" for c in tok) and tok != "()":
            out.append(tok)
            i = _consume_safe_member_suffix(tokens, i + 1)
            continue

        at_seg_start = i == 0 or _is_seg_start_op(tokens[i - 1])
        if at_seg_start:
            root, member_rest = _split_ps_root_token(tok)
            low_root = root.lower()
            if (low_root in SAFE_PS_AUTO_VARS or low_root in SAFE_PS_STATIC_ROOTS) and (
                not member_rest or _is_safe_member_chain(member_rest)
            ):
                j = i + 1
                after_args = _consume_safe_ps_call_args(tokens, j)
                if after_args is not None:
                    j = after_args
                elif j < n and tokens[j].startswith("("):
                    out.append(tok)
                    i += 1
                    continue
                j = _consume_safe_member_suffix(tokens, j)
                if j >= n or _is_seg_end_op(tokens[j]):
                    out.append("true")
                    i = j
                    continue

        out.append(tok)
        i += 1
    return out


def _split_segments(tokens: List[str]) -> List[Segment]:
    segments: List[Segment] = []
    cur = Segment()
    pending_redirect: Optional[str] = None
    for idx, tok in enumerate(tokens):
        if pending_redirect is not None:
            if pending_redirect in ("<<",) and tok.startswith("HEREDOC_"):
                cur.heredoc = tok
            elif pending_redirect == "<<<":
                cur.herestring = tok
            elif pending_redirect.endswith("&") and (tok.isdigit() or tok == "-"):
                pass                                    # fd duplication 2>&1
            else:
                cur.redirects.append((pending_redirect, tok))
            pending_redirect = None
            continue
        is_op = tok and all(c in "<>&|;()\n" for c in tok) and tok != _SEMI
        if is_op and ("<" in tok or ">" in tok):
            if cur.words and cur.words[-1].isdigit() and idx > 0:
                cur.words.pop()                         # fd number before redirect: 2>file
            pending_redirect = tok
            continue
        if is_op:
            piped = tok in ("|", "|&")
            if cur.words or cur.redirects or cur.heredoc:
                segments.append(cur)
            cur = Segment(piped_in=piped)
            continue
        cur.words.append(tok)
    if cur.words or cur.redirects or cur.heredoc:
        segments.append(cur)
    return segments


def _analyze_nested(command: str, ctx: _Ctx, cwd: Optional[str] = None) -> DecisionLevel:
    """Analyze an inner command (bash -c, $(...), find -exec) and merge its findings."""
    if _SUBST_RE.fullmatch(command.strip().strip("'\"")):
        _add(ctx, L.DENY, "Executes the output of a command substitution (dynamically generated code)")
        return L.DENY
    if ctx.depth + 1 > MAX_DEPTH:
        _add(ctx, L.ASK, "Command nesting too deep to analyze")
        return L.ASK
    v = analyze_command(command, base_dir=ctx.base_dir, cwd=cwd or ctx.cwd, policy=ctx.policy, _depth=ctx.depth + 1,
                        windows=ctx.force_windows)
    if v.level >= L.LOCK:
        raise _Lock(v.reasons[0])
    for r in v.reasons:
        _add(ctx, v.level, r)
    return v.level


def _strip_cmd_carets(text: str) -> str:
    """Unescape cmd.exe caret (^) sequences outside single/double quotes."""
    if "^" not in text:
        return text
    out: List[str] = []
    i, n = 0, len(text)
    in_single = in_double = False
    while i < n:
        ch = text[i]
        if ch == "'" and not in_double:
            in_single = not in_single
            out.append(ch)
            i += 1
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            out.append(ch)
            i += 1
            continue
        if ch == "^" and not in_single and not in_double and i + 1 < n:
            out.append(text[i + 1])
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _decode_ansi_c_body(inner: str) -> str:
    """Decode POSIX ANSI-C ($'...') escape sequences; LOCK immediately on NUL byte."""
    simple = {
        "a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f",
        "n": "\n", "r": "\r", "t": "\t", "v": "\v", "\\": "\\",
        "'": "'", '"': '"', "?": "?",
    }
    out: List[str] = []
    i, n = 0, len(inner)
    while i < n:
        ch = inner[i]
        if ch != "\\" or i + 1 >= n:
            out.append(ch)
            i += 1
            continue
        esc = inner[i + 1]
        if esc in simple:
            out.append(simple[esc])
            i += 2
            continue
        if esc == "x":
            m = re.match(r"[0-9a-fA-F]{1,2}", inner[i + 2 :])
            if m:
                cp = int(m.group(0), 16)
                if cp == 0:
                    raise _Lock("Null-byte path truncation in ANSI-C string")
                out.append(chr(cp))
                i += 2 + len(m.group(0))
                continue
        if esc == "u":
            m = re.match(r"[0-9a-fA-F]{1,4}", inner[i + 2 :])
            if m:
                cp = int(m.group(0), 16)
                if cp == 0:
                    raise _Lock("Null-byte path truncation in ANSI-C string")
                out.append(chr(cp))
                i += 2 + len(m.group(0))
                continue
        if esc == "U":
            m = re.match(r"[0-9a-fA-F]{1,8}", inner[i + 2 :])
            if m:
                cp = int(m.group(0), 16)
                if cp == 0:
                    raise _Lock("Null-byte path truncation in ANSI-C string")
                if cp <= 0x10FFFF:
                    out.append(chr(cp))
                    i += 2 + len(m.group(0))
                    continue
        if esc in "01234567":
            m = re.match(r"[0-7]{1,3}", inner[i + 1 :])
            if m:
                cp = int(m.group(0), 8) & 0xFF
                if cp == 0:
                    raise _Lock("Null-byte path truncation in ANSI-C string")
                out.append(chr(cp))
                i += 1 + len(m.group(0))
                continue
        if esc == "c" and i + 2 < n:
            cp = ord(inner[i + 2].upper()) ^ 64
            if cp == 0:
                raise _Lock("Null-byte path truncation in ANSI-C string")
            out.append(chr(cp))
            i += 3
            continue
        out.append("\\" + esc)
        i += 2
    return "".join(out)


def _normalize_ansi_c_quotes(text: str) -> str:
    """Decode unquoted POSIX ANSI-C $'...' strings into safe single-quoted words."""
    if "$'" not in text:
        return text
    out: List[str] = []
    i, n = 0, len(text)
    in_single = in_double = False
    while i < n:
        ch = text[i]
        if in_single:
            if ch == "'":
                in_single = False
            out.append(ch)
            i += 1
            continue
        if in_double:
            if ch == "\\" and i + 1 < n:
                out.append(text[i : i + 2])
                i += 2
                continue
            if ch == '"':
                in_double = False
            out.append(ch)
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            out.append(text[i : i + 2])
            i += 2
            continue
        if ch == "'":
            in_single = True
            out.append(ch)
            i += 1
            continue
        if ch == '"':
            in_double = True
            out.append(ch)
            i += 1
            continue
        if text.startswith("$'", i):
            j = i + 2
            while j < n:
                if text[j] == "\\" and j + 1 < n:
                    j += 2
                    continue
                if text[j] == "'":
                    break
                j += 1
            if j >= n:
                out.append(text[i:])
                break
            decoded = _decode_ansi_c_body(text[i + 2 : j])
            out.append("'" + decoded.replace("'", "'\"'\"'") + "'")
            i = j + 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _detect_windows(text: str, ctx: _Ctx) -> bool:
    if ctx.force_windows or bool(re.search(r"(?:^|[\s'\"=])[A-Za-z]:\\", text)):
        return True
    if re.search(r"(?:^|\s)-(?:encodedcommand|enc|ec)\b", text, re.IGNORECASE):
        return True
    raw_first = (text.strip().split() or [""])[0].strip("'\"")
    first = raw_first.replace("`", "").replace("^", "").replace("\\", "/").rsplit("/", 1)[-1].lower()
    for ext in (".exe", ".cmd", ".bat", ".com"):
        if first.endswith(ext) and len(first) > len(ext):
            first = first[: -len(ext)]
            break
    ps_like = re.match(r"^([a-z]+)-[a-z]+$", first)
    ps_var = bool(re.match(r"^\$(?:env:)?[a-z_][a-z0-9_]*=?$", first))
    ps_expr = text.lstrip().startswith(("(", "[", "$")) and bool(
        re.search(
            r"(?:\.(?:tostring|touniversaltime|tolocaltime|psversion)\b|::(?:now|utcnow|today|newguid|osversion|version|newline)\b|\$psversiontable\b|\bget-date\b)",
            text,
            re.IGNORECASE,
        )
    )
    if (
        first in CMD_BUILTINS
        or (ps_like and ps_like.group(1) in PS_VERBS)
        or first in POWERSHELLS
        or first == "cmd"
        or ps_var
        or ps_expr
        or first == "diskpart"
        or (first == "format" and bool(re.search(r"(?:^|\s)[A-Za-z]:(?:\s|$|\\|/)", text)))
    ):
        return True
    return False


def _analyze(text: str, ctx: _Ctx) -> None:
    # Fork bombs: name(){ name|name& };name
    if re.search(r"([\w:.]+)\s*\(\)\s*\{[^}]*\1\s*\|\s*\1\s*&", text):
        raise _Lock("Fork bomb detected")

    from .clans.custody import CustodyClan     # local import avoids a cycle
    sec = CustodyClan.inspect_secrets(text)
    if sec.level >= L.LOCK:
        if ctx.policy.secret_level == "ask":
            _add(ctx, L.ASK, "Command line contains a live credential (owner approval): " + "; ".join(sec.reasons))
        else:
            raise _Lock("Command line contains a live credential: " + "; ".join(sec.reasons))

    if ctx.depth == 0:
        text = text.replace("\ue000", "").replace("\ue001", "")
    windows = _detect_windows(text, ctx)
    if windows:
        ctx.force_windows = True
    # $IFS / ${IFS} word splitting evasion: rm${IFS}-rf${IFS}~
    text = re.sub(r"\$\{IFS\}|\$IFS\b", " ", text)
    text, heredocs, quoted = _extract_heredocs(text)
    for body, q in zip(heredocs, quoted):
        if not q and ("$(" in body or "`" in body):
            _extract_substitutions(body, ctx, windows=windows)
    text = _normalize_ansi_c_quotes(text)
    text = re.sub(r"\\;|(?<![\w'\"])';'(?![\w'\"])|(?<![\w'\"])\";\"(?![\w'\"])", f" {_SEMI} ", text)
    text = _extract_substitutions(text, ctx, windows=windows)
    windows = windows or _detect_windows(text, ctx)
    if windows:
        ctx.force_windows = True
    text = _expand_shell_braces(text, ctx, windows=windows)
    try:
        tokens = _strip_safe_ps_member_chains(_lex(text, windows))
    except ValueError:
        _add(ctx, L.ASK, "Command could not be parsed safely (unbalanced quotes)")
        return

    for seg in _split_segments(tokens):
        if seg.heredoc and seg.heredoc.startswith("HEREDOC_"):
            try:
                seg.heredoc = heredocs[int(seg.heredoc.split("_", 1)[1])]
            except (ValueError, IndexError):
                seg.heredoc = ""
        _analyze_segment(seg, ctx)


# ---------------------------------------------------------------------------
# Argument helpers
# ---------------------------------------------------------------------------

def _has_subst(word: str) -> bool:
    return bool(_SUBST_RE.search(word))


def _subst_safe(word: str, ctx: _Ctx) -> Optional[str]:
    """Replace safe substitutions with a neutral token; None if an unsafe one remains."""
    def repl(m: "re.Match[str]") -> str:
        return "x" if int(m.group(1)) in ctx.safe_substitutions else "\u0001"
    out = _SUBST_RE.sub(repl, word)
    return None if "\u0001" in out else out


def _is_option(word: str, windows_flags: bool = False) -> bool:
    if word.startswith("-") and word != "-" and not word.startswith("--=") :
        return True
    if windows_flags and re.match(r"^/[A-Za-z?][A-Za-z0-9:\-]*$", word) and len(word) <= 12:
        return True
    return False


def _expand_brace_sequence(inner: str, limit: int) -> Tuple[bool, Optional[List[str]]]:
    """Expand bash {start..end[..step]} integer or single-ASCII-letter sequences up to *limit*."""
    if not inner or any(c in inner for c in " \t\r\n'\"{},"):
        return False, None
    parts = inner.split("..")
    if len(parts) not in (2, 3):
        return False, None
    a, b = parts[0], parts[1]
    step_raw = parts[2] if len(parts) == 3 else None

    if re.fullmatch(r"[+-]?\d+", a) and re.fullmatch(r"[+-]?\d+", b) and (
        step_raw is None or re.fullmatch(r"[+-]?\d+", step_raw)
    ):
        start, end = int(a), int(b)
        raw_step = abs(int(step_raw)) if step_raw is not None else 1
        if raw_step == 0:
            raw_step = 1
        step = raw_step if start <= end else -raw_step
        count = abs(end - start) // abs(step) + 1
        if count > limit:
            return True, None

        def _pad_width(s: str) -> int:
            digits = s.lstrip("+-")
            return len(digits) if (len(digits) > 1 and digits.startswith("0")) else 0

        pad = max(_pad_width(a), _pad_width(b))
        vals: List[str] = []
        cur = start
        while (cur <= end) if step > 0 else (cur >= end):
            if pad:
                sign = "-" if cur < 0 else ""
                vals.append(f"{sign}{abs(cur):0{pad}d}")
            else:
                vals.append(str(cur))
            cur += step
        return True, vals

    if (
        len(a) == 1 and len(b) == 1 and a.isascii() and b.isascii() and a.isalpha() and b.isalpha()
        and (step_raw is None or re.fullmatch(r"[+-]?\d+", step_raw))
    ):
        o1, o2 = ord(a), ord(b)
        raw_step = abs(int(step_raw)) if step_raw is not None else 1
        if raw_step == 0:
            raw_step = 1
        step = raw_step if o1 <= o2 else -raw_step
        count = abs(o2 - o1) // abs(step) + 1
        if count > limit:
            return True, None
        vals = []
        cur = o1
        while (cur <= o2) if step > 0 else (cur >= o2):
            vals.append(chr(cur))
            cur += step
        return True, vals

    return False, None


def _find_unquoted_brace_span(
    word: str,
    windows: bool,
    *,
    respect_quotes: bool = True,
) -> Optional[Tuple[int, int, List[str], bool]]:
    """Find the first expandable unquoted {a,b} or {a..b} span in *word*."""
    n = len(word)
    i = 0
    in_s = in_d = False
    while i < n:
        ch = word[i]
        if respect_quotes:
            if in_s:
                if windows and ch == "'" and i + 1 < n and word[i + 1] == "'":
                    i += 2
                    continue
                if ch == "'":
                    in_s = False
                i += 1
                continue
            if in_d:
                if windows and ch == "`" and i + 1 < n:
                    i += 2
                    continue
                if (not windows) and ch == "\\" and i + 1 < n:
                    i += 2
                    continue
                if ch == '"':
                    in_d = False
                i += 1
                continue
            if windows and ch == "`" and i + 1 < n:
                i += 2
                continue
            if (not windows) and ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == "'":
                in_s = True
                i += 1
                continue
            if ch == '"':
                in_d = True
                i += 1
                continue
            if (ch == "$" or (windows and ch == "@")) and i + 1 < n and word[i + 1] == "{":
                depth = 1
                j = i + 2
                j_s = j_d = False
                while j < n and depth > 0:
                    cj = word[j]
                    if j_s:
                        if windows and cj == "'" and j + 1 < n and word[j + 1] == "'":
                            j += 2
                            continue
                        if cj == "'":
                            j_s = False
                    elif j_d:
                        if windows and cj == "`" and j + 1 < n:
                            j += 2
                            continue
                        if (not windows) and cj == "\\" and j + 1 < n:
                            j += 2
                            continue
                        if cj == '"':
                            j_d = False
                    else:
                        if windows and cj == "`" and j + 1 < n:
                            j += 2
                            continue
                        if (not windows) and cj == "\\" and j + 1 < n:
                            j += 2
                            continue
                        if cj == "'":
                            j_s = True
                        elif cj == '"':
                            j_d = True
                        elif cj == "{":
                            depth += 1
                        elif cj == "}":
                            depth -= 1
                    j += 1
                i = j
                continue

        if ch == "{":
            depth = 1
            j = i + 1
            j_s = j_d = False
            commas: List[int] = []
            while j < n and depth > 0:
                cj = word[j]
                if respect_quotes:
                    if j_s:
                        if windows and cj == "'" and j + 1 < n and word[j + 1] == "'":
                            j += 2
                            continue
                        if cj == "'":
                            j_s = False
                        j += 1
                        continue
                    if j_d:
                        if windows and cj == "`" and j + 1 < n:
                            j += 2
                            continue
                        if (not windows) and cj == "\\" and j + 1 < n:
                            j += 2
                            continue
                        if cj == '"':
                            j_d = False
                        j += 1
                        continue
                    if windows and cj == "`" and j + 1 < n:
                        j += 2
                        continue
                    if (not windows) and cj == "\\" and j + 1 < n:
                        j += 2
                        continue
                    if cj == "'":
                        j_s = True
                        j += 1
                        continue
                    if cj == '"':
                        j_d = True
                        j += 1
                        continue
                if cj == "{":
                    depth += 1
                elif cj == "}":
                    depth -= 1
                    if depth == 0:
                        break
                elif cj == "," and depth == 1:
                    commas.append(j)
                j += 1

            if depth == 0:
                if commas:
                    alts: List[str] = []
                    prev = i + 1
                    for cpos in commas:
                        alts.append(word[prev:cpos])
                        prev = cpos + 1
                    alts.append(word[prev:j])
                    return i, j, alts, False
                inner = word[i + 1 : j]
                if ".." in inner and _expand_brace_sequence(inner, 10**9)[0]:
                    return i, j, [inner], True
            i += 1
            continue
        i += 1
    return None


def _expand_brace_word(
    word: str,
    windows: bool,
    limit: int = 32,
    _depth: int = 0,
    *,
    respect_quotes: bool = True,
) -> Optional[List[str]]:
    if _depth > 16:
        return None
    span = _find_unquoted_brace_span(word, windows, respect_quotes=respect_quotes)
    if span is None:
        return [word]
    open_idx, close_idx, items, is_seq = span
    prefix = word[:open_idx]
    suffix = word[close_idx + 1 :]
    if is_seq:
        valid, seq = _expand_brace_sequence(items[0], limit)
        if not valid or seq is None:
            return None
        parts = seq
    else:
        parts = items
    results: List[str] = []
    for part in parts:
        rem = limit - len(results)
        if rem <= 0:
            return None
        expanded = _expand_brace_word(
            prefix + part + suffix,
            windows,
            limit=rem,
            _depth=_depth + 1,
            respect_quotes=respect_quotes,
        )
        if expanded is None:
            return None
        results.extend(expanded)
        if len(results) > limit:
            return None
    return results


def _expand_shell_braces(text: str, ctx: _Ctx, windows: bool = False) -> str:
    """Expand unquoted bash brace words ({--opt=val,}, --opt{a,b}=v) before lexing."""
    if "{" not in text or "}" not in text:
        return text
    out: List[str] = []
    i = 0
    n = len(text)
    after_redirect = False
    while i < n:
        ch = text[i]
        if ch in " \t\r":
            j = i + 1
            while j < n and text[j] in " \t\r":
                j += 1
            out.append(text[i:j])
            i = j
            continue
        if ch in ";&|()<>\n":
            j = i + 1
            while j < n and text[j] in ";&|()<>\n":
                j += 1
            op = text[i:j]
            out.append(op)
            after_redirect = "<" in op or ">" in op
            i = j
            continue
        j = i
        in_s = in_d = False
        brace_depth = 0
        while j < n:
            cj = text[j]
            if in_s:
                if windows and cj == "'" and j + 1 < n and text[j + 1] == "'":
                    j += 2
                    continue
                if cj == "'":
                    in_s = False
                j += 1
                continue
            if in_d:
                if windows and cj == "`" and j + 1 < n:
                    j += 2
                    continue
                if (not windows) and cj == "\\" and j + 1 < n:
                    j += 2
                    continue
                if cj == '"':
                    in_d = False
                j += 1
                continue
            if windows and cj == "`" and j + 1 < n:
                j += 2
                continue
            if (not windows) and cj == "\\" and j + 1 < n:
                j += 2
                continue
            if cj == "'":
                in_s = True
                j += 1
                continue
            if cj == '"':
                in_d = True
                j += 1
                continue
            if cj == "{":
                brace_depth += 1
                j += 1
                continue
            if cj == "}":
                if brace_depth > 0:
                    brace_depth -= 1
                j += 1
                continue
            if brace_depth == 0 and cj in " \t\r;&|()<>\n":
                break
            if brace_depth > 0 and cj in " \t\r\n":
                break
            j += 1
        word = text[i:j]
        i = j
        is_redir_target = after_redirect
        after_redirect = False
        if not is_redir_target and "{" in word and "}" in word and _find_unquoted_brace_span(word, windows) is not None:
            expanded = _expand_brace_word(word, windows=windows, limit=32)
            if expanded is None:
                if not re.fullmatch(r"\{[+-]?\d+\.\.[+-]?\d+(?:\.\.[+-]?\d+)?\}", word):
                    _add(ctx, L.ASK, f"Command uses complex shell brace expansion: {word}")
                    for frag in re.split(r"[{},=]+", word):
                        frag_clean = frag.strip("'\"")
                        if not frag_clean:
                            continue
                        if boundaries.GUARD_ENV_RE.match(frag_clean):
                            raise _Lock(f"Hard boundary {boundaries.POLICY_TAMPER}: sets {frag_clean}", boundaries.POLICY_TAMPER)
                        if _looks_like_path_token(frag_clean) or classify_sensitive(frag_clean, write_mode=True) or _touches_sensitive_control_dir(frag_clean):
                            _check_path(ctx, frag_clean, "write")
                out.append(word)
            else:
                non_empty = [cand for cand in expanded if cand]
                if non_empty:
                    out.append(" ".join(non_empty))
        else:
            out.append(word)
    return "".join(out)


def _expand_brace_candidates(word: str, limit: int = 32) -> Optional[List[str]]:
    """Expand bash-style brace expressions ({a,b}, {a..z}, {.git/config,}) into concrete path candidates.

    Returns None when the expansion exceeds *limit* candidates so the caller can fail closed to ASK.
    """
    return _expand_brace_word(word, windows=True, limit=limit, respect_quotes=False)


def _expand_fs_glob(abs_path: str, *, include_hidden: bool, limit: int = 64) -> List[str]:
    """Expand an existing workspace glob pattern up to *limit* paths without raising."""
    if looks_windows_path(abs_path) and os.name != "nt":
        return []
    if os.name == "nt" and abs_path.startswith("/") and not abs_path.startswith("//"):
        return []
    pat = re.sub(r"\[\^", "[!", abs_path)
    try:
        if sys.version_info >= (3, 11):
            it = glob.iglob(pat, include_hidden=include_hidden)
        else:
            it = glob.iglob(pat)
        return list(itertools.islice(it, limit))
    except OSError:
        return []


def _check_path(
    ctx: _Ctx,
    raw: str,
    mode: str = "read",
    recursive: bool = False,
    *,
    _from_glob: bool = False,
) -> Optional[str]:
    """Check one path argument; returns the resolved path (or None if it was refused)."""
    if raw is None:
        return None
    word = raw
    if _has_subst(word):
        safe = _subst_safe(word, ctx)
        if safe is None:
            _add(ctx, L.ASK, f"Path built from a command substitution: {raw}")
            return None
        word = safe
    if "{" in word and "}" in word and re.search(r"\{[^{}]*(?:,|\.\.)[^{}]*\}", word):
        candidates = _expand_brace_candidates(word)
        if candidates is None:
            _add(ctx, L.ASK, f"Path uses complex shell brace expansion: {raw}")
            return None
        last_resolved: Optional[str] = None
        for cand in candidates:
            if not cand:
                continue
            r = _check_path(ctx, cand, mode, recursive=recursive, _from_glob=_from_glob)
            if r is not None:
                last_resolved = r
        return last_resolved
    m_net = re.match(r"^/dev/(tcp|udp)/([^/]+)/(\d+)", word)
    if m_net:
        _check_url(ctx, f"http://{m_net.group(2)}:{m_net.group(3)}/", allowlist=False)
        _add(ctx, L.DENY, f"Raw network socket redirection via {word} (reverse-shell pattern)")
        return None
    if word.lower() in SPECIAL_DEVICES or re.match(r"^/dev/fd/\d+$", word):
        return word
    if re.match(r"^(?:hk(?:lm|cu|cr|u|cc)|registry)::?", word, re.IGNORECASE):
        _add(ctx, L.ASK, f"Windows registry access: {raw}")
        return None
    if re.match(r"^env:", word, re.IGNORECASE):
        _add(ctx, L.ASK, f"Environment variable dump via env: drive ({raw})")
        return None
    if "\x00" in word or "%00" in word:
        raise _Lock("Null-byte path truncation in command")

    if BLOCK_DEVICE_RE.match(word) and mode in ("write", "delete"):
        raise _Lock(f"Raw block device write: {raw}", boundaries.SYSTEM_DESTRUCTION)

    # Moving a file away removes it from where it was: a delete for the hard boundaries,
    # a read for everything else.
    moving = mode == "move"
    if moving:
        mode = "read"
    abs_path, confined, unresolved = resolve_path(word, base_dir=ctx.base_dir, cwd=ctx.cwd)
    if confined is False and ctx.policy.extra_roots and any(is_inside(abs_path, r) for r in ctx.policy.extra_roots):
        confined = True
    if not unresolved:
        _minotaur_path(ctx, abs_path, raw)
        hit = boundaries.check_path(abs_path, "delete" if moving else mode, ctx.policy)
        if hit:
            boundary, level, reason = hit
            if level == "LOCK":
                raise _Lock(reason, boundary)
            ctx.boundary = boundary
            _add(ctx, L.DENY if level == "DENY" else L.ASK, reason)
            if level == "DENY":
                return None
    sensitivity = classify_sensitive(word, abs_path, write_mode=(mode != "read"))
    if sensitivity == "critical":
        raise _Lock(f"Command accesses a credential or system store: {raw}", boundaries.MASTER_SECRET)
    if sensitivity == "startup" and mode != "read":
        _add(ctx, L.DENY, f"Command writes a startup/persistence file: {raw}")
        return None

    if not _from_glob and not unresolved and has_glob(abs_path):
        include_hidden = (
            ctx.force_windows
            or mode != "read"
            or any(p.startswith(".") for p in abs_path.replace("\\", "/").split("/") if p)
        )
        for match in _expand_fs_glob(abs_path, include_hidden=include_hidden, limit=64):
            _check_path(ctx, match, "move" if moving else mode, recursive=recursive, _from_glob=True)

    if mode == "delete" and not unresolved:
        ctx.destructive.append({"operation": "delete", "target": abs_path})
        globless = abs_path
        if "*" in os.path.basename(abs_path) or "?" in os.path.basename(abs_path):
            globless = os.path.dirname(abs_path) or "/"
        if is_catastrophic_target(globless, home_dir()):
            if recursive or globless != abs_path or abs_path.rstrip("/\\") in ("", "/"):
                raise _Lock(f"Catastrophic recursive deletion of root/system path: rm {raw}", boundaries.SYSTEM_DESTRUCTION)
            _add(ctx, L.DENY, f"Deleting a system/home location: {raw}")
            return None
        if any(c in abs_path for c in "*?[]"):
            _add(ctx, L.DENY, "Destructive targets must be exact; wildcard deletion is refused")
            return None

    if unresolved:
        _add(ctx, L.ASK, f"Path contains a variable Aegis cannot resolve: {raw}")
        return None
    if ctx.base_dir is not None and not confined:
        _add(ctx, L.DENY, f"Command path escapes the workspace: {raw}")
        return None
    if ctx.base_dir is not None and mode == "delete" and recursive:
        target = abs_path
        if "*" in os.path.basename(abs_path):
            target = os.path.dirname(abs_path)
        for root in ctx.policy.roots(ctx.base_dir):
            base = os.path.realpath(root) if os.name == "nt" or not looks_windows_path(root) else root.replace("\\", "/")
            if target.replace("\\", "/").rstrip("/").lower() == base.replace("\\", "/").rstrip("/").lower():
                _add(ctx, L.ASK, f"Recursive delete of a whole workspace root: {raw}")
                return None
    if sensitivity == "autoexec" and mode != "read":
        _add(ctx, L.ASK, f"Writes a file that runs code automatically later (hook/.envrc): {raw}")
    if sensitivity == "startup":
        _add(ctx, L.ASK, f"Reads a shell startup/history file: {raw}")
    elif sensitivity == "secret":
        if mode == "upload":
            _add(ctx, L.DENY, f"Uploads a secret-bearing file: {raw}")
        elif mode in ("read", "exec"):
            _add(ctx, L.ASK, f"Reads a secret-bearing file (owner approval): {raw}")
            ctx.effects.add("read_private")
    if mode == "upload":
        ctx.effects.add("egress")
    if mode == "delete":
        _blast_radius(ctx, abs_path, raw, recursive)
    return abs_path


def _blast_radius(ctx: _Ctx, abs_path: str, raw: str, recursive: bool) -> None:
    """Measure a delete before it runs; above the limit the owner decides (Destructive Action Constitution)."""
    from . import impact as _impact
    if looks_windows_path(abs_path) and os.name != "nt":
        return
    imp = _impact.measure_delete(abs_path, recursive, ctx.policy.blast_max_entries, ctx.policy.blast_max_bytes)
    if imp.entries == 0 and imp.complete:
        return
    ctx.impact.append(imp.to_dict())
    if imp.exceeded or not imp.complete:
        _add(ctx, L.ASK, f"Deletes {_impact.describe(imp)} in {raw} (more than {ctx.policy.blast_max_entries} items "
                         f"or {_impact.human_bytes(ctx.policy.blast_max_bytes)}: owner approval)")


def _minotaur_path(ctx: _Ctx, abs_path: str, raw: str) -> None:
    """A decoy file planted by Minotaur: touching it in any way is a LOCK."""
    trip = getattr(ctx.policy, "tripwires", None)
    if trip is not None and trip.match_path(abs_path):
        raise _Lock(f"Minotaur tripwire: a decoy file was touched ({raw})", "MINOTAUR_TRIPWIRE")


def _check_url(ctx: _Ctx, url: str, upload: bool = False, allowlist: bool = True) -> None:
    from .clans.custody import CustodyClan
    if _has_subst(url):
        _add(ctx, L.ASK, f"URL built from a command substitution: {url}")
        return
    if "://" not in url:
        url = "http://" + url
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    scheme = (parsed.scheme or "").lower()
    v = CustodyClan.inspect_url(url)
    if v.level >= L.LOCK:
        raise _Lock(v.reasons[0])
    if not v.passed:
        loopback_only = all("loopback" in r.lower() for r in v.reasons)
        if (
            loopback_only
            and host in {"localhost", "127.0.0.1", "::1"}
            and hasattr(ctx.policy, "loopback_port_allowed")
            and ctx.policy.loopback_port_allowed(parsed.port)
        ):
            return
        _add(ctx, L.ASK if loopback_only else v.level,
             ("Local service access (owner approval): " if loopback_only else "") + "; ".join(v.reasons))
        return
    # For Minotaur: anything fetched is untrusted content; anything sent, or any request to a
    # host outside the allowlist (the URL itself can carry data), is egress.
    ctx.effects.add("fetch")
    if upload or not ctx.policy.host_allowed(host):
        ctx.effects.add("egress")
    if not allowlist:
        return
    if upload and is_exfil_sink(host):
        _add(ctx, L.DENY, f"Upload to a known anonymous exfiltration sink: {host}")
        return
    if upload:
        _add(ctx, L.ASK, f"Uploads data to {host or url} (owner approval)")
        return
    if scheme not in ("http", "https", "git", "ssh", "git+https", "git+ssh") or not ctx.policy.host_allowed(host):
        what = "Upload to" if upload else "Network access to"
        _add(ctx, L.ASK, f"{what} a host outside the allowlist: {host or url}")
        if not upload:
            ctx.untrusted_download = True


def _secret_vars(ctx: _Ctx, words: List[str]) -> None:
    for w in words:
        m = SECRET_VAR_RE.search(w)
        if m and m.group(1).upper() not in {"SSH_AUTH_SOCK", "GPG_AGENT_INFO"}:
            _add(ctx, L.ASK, f"Reads a secret-like environment variable: {m.group(1)}")
            return


def _check_redirects(ctx: _Ctx, seg: Segment) -> None:
    for op, target in seg.redirects:
        mode = "read" if op.startswith("<") else "write"
        _check_path(ctx, target, mode)


def _canon_binary(word: str) -> str:
    name = word.replace("\\", "/").rsplit("/", 1)[-1].lower()
    for ext in (".exe", ".cmd", ".bat", ".com"):
        if name.endswith(ext):
            name = name[: -len(ext)]
    if re.match(r"^python\d+(\.\d+)?$", name):
        return "python3"
    if re.match(r"^mkfs(\.\w+)?$", name):
        return "mkfs"
    return name


# ---------------------------------------------------------------------------
# Segment analysis
# ---------------------------------------------------------------------------

def _analyze_segment(seg: Segment, ctx: _Ctx) -> None:
    words = list(seg.words)
    _check_redirects(ctx, seg)
    _secret_vars(ctx, words)
    if not words:
        return

    # Shell grammar keywords: analyze the command that follows them
    while words and words[0] in SHELL_KEYWORDS:
        kw = words.pop(0)
        if kw == "function" and words:
            words.pop(0)
            if words and words[0] in ("{", "()"):
                words.pop(0)
    if words and words[0] in SKIP_SEGMENT_KEYWORDS:
        return
    while words and words[-1] in ("}", "fi", "done", "esac"):
        words.pop()
    if not words:
        return

    # Leading VAR=value or PowerShell $var = value / $env:VAR = value assignments
    assignments: List[Tuple[str, str]] = []
    while words:
        m_ps_inline = re.match(r"^\$(?:env:)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$", words[0], re.I)
        m_ps_spaced = (
            re.match(r"^\$(?:env:)?([A-Za-z_][A-Za-z0-9_]*)$", words[0], re.I)
            if len(words) >= 2 and words[1] == "="
            else None
        )
        if m_ps_inline:
            name, value = m_ps_inline.group(1), m_ps_inline.group(2)
            words.pop(0)
            if boundaries.GUARD_ENV_RE.match(name):
                raise _Lock(f"Hard boundary {boundaries.POLICY_TAMPER}: sets {name}", boundaries.POLICY_TAMPER)
            if _is_dangerous_env_var(name):
                _add(ctx, L.ASK, f"Overrides a security-relevant environment variable: {name}")
            if value:
                words.insert(0, value)
            else:
                assignments.append((name, ""))
            # If the RHS is a single scalar literal (not a command), record the variable and finish segment
            if len(words) == 1 and not _has_subst(words[0]) and not any(c in words[0] for c in "/\\") \
                    and not _is_known_command_word(_canon_binary(words[0])):
                ctx.variables[name] = _expand_vars(words[0], ctx)
                return
            break
        if m_ps_spaced:
            name = m_ps_spaced.group(1)
            words.pop(0)
            words.pop(0)
            if boundaries.GUARD_ENV_RE.match(name):
                raise _Lock(f"Hard boundary {boundaries.POLICY_TAMPER}: sets {name}", boundaries.POLICY_TAMPER)
            if _is_dangerous_env_var(name):
                _add(ctx, L.ASK, f"Overrides a security-relevant environment variable: {name}")
            if not words:
                assignments.append((name, ""))
                break
            if len(words) == 1 and not _has_subst(words[0]) and not any(c in words[0] for c in "/\\") \
                    and not _is_known_command_word(_canon_binary(words[0])):
                ctx.variables[name] = _expand_vars(words[0], ctx)
                return
            break
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", words[0]):
            name, _, value = words.pop(0).partition("=")
            if boundaries.GUARD_ENV_RE.match(name):
                raise _Lock(f"Hard boundary {boundaries.POLICY_TAMPER}: sets {name}", boundaries.POLICY_TAMPER)
            if _is_dangerous_env_var(name):
                _add(ctx, L.ASK, f"Overrides a security-relevant environment variable: {name}")
            assignments.append((name, value))
            continue
        break
    if not words:
        for name, value in assignments:
            ctx.variables[name] = _expand_vars(value, ctx)
        return
    words = [_expand_vars(w, ctx) for w in words]

    if ctx.force_windows and words and "^" in words[0]:
        candidate = _canon_binary(_strip_cmd_carets(words[0]))
        if _is_known_command_word(candidate):
            words = [_strip_cmd_carets(w) for w in words]

    # Brace expansion in the command word: {rm,-rf,~} -> rm -rf ~
    m_brace = re.fullmatch(r"\{([^{}]*,[^{}]*)\}", words[0])
    if m_brace:
        words = m_brace.group(1).split(",") + words[1:]

    _dispatch(words, seg, ctx)


def _is_known_command_word(name: str) -> bool:
    return (
        name in NO_PATH_BINARIES
        or name in READ_BINARIES
        or name in PATTERN_FIRST
        or name in WRITE_BINARIES
        or name in DELETE_BINARIES
        or name in SHELLS
        or name in POWERSHELLS
        or name in INTERPRETERS
        or name in PROJECT_TOOLS
        or name in NETWORK_FETCHERS
        or name in REMOTE_TOOLS
        or name in SYSTEM_LOCK
        or name in PRIVILEGE
        or name in DENY_BINARIES
        or name in ASK_BINARIES
        or name in WRAPPERS
        or name in CMD_BUILTINS
        or name in {"git", "ollama", "cmd", "env", "xargs", "cd", "pushd", "chdir", "set-location", "sl", "popd", "source", ".", "eval", "awk", "gawk", "mawk", "nawk", "systemctl", "vssadmin"}
    )


def _expand_vars(word: str, ctx: _Ctx) -> str:
    """Expand variables assigned earlier in this command (X=rm; $X -rf ~)."""
    if not ctx.variables or "$" not in word:
        return word

    def repl(m: "re.Match[str]") -> str:
        name = m.group(1) or m.group(2)
        return ctx.variables.get(name, m.group(0))
    return re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)", repl, word)


def _dispatch(words: List[str], seg: Segment, ctx: _Ctx) -> None:
    raw_bin = words[0]
    args = words[1:]
    if _has_subst(raw_bin) or re.match(r"^\$", raw_bin):
        _add(ctx, L.ASK, f"Binary name comes from a variable or substitution: {raw_bin}")
        return
    name = _canon_binary(raw_bin)

    # Path-like argv[0]: ./script.sh, bin/tool, /usr/bin/python3, C:\tools\x.exe
    if "/" in raw_bin or "\\" in raw_bin or raw_bin.startswith("~"):
        low = raw_bin.replace("\\", "/").lower()
        if not low.startswith(SYSTEM_BIN_DIRS):
            resolved = _check_path(ctx, raw_bin, "exec")
            if resolved is not None:
                ctx.exec_after_download = True
                _project_exec(ctx, f"runs workspace program {raw_bin}")
            return
        # system binary by absolute path -> classify by its name

    if name in PRIVILEGE:
        _add(ctx, L.DENY, f"Privilege escalation via {name}")
        return
    hit = boundaries.check_command(name, args, ctx.policy)
    if hit:
        raise _Lock(hit[1], hit[0])
    if name in SYSTEM_LOCK:
        raise _Lock(f"Destructive system command blocked: {name}", boundaries.SYSTEM_DESTRUCTION)
    if name in ("init", "telinit") and args and args[0] in ("0", "6"):
        raise _Lock("System shutdown/reboot command blocked", boundaries.SYSTEM_DESTRUCTION)
    if name == "systemctl":
        verb = next((a.lower() for a in args if not a.startswith("-")), "")
        if verb in {"poweroff", "reboot", "halt", "kexec", "suspend", "hibernate"}:
            raise _Lock("System shutdown/reboot command blocked", boundaries.SYSTEM_DESTRUCTION)
        # Read-only queries are not changes (the boundaries layer already caught stop/disable
        # of the guard or a logging service before this point).
        if verb in {"status", "is-active", "is-enabled", "is-failed", "show", "cat", "list-units",
                    "list-unit-files", "list-timers", "list-sockets", "list-dependencies", "get-default",
                    "show-environment", "", "help", "--version"}:
            return
        _add(ctx, L.ASK, "systemctl changes services (owner approval)")
        return
    if name == "vssadmin" and any(a.lower() == "delete" for a in args):
        raise _Lock("Shadow copy deletion (ransomware pattern) blocked", boundaries.BACKUP_DESTRUCTION)
    if name in DENY_BINARIES:
        _add(ctx, L.DENY, f"Account/kernel administration command blocked: {name}")
        return

    if name in WRAPPERS:
        return _wrapper(name, args, seg, ctx)
    if name == "env":
        idx = 0
        n_args = len(args)
        while idx < n_args:
            a = args[idx]
            if a == "--":
                idx += 1
                break
            if a.startswith("--") and len(a) > 2:
                opt, eq, val = a.partition("=")
                if "--split-string".startswith(opt) and len(opt) >= 3:
                    rest_tail = " ".join(args[idx + 1:])
                    nested = (val + " " + rest_tail).strip() if eq else rest_tail
                    _analyze_nested(nested, ctx)
                    return
                if "--chdir".startswith(opt) and len(opt) >= 3:
                    target = val if eq else (args[idx + 1] if idx + 1 < n_args else "")
                    idx += 1 if eq else 2
                    if target:
                        if any(c in target for c in "*?[]{}"):
                            _add(ctx, L.ASK, f"env --chdir target contains glob/brace wildcard: {target}")
                        resolved_cd = _check_path(ctx, target, "cd")
                        _check_cd_control_dir(ctx, target, resolved_cd, "env --chdir")
                        if resolved_cd is not None:
                            ctx.cwd = resolved_cd
                    continue
                if "--unset".startswith(opt) and len(opt) >= 3:
                    idx += 1 if eq else 2
                    continue
                if any(o.startswith(opt) and len(opt) >= 3 for o in (
                    "--ignore-environment", "--null", "--debug",
                )):
                    idx += 1
                    continue
                _add(ctx, L.ASK, f"env uses unrecognized option '{a}' (owner approval)")
                idx += 1
                continue
            if a.startswith("-") and len(a) > 1 and not a.startswith("--"):
                chars = a[1:]
                k = 0
                idx += 1
                while k < len(chars):
                    ch = chars[k]
                    if ch in ("i", "0", "v"):
                        k += 1
                        continue
                    if ch == "S":
                        val = chars[k + 1:] if k + 1 < len(chars) else (args[idx] if idx < n_args else "")
                        tail = args[idx:] if k + 1 < len(chars) else args[idx + 1:]
                        nested = (val + " " + " ".join(tail)).strip()
                        _analyze_nested(nested, ctx)
                        return
                    if ch == "C":
                        target = chars[k + 1:] if k + 1 < len(chars) else (args[idx] if idx < n_args else "")
                        if k + 1 >= len(chars) and idx < n_args:
                            idx += 1
                        if target:
                            if any(c in target for c in "*?[]{}"):
                                _add(ctx, L.ASK, f"env -C target contains glob/brace wildcard: {target}")
                            resolved_cd = _check_path(ctx, target, "cd")
                            _check_cd_control_dir(ctx, target, resolved_cd, "env -C")
                            if resolved_cd is not None:
                                ctx.cwd = resolved_cd
                        break
                    if ch == "u":
                        if k + 1 >= len(chars) and idx < n_args:
                            idx += 1
                        break
                    _add(ctx, L.ASK, f"env uses unrecognized flag '-{ch}' in '{a}' (owner approval)")
                    break
                continue
            break
        rest = list(args[idx:])
        while rest and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", rest[0]):
            var, _, val = rest[0].partition("=")
            if boundaries.GUARD_ENV_RE.match(var):
                raise _Lock(f"Hard boundary {boundaries.POLICY_TAMPER}: sets {var}", boundaries.POLICY_TAMPER)
            if _is_dangerous_env_var(var):
                _add(ctx, L.ASK, f"Overrides a security-relevant environment variable: {var}")
            if var.upper() == "TAPE" and val:
                _check_path(ctx, val, "write")
            rest.pop(0)
        if not rest:
            _add(ctx, L.ASK, "Unrestricted environment variable dump (env)")
            return
        return _dispatch(rest, Segment(words=rest, piped_in=seg.piped_in), ctx)
    if name in ("printenv", "export", "declare", "typeset", "set"):
        return _env_builtin(name, args, ctx)
    if name == "xargs":
        return _xargs(args, seg, ctx)
    if name in ("cd", "pushd", "chdir", "set-location", "sl"):
        return _cd(args, ctx)
    if name == "popd":
        _add(ctx, L.ASK, "popd changes to an unknown directory")
        return
    if name in ("source", "."):
        if args and args[0].startswith("{"):
            # PowerShell dot-sourcing a script block runs its body: `. { ... }`
            body = " ".join(args).strip()
            body = body[1:]
            if body.endswith("}"):
                body = body[:-1]
            if body.strip():
                _analyze_nested(body, ctx)
            return
        if args:
            if _check_path(ctx, args[0], "exec") is not None:
                _project_exec(ctx, f"sources shell file {args[0]}")
        return
    if name == "eval":
        joined = " ".join(args)
        if _SUBST_RE.search(joined):
            _add(ctx, L.DENY, "eval of a command substitution executes generated code")
            return
        _analyze_nested(joined, ctx)
        return

    if name == "busybox":
        # `busybox APPLET ARGS...` is exactly `APPLET ARGS...`
        if args and not args[0].startswith("-"):
            return _dispatch(args, Segment(words=args, redirects=seg.redirects, piped_in=seg.piped_in,
                                           heredoc=seg.heredoc, herestring=seg.herestring), ctx)
        return
    if name in SHELLS:
        return _shell(name, args, seg, ctx)
    if name in POWERSHELLS:
        return _powershell(args, seg, ctx)
    if name == "cmd":
        return _cmd(args, seg, ctx)
    if name in INTERPRETERS or name == "awk" or name in ("gawk", "mawk", "nawk"):
        if name in ("awk", "gawk", "mawk", "nawk"):
            return _awk(args, ctx)
        return _interpreter(name, args, seg, ctx)

    if name in NO_PATH_BINARIES:
        return
    if name in READ_BINARIES:
        if name in ("dir", "ls", "gci", "get-childitem") and any(re.match(r"^env:", a, re.I) for a in args):
            _add(ctx, L.ASK, "Environment variable dump via env: drive")
            return
        if name in ("less", "more") and any(a.startswith("+") and ("!" in a or "|" in a) for a in args):
            _add(ctx, L.ASK, f"{name} +command runs a shell command (owner approval)")
            return
        return _read_tool(name, args, ctx)
    if name in PATTERN_FIRST:
        return _pattern_tool(name, args, ctx)
    if name == "sed":
        return _sed(args, ctx)
    if name == "find":
        return _find(args, ctx)
    if name in DELETE_BINARIES:
        return _delete(name, args, ctx)
    if name == "robocopy":
        return _robocopy(args, ctx)
    if name == "dd":
        return _dd(args, ctx)
    if name == "chmod":
        return _chmod(args, ctx)
    if name == "tar":
        return _tar(args, ctx)
    if name in ("unzip", "7z", "7za"):
        return _archive_extract(name, args, ctx)
    if name == "rsync":
        return _rsync(args, ctx)
    if name in ("zip",) and any(a in ("-TT", "--unzip-command") or a.startswith("--unzip-command=") for a in args):
        _add(ctx, L.ASK, "zip -TT runs an arbitrary test command (owner approval)")
        return
    if name in ("cp", "mv", "ln", "install", "copy", "move", "copy-item", "cpi", "move-item", "mi", "xcopy"):
        return _copy_like(name, args, ctx)
    if name in ("chown", "chgrp"):
        return _chown(args, ctx)
    if name in ("new-item", "ni", "mklink"):
        return _link_or_new_item(name, args, ctx)
    if name in WRITE_BINARIES:
        return _paths(ctx, args, "write", windows=name in CMD_BUILTINS)
    if name == "git":
        return _git(args, ctx)
    if name in NETWORK_FETCHERS:
        return _fetch(name, args, ctx)
    if name in REMOTE_TOOLS:
        ctx.effects.update(("fetch", "egress"))
        _add(ctx, L.ASK, f"Remote access / transfer tool requires owner approval: {name}")
        for a in args:
            if not _is_option(a) and ":" not in a and "@" not in a:
                if any(c in a for c in "/\\~") or a.startswith("."):
                    _check_path(ctx, a, "upload")
        return
    if name in ("iex", "invoke-expression") and seg.piped_in:
        _add(ctx, L.DENY, "Untrusted pipeline executed directly by Invoke-Expression")
        return
    if name == "ollama":
        return _ollama(args, ctx)
    if name in ASK_BINARIES:
        if name == "docker" and args and args[0] in {"ps", "images", "version", "info", "logs"}:
            return
        if name == "gh" and _gh_safe(args, ctx):
            return
        if name == "kubectl" and args and args[0] in {"get", "describe", "logs", "version"}:
            return
        _add(ctx, L.ASK, f"Command requires owner approval: {name}")
        return
    if name in PROJECT_TOOLS or name in ctx.policy.extra_allowed_binaries:
        return _project_tool(name, args, ctx)

    level = L.DENY if ctx.policy.unknown_binary == "deny" else L.ASK
    _add(ctx, level, f"Unknown command '{name}' is not on the Aegis allowlist")


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

def _project_exec(ctx: _Ctx, what: str) -> None:
    if ctx.policy.project_exec == "ask":
        _add(ctx, L.ASK, f"Executes project code ({what}); owner approval required by policy")


def _looks_like_path_token(val: str) -> bool:
    return bool(val) and (
        any(c in val for c in "/\\~$")
        or val.startswith(".")
        or looks_windows_path(val)
    )


_PS_PATH_PARAMS = ("-path", "-literalpath", "-filepath", "-destination", "-target", "-outfile", "-output")
_PS_NON_PATH_PARAMS = frozenset({
    "-value", "-encoding", "-inputobject", "-itemtype", "-type", "-delimiter",
    "-force", "-confirm", "-whatif", "-raw", "-width", "-tail", "-totalcount",
})


def _paths(ctx: _Ctx, args: List[str], mode: str, windows: bool = False) -> None:
    end_of_opts = False
    for a in args:
        if a == "--":
            end_of_opts = True
            continue
        if not end_of_opts and _is_option(a, windows):
            if "=" in a and a.startswith("--"):
                val = a.split("=", 1)[1]
                if _looks_like_path_token(val):
                    _check_path(ctx, val, mode)
            elif ":" in a and a.startswith("-") and not a.startswith("--"):
                opt_name, _, val = a.partition(":")
                low_opt = opt_name.lower()
                if val and len(low_opt) >= 2 and low_opt not in _PS_NON_PATH_PARAMS and any(p.startswith(low_opt) for p in _PS_PATH_PARAMS):
                    _check_path(ctx, val, mode)
            continue
        if "://" in a:
            _check_url(ctx, a, allowlist=False)
            continue
        _check_path(ctx, a, mode)


def _expand_long_opt(opt: str, classes) -> str:
    """Return the known long option that `opt` abbreviates, checking classes in order.

    GNU tools accept any prefix of a long option; we resolve fail-closed: the first class
    (most dangerous) containing an option that starts with `opt` wins, even if ambiguous.
    """
    if len(opt) < 3 or not opt.startswith("--"):
        return opt
    for cls in classes:
        if opt in cls:
            return opt
    for cls in classes:
        for known in sorted(cls):
            if known.startswith("--") and known.startswith(opt):
                return known
    return opt


def _read_tool(name: str, args: List[str], ctx: _Ctx) -> None:
    spec = _READ_TOOL_SPEC.get(name)
    windows = name in CMD_BUILTINS
    if spec is None:
        return _paths(ctx, args, "read", windows=windows)
    write_opts = spec.get("write_opts") or set()
    read_opts = spec.get("read_opts") or set()
    ask_opts = spec.get("ask_opts") or set()
    value_opts = spec.get("value_opts") or set()
    write_from_pos = spec.get("write_from_pos")
    win_read_prefixes = spec.get("win_read_prefixes") or ()

    end_of_opts = False
    pos_idx = 0
    i = 0
    n = len(args)
    while i < n:
        a = args[i]
        i += 1
        if a == "--" and not end_of_opts:
            end_of_opts = True
            continue
        if not end_of_opts:
            if win_read_prefixes:
                low = a.lower()
                matched_pref = next((p for p in win_read_prefixes if low.startswith(p)), None)
                if matched_pref is not None:
                    val = a[len(matched_pref):]
                    if val:
                        _check_path(ctx, val, "read")
                    continue
            if a.startswith("--") and len(a) > 2:
                opt, eq, val = a.partition("=")
                # GNU getopt accepts any unambiguous prefix (--out == --output), so map an
                # abbreviation onto the option it can expand to. Most dangerous class wins.
                opt = _expand_long_opt(opt, (ask_opts, write_opts, read_opts, value_opts))
                if opt in ask_opts:
                    _add(ctx, L.ASK, f"{name} {opt} executes an arbitrary program (owner approval)")
                    if not eq and i < n:
                        i += 1
                    continue
                if opt in write_opts:
                    target = val if eq else (args[i] if i < n else "")
                    if not eq and i < n:
                        i += 1
                    if target:
                        _check_path(ctx, target, "write")
                    continue
                if opt in read_opts:
                    target = val if eq else (args[i] if i < n else "")
                    if not eq and i < n:
                        i += 1
                    if target:
                        _check_path(ctx, target, "read")
                    continue
                if opt in value_opts:
                    if not eq and i < n:
                        i += 1
                    continue
                # Unknown long option on a tool with a known output table: a path-like value
                # could be an output we do not model, so fail closed and check it as a write.
                if eq and _looks_like_path_token(val):
                    _check_path(ctx, val, "write")
                continue
            if a.startswith("-") and len(a) > 1 and not a.startswith("--"):
                if a in value_opts and len(a) > 2:
                    if i < n:
                        i += 1
                    continue
                chars = a[1:]
                k = 0
                while k < len(chars):
                    flag = "-" + chars[k]
                    if flag in ask_opts:
                        _add(ctx, L.ASK, f"{name} {flag} executes an arbitrary program (owner approval)")
                        if k + 1 >= len(chars) and i < n:
                            i += 1
                        break
                    if flag in write_opts:
                        target = chars[k + 1:] if k + 1 < len(chars) else (args[i] if i < n else "")
                        if k + 1 >= len(chars) and i < n:
                            i += 1
                        if target:
                            _check_path(ctx, target, "write")
                        break
                    if flag in read_opts:
                        target = chars[k + 1:] if k + 1 < len(chars) else (args[i] if i < n else "")
                        if k + 1 >= len(chars) and i < n:
                            i += 1
                        if target:
                            _check_path(ctx, target, "read")
                        break
                    if flag in value_opts:
                        if k + 1 >= len(chars) and i < n:
                            i += 1
                        break
                    k += 1
                continue
            if windows and _is_option(a, True):
                continue
        if "://" in a:
            _check_url(ctx, a, allowlist=False)
        else:
            mode = "write" if (write_from_pos is not None and pos_idx >= write_from_pos) else "read"
            _check_path(ctx, a, mode)
        pos_idx += 1


def _wrapper(name: str, args: List[str], seg: Segment, ctx: _Ctx) -> None:
    rest = list(args)
    if name in ("timeout",):
        while rest and rest[0].startswith("-"):
            opt = rest.pop(0)
            if opt in ("-s", "--signal", "-k", "--kill-after") and rest:
                rest.pop(0)
        if rest:
            rest.pop(0)                         # duration
    elif name in ("nice", "ionice", "stdbuf", "watch", "time"):
        while rest and rest[0].startswith("-"):
            opt = rest.pop(0)
            if opt in ("-n", "-c", "-i", "-o", "-e", "-d", "--interval") and rest and not rest[0].startswith("-"):
                rest.pop(0)
        if name == "watch" and rest:
            # watch joins its arguments and runs them through `sh -c` (unless -x): analyze that text.
            _analyze_nested(" ".join(rest), ctx)
            return
    elif name in ("command", "builtin", "exec"):
        while rest and rest[0].startswith("-"):
            rest.pop(0)
    if not rest:
        return
    _dispatch(rest, Segment(words=rest, piped_in=seg.piped_in), ctx)


def _env_builtin(name: str, args: List[str], ctx: _Ctx) -> None:
    plain = [a for a in args if not a.startswith("-")]
    if name == "printenv":
        if not plain or any(SECRET_VAR_RE.search("$" + p) for p in plain):
            _add(ctx, L.ASK, "Environment variable dump (printenv)")
        return
    if name == "set":
        if not args:
            _add(ctx, L.ASK, "Environment variable dump (set)")
            return
        # cmd.exe: `set NAME=value`, `set "NAME=value"`, `set /p NAME=...`, `set /a NAME=...`
        for a in args:
            tok = a.strip().strip('"').strip()
            if not tok or tok.startswith(("-", "/")) or "=" not in tok:
                continue
            var = tok.split("=", 1)[0].strip()
            if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", var):
                continue
            if boundaries.GUARD_ENV_RE.match(var):
                raise _Lock(f"Hard boundary {boundaries.POLICY_TAMPER}: sets {var}", boundaries.POLICY_TAMPER)
            if _is_dangerous_env_var(var):
                _add(ctx, L.ASK, f"Overrides a security-relevant environment variable: {var}")
        return
    # export / declare / typeset
    if not plain or any(a in ("-p", "-x") for a in args) and not plain:
        _add(ctx, L.ASK, f"Environment variable dump ({name})")
        return
    for a in plain:
        var, eq, value = a.partition("=")
        if eq and _is_dangerous_env_var(var):
            _add(ctx, L.ASK, f"Overrides a security-relevant environment variable: {var}")
        if eq:
            ctx.variables[var] = _expand_vars(value, ctx)


def _xargs(args: List[str], seg: Segment, ctx: _Ctx) -> None:
    rest = list(args)
    takes_value = {"-I", "-i", "-n", "-L", "-P", "-s", "-d", "-E", "-a", "--max-args", "--max-procs",
                   "--delimiter", "--arg-file", "--replace"}
    while rest and rest[0].startswith("-"):
        opt = rest.pop(0)
        if opt.startswith("--arg-file="):
            _check_path(ctx, opt.split("=", 1)[1], "read")
            continue
        if opt.startswith("-a") and len(opt) > 2 and not opt.startswith("--"):
            _check_path(ctx, opt[2:], "read")
            continue
        if opt in takes_value and rest:
            val = rest.pop(0)
            if opt in ("-a", "--arg-file"):
                _check_path(ctx, val, "read")
    if not rest:
        return
    inner = _canon_binary(rest[0])
    if inner in DELETE_BINARIES | {"mv", "cp", "chmod", "chown", "dd", "truncate", "tee", "ln"} or inner in SHELLS | INTERPRETERS:
        _add(ctx, L.ASK, f"xargs feeds unknown targets to '{inner}' (owner approval)")
        return
    _dispatch(rest, Segment(words=rest, piped_in=seg.piped_in), ctx)


def _check_cd_control_dir(ctx: _Ctx, target: str, resolved: Optional[str], label: str) -> None:
    if _touches_sensitive_control_dir(target) or (
        resolved is not None
        and _touches_sensitive_control_dir(resolved)
        and not _touches_sensitive_control_dir(ctx.base_dir or "")
    ):
        _add(ctx, L.ASK, f"{label} enters sensitive control directory '{target}' (owner approval)")


def _cd(args: List[str], ctx: _Ctx) -> None:
    targets = [a for a in args if not _is_option(a)]
    target = targets[0] if targets else "~"
    if target == "-":
        _add(ctx, L.ASK, "cd - changes to an unknown previous directory")
        return
    if any(c in target for c in "*?[]{}"):
        _add(ctx, L.ASK, f"cd target contains glob/brace wildcard: {target}")
        return
    resolved = _check_path(ctx, target, "cd")
    _check_cd_control_dir(ctx, target, resolved, "cd")
    if resolved is not None:
        ctx.cwd = resolved


def _shell(name: str, args: List[str], seg: Segment, ctx: _Ctx) -> None:
    rest = list(args)
    script_text = None
    script_file = None
    while rest:
        a = rest.pop(0)
        if a == "-c" or (a.startswith("-") and not a.startswith("--") and "c" in a[1:]):
            if rest:
                script_text = rest.pop(0)
            break
        if a.startswith("-") or a.startswith("+"):
            if a in ("-o", "+o", "-O", "+O") and rest:
                rest.pop(0)
            continue
        script_file = a
        break
    if script_text is not None:
        prev_win = ctx.force_windows
        ctx.force_windows = False
        try:
            _analyze_nested(script_text, ctx)
        finally:
            ctx.force_windows = prev_win
        return
    if script_file is not None and script_file not in STDIN_PATHS:
        if _check_path(ctx, script_file, "exec") is not None:
            ctx.exec_after_download = True
            _project_exec(ctx, f"{name} {script_file}")
        return
    if seg.piped_in:
        _add(ctx, L.DENY, f"Untrusted pipeline executed directly by the {name} shell")
        return
    if seg.heredoc is not None or seg.herestring is not None:
        prev_win = ctx.force_windows
        ctx.force_windows = False
        try:
            _analyze_nested(seg.heredoc if seg.heredoc is not None else seg.herestring, ctx)
        finally:
            ctx.force_windows = prev_win
        return
    _add(ctx, L.ASK, f"Spawning bare interactive shell session requires owner approval: {name}")


def _cmd(args: List[str], seg: Segment, ctx: _Ctx) -> None:
    for i, a in enumerate(args):
        low = _strip_cmd_carets(a).lower()
        if low in ("/c", "/k", "/r"):
            inner = _strip_cmd_carets(" ".join(args[i + 1:]))
            if low == "/k":
                _add(ctx, L.ASK, "cmd /k keeps an interactive shell open")
            if inner:
                prev_win = ctx.force_windows
                ctx.force_windows = True
                try:
                    _analyze_nested(inner, ctx)
                finally:
                    ctx.force_windows = prev_win
            return
    if seg.piped_in:
        _add(ctx, L.DENY, "Untrusted pipeline executed directly by cmd.exe")
        return
    _add(ctx, L.ASK, "Spawning bare cmd.exe shell requires owner approval")


def _powershell(args: List[str], seg: Segment, ctx: _Ctx) -> None:
    rest = list(args)
    takes_value = {"-executionpolicy", "-ep", "-ex", "-windowstyle", "-w", "-inputformat",
                   "-outputformat", "-of", "-if", "-configurationname", "-workingdirectory", "-wd",
                   "-version", "-psconsolefile", "-settingsfile"}
    while rest:
        a = rest.pop(0)
        low = a.lower()
        if low in ("-command", "-c", "-com", "-comm", "-comma", "-comman"):
            inner = " ".join(rest)
            if inner.strip() == "-" and seg.piped_in:
                _add(ctx, L.DENY, "Untrusted pipeline executed directly by PowerShell")
            elif inner:
                _analyze_nested(inner, ctx)
            return
        if low in ("-encodedcommand", "-enc", "-e", "-ec") or (
            len(low) >= 3 and low.startswith("-en") and "-encodedcommand".startswith(low)
        ):
            _add(ctx, L.ASK, "PowerShell -EncodedCommand hides the command from inspection")
            if not rest or not rest[0].strip():
                _add(ctx, L.DENY, "PowerShell -EncodedCommand missing payload")
                return
            b64_arg = rest.pop(0).strip()
            try:
                raw_bytes = base64.b64decode(b64_arg, validate=True)
            except Exception:
                raw_bytes = b""
            if not raw_bytes or (len(raw_bytes) % 2) != 0:
                _add(ctx, L.DENY, "Malformed or opaque PowerShell -EncodedCommand payload")
                return
            try:
                decoded = raw_bytes.decode("utf-16-le", errors="strict")
            except UnicodeDecodeError:
                _add(ctx, L.DENY, "Malformed or opaque PowerShell -EncodedCommand payload")
                return
            if not decoded.strip() or "\x00" in decoded:
                _add(ctx, L.DENY, "Malformed or opaque PowerShell -EncodedCommand payload")
                return
            prev_win = ctx.force_windows
            ctx.force_windows = True
            try:
                _analyze_nested(decoded, ctx)
            finally:
                ctx.force_windows = prev_win
            return
        if low in ("-file", "-f"):
            if rest and _check_path(ctx, rest[0], "exec") is not None:
                ctx.exec_after_download = True
                _project_exec(ctx, f"powershell -File {rest[0]}")
            return
        if low in takes_value:
            if rest:
                val = rest.pop(0)
                if low in ("-executionpolicy", "-ep", "-ex") and val.lower() in ("bypass", "unrestricted"):
                    _add(ctx, L.ASK, "PowerShell execution policy bypass")
            continue
        if low.startswith("-"):
            continue
        # First positional argument: the rest is the command (powershell Remove-Item ...)
        inner = " ".join([a] + rest)
        if a.lower().endswith(".ps1"):
            if _check_path(ctx, a, "exec") is not None:
                ctx.exec_after_download = True
                _project_exec(ctx, f"powershell {a}")
            return
        _analyze_nested(inner, ctx)
        return
    if seg.piped_in:
        _add(ctx, L.DENY, "Untrusted pipeline executed directly by PowerShell")
        return
    _add(ctx, L.ASK, "Spawning bare PowerShell session requires owner approval")


def _ollama(args: List[str], ctx: _Ctx) -> None:
    rest = [a for a in args if not a.startswith("-")]
    if not args or args[0].lower() in ("-v", "--version", "-h", "--help", "help"):
        return
    if not rest:
        return
    sub = rest[0].lower()
    if sub in ("list", "ls", "ps", "show", "run", "stop", "pull", "cp", "rm"):
        return
    if sub == "create":
        it = list(args)
        while it:
            tok = it.pop(0)
            if tok in ("-f", "--file") and it:
                _check_path(ctx, it.pop(0), "read")
            elif tok.startswith("--file="):
                _check_path(ctx, tok.split("=", 1)[1], "read")
        return
    _add(ctx, L.ASK, f"ollama {sub} requires owner approval")


def _gh_safe(args: List[str], ctx: _Ctx) -> bool:
    pos = [a for a in args if not a.startswith("-")]
    if not pos:
        return False
    if pos[0] in ("status", "version"):
        return True
    if len(pos) < 2:
        return False
    pair = (pos[0], pos[1])
    if pair in {
        ("pr", "list"), ("pr", "view"), ("pr", "status"), ("pr", "checks"), ("pr", "diff"),
        ("pr", "create"), ("pr", "edit"), ("pr", "comment"), ("pr", "close"), ("pr", "reopen"),
        ("pr", "ready"), ("pr", "merge"),
        ("issue", "list"), ("issue", "view"), ("issue", "status"), ("issue", "create"),
        ("issue", "edit"), ("issue", "comment"), ("issue", "close"), ("issue", "reopen"),
        ("repo", "view"), ("repo", "list"),
        ("run", "list"), ("run", "view"), ("run", "watch"), ("run", "rerun"),
        ("workflow", "list"), ("workflow", "view"), ("workflow", "run"),
        ("release", "list"), ("release", "view"),
        ("auth", "status"),
    }:
        return True
    if pair == ("repo", "clone"):
        # gh repo clone <repo> [<directory>] [-- <gitflags>...]
        if len(pos) >= 3:
            _check_path(ctx, pos[2], "write")
        return True
    return False


_INLINE_FS_ROOT_RE = re.compile(
    r"^/(?:etc|root|home|Users|var|usr|opt|tmp|proc|sys|boot|mnt|media|srv|run|private|Library|System|Volumes)(?:/|$)"
)


def _looks_inline_fs_path(lit: str) -> bool:
    if not lit or "://" in lit or "\n" in lit or len(lit) > 1024:
        return False
    if lit in ("~", "..", ".env") or lit.startswith(("~/", "~\\", "../", "..\\")):
        return True
    if looks_windows_path(lit):
        return True
    if _INLINE_FS_ROOT_RE.match(lit):
        return True
    if classify_sensitive(lit, lit) in ("critical", "secret", "startup"):
        return True
    return False


def _inline_code(ctx: _Ctx, interpreter: str, code: str) -> None:
    """Inline code (-c/-e/heredoc): find embedded shell commands, else ask the owner (unless policy allows)."""
    for lit in re.findall(r"'([^'\n]{2,})'|\"([^\"\n]{2,})\"", code):
        s = lit[0] or lit[1]
        if len(s) >= 3:
            first = _canon_binary((s.strip().split() or [""])[0])
            if first in DELETE_BINARIES | SYSTEM_LOCK | NETWORK_FETCHERS | SHELLS | POWERSHELLS | {"find", "dd", "chmod", "mv", "cp", "git", "tar", "rsync"}:
                _analyze_nested(s, ctx)
                continue
        s_clean = s.strip()
        if re.match(r"^https?://\S+$", s_clean, re.I):
            _check_url(ctx, s_clean)
        elif _looks_inline_fs_path(s_clean):
            _check_path(ctx, s_clean, "read")
    if REVERSE_SHELL_RE.search(code) and re.search(r"subprocess|pty\.spawn|os\.dup2|/bin/(?:ba)?sh|child_process|exec\(", code):
        _add(ctx, L.DENY, f"Reverse-shell pattern in inline {interpreter} code (socket + process)")
        return
    if DESTRUCTIVE_CODE_RE.search(code):
        _add(ctx, L.DENY, f"Destructive operation in inline {interpreter} code")
        return
    if getattr(ctx.policy, "inline_exec", "ask") == "allow" and ctx.base_dir is not None:
        _project_exec(ctx, f"inline {interpreter}")
        return
    _add(ctx, L.ASK, f"Inline interpreter code execution ({interpreter}) requires human owner approval")


def _interpreter(name: str, args: List[str], seg: Segment, ctx: _Ctx) -> None:
    rest = list(args)
    py = name.startswith("py")
    inline_flags = INLINE_FLAGS_BY.get(name, {"-e"})
    value_opts = VALUE_OPTS_BY.get("python3" if py else ("node" if name in ("nodejs", "ts-node", "tsx") else name), set())
    if name in ("deno", "bun") and rest:
        sub = rest[0]
        if sub in ("eval", "-e"):
            return _inline_code(ctx, name, " ".join(rest[1:]))
        if sub in ("repl",):
            _add(ctx, L.ASK, f"Interactive {name} REPL requires owner approval")
            return
        if sub in ("x", "install", "add", "upgrade", "compile", "jupyter", "publish"):
            if sub in ("x", "publish"):
                _add(ctx, L.ASK, f"{name} {sub} downloads/publishes code (owner approval)")
            else:
                _project_exec(ctx, f"{name} {sub}")
            return
        if sub in ("run", "test", "bench", "check", "fmt", "lint", "task", "build"):
            for a in rest[1:]:
                if "://" in a:
                    _add(ctx, L.ASK, f"{name} runs remote code: {a}")
                    return
            for a in rest[1:]:
                if not a.startswith("-"):
                    if _check_path(ctx, a, "exec") is not None:
                        ctx.exec_after_download = True
                        _project_exec(ctx, f"{name} {sub} {a}")
                    return
            _project_exec(ctx, f"{name} {sub}")
            return
    safe_sys_path = False
    while rest:
        a = rest.pop(0)
        if a in ("-V", "--version", "-h", "--help", "-v") and not rest:
            return
        if a in inline_flags or (a.startswith("-c") and py and len(a) > 2 and not a.startswith("--")):
            code = rest[0] if rest else (a[2:] if len(a) > 2 else "")
            return _inline_code(ctx, name, code)
        if py and a == "-m":
            mod = rest.pop(0) if rest else ""
            return _python_module(mod, rest, ctx, safe_sys_path=safe_sys_path)
        if a == "-":
            break
        if py and a.startswith("-") and not a.startswith("--") and len(a) > 1:
            flags = a[1:]
            idx = 0
            while idx < len(flags):
                ch = flags[idx]
                if ch in ("I", "P"):
                    safe_sys_path = True
                    idx += 1
                    continue
                if ch == "c":
                    code = flags[idx + 1:] if idx + 1 < len(flags) else (rest.pop(0) if rest else "")
                    return _inline_code(ctx, name, code)
                if ch == "m":
                    mod = flags[idx + 1:] if idx + 1 < len(flags) else (rest.pop(0) if rest else "")
                    return _python_module(mod, rest, ctx, safe_sys_path=safe_sys_path)
                if ch in ("X", "W"):
                    if idx + 1 >= len(flags) and rest:
                        rest.pop(0)
                    break
                if ch.isdigit():
                    break
                idx += 1
            continue
        if a in value_opts:
            if rest:
                val = rest.pop(0)
                if a in ("-r", "--require", "--import", "--env-file", "-I") and _looks_like_path_token(val):
                    _check_path(ctx, val, "exec")
            continue
        if a.startswith("-"):
            continue
        if "://" in a:
            _add(ctx, L.ASK, f"{name} runs remote code: {a}")
            return
        if a in STDIN_PATHS:
            break
        if _check_path(ctx, a, "exec") is not None:
            ctx.exec_after_download = True
            _project_exec(ctx, f"{name} {a}")
        _paths(ctx, [x for x in rest if _looks_like_path_token(x)], "read")
        return
    if seg.heredoc is not None or seg.herestring is not None:
        return _inline_code(ctx, name, seg.heredoc if seg.heredoc is not None else seg.herestring)
    if seg.piped_in:
        if getattr(ctx.policy, "inline_exec", "ask") == "allow" and ctx.base_dir is not None and not ctx.untrusted_download:
            _project_exec(ctx, f"piped {name}")
            return
        _add(ctx, L.DENY, f"Untrusted pipeline execution directly into interpreter ({name})")
        return
    _add(ctx, L.ASK, f"Interactive {name} session requires owner approval")


def _python_module_paths(mod_l: str, rest: List[str], ctx: _Ctx) -> None:
    """Inspect all path arguments to `python -m <mod>` (including Windows paths and write targets)."""
    if mod_l == "json.tool":
        end_of_opts = False
        pos_idx = 0
        i = 0
        while i < len(rest):
            a = rest[i]
            i += 1
            if a == "--" and not end_of_opts:
                end_of_opts = True
                continue
            if not end_of_opts and a.startswith("-") and len(a) > 1:
                if (a == "--indent" or (a.startswith("--") and "=" not in a and len(a) >= 4 and "--indent".startswith(a))) and i < len(rest):
                    i += 1
                elif a.startswith("--") and "=" in a:
                    opt, val = a.split("=", 1)
                    if _looks_like_path_token(val):
                        _check_path(ctx, val, "write" if opt in ("--output", "--outfile") else "read")
                continue
            _check_path(ctx, a, "write" if pos_idx >= 1 else "read")
            pos_idx += 1
        return
    if mod_l == "py_compile":
        _paths(ctx, rest, "write")
        return
    if mod_l == "compileall":
        val_opts = {"-r", "-j", "-x", "-d", "-e", "-s", "-p", "-o", "--invalidation-mode"}
        end_of_opts = False
        i = 0
        while i < len(rest):
            a = rest[i]
            i += 1
            if a == "--" and not end_of_opts:
                end_of_opts = True
                continue
            if not end_of_opts and a.startswith("-") and len(a) > 1:
                if a == "-i" and i < len(rest):
                    _check_path(ctx, rest[i], "read")
                    i += 1
                elif a.startswith("-i") and len(a) > 2 and not a.startswith("--"):
                    _check_path(ctx, a[2:], "read")
                elif a in val_opts and i < len(rest):
                    i += 1
                elif a.startswith("--") and "=" in a:
                    val = a.split("=", 1)[1]
                    if _looks_like_path_token(val):
                        _check_path(ctx, val, "read")
                continue
            _check_path(ctx, a, "write")
        return
    if mod_l in ("venv", "virtualenv"):
        end_of_opts = False
        i = 0
        while i < len(rest):
            a = rest[i]
            i += 1
            if a == "--" and not end_of_opts:
                end_of_opts = True
                continue
            if not end_of_opts and a.startswith("-") and len(a) > 1:
                if a == "--prompt" and i < len(rest):
                    i += 1
                elif a.startswith("--") and "=" in a:
                    val = a.split("=", 1)[1]
                    if _looks_like_path_token(val):
                        _check_path(ctx, val, "read")
                continue
            _check_path(ctx, a, "write")
        return
    if mod_l in ("black", "isort"):
        read_only = any(a in ("--check", "--check-only", "--diff") or (mod_l == "isort" and a == "-c") for a in rest)
        path_read_opts = {"--config", "--settings-path", "--settings-file", "--sp"}
        nonpath_val_opts = {
            "-a", "--add-import", "--rm", "--remove-import", "-l", "--line-length",
            "--profile", "-m", "--multi-line", "-t", "--target-version",
            "--include", "--exclude", "--extend-exclude", "--force-exclude",
            "-s", "--skip", "--skip-glob", "-w", "--workers", "--stdin-filename",
        }
        if mod_l == "black":
            nonpath_val_opts = nonpath_val_opts | {"-c", "--code"}
        else:
            nonpath_val_opts = nonpath_val_opts | {"--code"}
        end_of_opts = False
        i = 0
        while i < len(rest):
            a = rest[i]
            i += 1
            if a == "--" and not end_of_opts:
                end_of_opts = True
                continue
            if not end_of_opts and a.startswith("-") and len(a) > 1:
                if a.startswith("--") and "=" in a:
                    opt, val = a.split("=", 1)
                    if opt in path_read_opts:
                        _check_path(ctx, val, "read")
                    elif opt not in nonpath_val_opts and _looks_like_path_token(val):
                        _check_path(ctx, val, "read")
                elif a in path_read_opts:
                    if i < len(rest):
                        _check_path(ctx, rest[i], "read")
                        i += 1
                elif a in nonpath_val_opts:
                    if i < len(rest):
                        i += 1
                continue
            _check_path(ctx, a, "read" if read_only else "write")
        return
    if mod_l == "ruff":
        mutating = (
            ("format" in rest and not any(a in ("--check", "--diff") for a in rest))
            or any(a == "--fix" or a.startswith("--fix-") or a == "--unsafe-fixes" for a in rest)
        )
        nonpath_val_opts = {
            "--select", "--ignore", "--extend-select", "--extend-ignore", "--exclude",
            "--extend-exclude", "--target-version", "--line-length", "--output-format",
            "--cache-dir", "--stdin-filename",
        }
        end_of_opts = False
        sub_seen = False
        i = 0
        while i < len(rest):
            a = rest[i]
            i += 1
            if a == "--" and not end_of_opts:
                end_of_opts = True
                continue
            if not end_of_opts and a.startswith("-") and len(a) > 1:
                if a.startswith("--") and "=" in a:
                    opt, val = a.split("=", 1)
                    if opt == "--config":
                        _check_path(ctx, val, "read")
                    elif opt == "--output-file":
                        _check_path(ctx, val, "write")
                    elif opt not in nonpath_val_opts and _looks_like_path_token(val):
                        _check_path(ctx, val, "read")
                elif a == "--config":
                    if i < len(rest):
                        _check_path(ctx, rest[i], "read")
                        i += 1
                elif a in ("-o", "--output-file"):
                    if i < len(rest):
                        _check_path(ctx, rest[i], "write")
                        i += 1
                elif a in nonpath_val_opts:
                    if i < len(rest):
                        i += 1
                continue
            if not end_of_opts and not sub_seen and a in ("format", "check", "rule", "linter", "clean", "version", "help"):
                sub_seen = True
                continue
            sub_seen = True
            _check_path(ctx, a, "write" if mutating else "read")
        return
    _paths(ctx, rest, "read")


def _python_module(mod: str, rest: List[str], ctx: _Ctx, safe_sys_path: bool = False) -> None:
    mod_l = mod.lower()
    if mod_l in ("pip", "pip3"):
        _pip(rest, ctx)
        if not safe_sys_path:
            _project_exec(ctx, f"python -m {mod} (without -I/-P)")
        return
    if mod_l in ("http.server", "smtpd", "ftplib", "telnetlib"):
        _add(ctx, L.ASK, f"python -m {mod} opens a network service (owner approval)")
        return
    _python_module_paths(mod_l, rest, ctx)
    if mod_l in SAFE_PY_MODULES:
        if mod_l in ALWAYS_PROJECT_EXEC_PY_MODULES:
            _project_exec(ctx, f"python -m {mod}")
        elif not safe_sys_path:
            _project_exec(ctx, f"python -m {mod} (without -I/-P)")
        return
    _project_exec(ctx, f"python -m {mod}")


def _pip(args: List[str], ctx: _Ctx) -> None:
    rest = list(args)
    sub = next((x.lower() for x in args if not x.startswith("-")), "")
    url_opts = {"-i", "--index-url", "--extra-index-url", "-f", "--find-links"}
    path_opts = {"-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-t", "--target"}
    while rest:
        a = rest.pop(0)
        if "=" in a and a.split("=", 1)[0] in url_opts | path_opts:
            a, val = a.split("=", 1)
            rest.insert(0, val)
        if a in url_opts and rest:
            _check_url(ctx, rest.pop(0))
        elif a in path_opts and rest:
            val = rest.pop(0)
            if "://" in val or val.startswith("git+"):
                _check_url(ctx, val.replace("git+", "", 1))
            else:
                _check_path(ctx, val, "write" if a in ("-t", "--target") else "read")
        elif "://" in a:
            _check_url(ctx, a.split("+", 1)[-1] if a.startswith(("git+", "hg+", "svn+")) else a)
        elif not a.startswith("-") and _looks_like_path_token(a):
            _check_path(ctx, a, "read")
    if sub in ("install", "wheel", "download", "build"):
        _project_exec(ctx, f"pip {sub}")


def _project_tool(name: str, args: List[str], ctx: _Ctx) -> None:
    if name in ("pip", "pip3"):
        return _pip(args, ctx)
    if name in ("npm", "pnpm", "yarn") and args:
        sub = args[0]
        if sub in ("exec", "dlx", "x") or (name == "npm" and sub == "exec"):
            _add(ctx, L.ASK, f"{name} {sub} downloads and runs an arbitrary package (owner approval)")
            return
        if any(a in ("-g", "--global", "--location=global") for a in args):
            _add(ctx, L.ASK, f"{name} global install changes the machine, not the workspace (owner approval)")
            return
        if sub in ("publish", "login", "adduser", "token"):
            _add(ctx, L.ASK, f"{name} {sub} sends data/credentials to a registry (owner approval)")
            return
        if sub in ("config", "set") and len(args) > 1 and args[1] in ("set", "edit", "delete"):
            _add(ctx, L.ASK, f"{name} config change (owner approval)")
            return
    if name == "uv" and args and args[0] in ("tool", "run") and len(args) > 1 and args[0] == "tool":
        _add(ctx, L.ASK, "uv tool installs/runs external packages (owner approval)")
        return
    if name == "uv" and args and args[0] == "pip":
        return _pip(args[1:], ctx)
    for a in args:
        if "://" in a:
            _check_url(ctx, a.split("+", 1)[-1] if a.startswith(("git+", "hg+")) else a)
        elif not _is_option(a) and (_looks_like_path_token(a) or a.startswith("..")):
            _check_path(ctx, a, "read")
        elif a.startswith("--") and "=" in a:
            val = a.split("=", 1)[1]
            if "://" in val:
                _check_url(ctx, val)
            elif _looks_like_path_token(val):
                _check_path(ctx, val, "read")
    if name in PROJECT_TOOLS:
        _project_exec(ctx, f"{name} {' '.join(args[:2])}".strip())


def _pattern_tool(name: str, args: List[str], ctx: _Ctx) -> None:
    rest = list(args)
    if name == "rg" and any(a == "--pre" or a.startswith("--pre=") for a in rest):
        _add(ctx, L.ASK, "rg --pre runs an arbitrary program on every searched file (owner approval)")
        return
    in_place = name == "yq" and any(a in ("-i", "--inplace") or a.startswith("--inplace=") for a in rest)
    pattern_given = any(
        a in ("-e", "--regexp", "-f", "--file", "-Pattern", "-pattern")
        or a.startswith(("--regexp=", "--file="))
        or (a.startswith(("-e", "-f")) and len(a) > 2 and not a.startswith("--"))
        for a in rest
    )
    skip_next = False
    first_positional = True
    for i, a in enumerate(rest):
        if skip_next:
            skip_next = False
            if rest[i - 1] in ("-f", "--file"):
                _check_path(ctx, a, "read")
            continue
        if a in ("-e", "--regexp", "-f", "--file", "-Pattern", "-pattern", "-m", "-A", "-B", "-C",
                 "--max-count", "-g", "--glob", "-t", "--type", "--include", "--exclude", "--arg",
                 "--argjson"):
            skip_next = True
            continue
        if a.startswith("--file="):
            _check_path(ctx, a.split("=", 1)[1], "read")
            continue
        if a.startswith("-f") and len(a) > 2 and not a.startswith("--"):
            _check_path(ctx, a[2:], "read")
            continue
        if _is_option(a):
            continue
        if first_positional and not pattern_given:
            first_positional = False
            continue
        if name in ("jq", "yq") and a.startswith("."):
            continue
        _check_path(ctx, a, "write" if in_place else "read")


def _sed_script_is_pure(script: str) -> bool:
    """Strict allowlist for side-effect-free sed scripts (p/d/q/=, pure s///[gpIiMm0-9]*, y///).

    Fails closed (returns False -> ASK) on any write/read/exec command (w/W/r/R/e),
    alternate address delimiters (\\%..\\%), blocks ({...}), branches, or unrecognized syntax.
    """
    n = len(script)
    i = 0

    def _skip_delimited(pos: int, delim: str) -> int:
        while pos < n:
            ch = script[pos]
            if ch == "\\" and pos + 1 < n:
                pos += 2
                continue
            if ch == delim:
                return pos + 1
            pos += 1
        return -1

    def _skip_simple_addr(pos: int) -> int:
        while pos < n and script[pos] in " \t":
            pos += 1
        if pos >= n:
            return pos
        if script[pos] == "/":
            nxt = _skip_delimited(pos + 1, "/")
            if nxt < 0:
                return -1
            pos = nxt
            while pos < n and script[pos] in "IMim":
                pos += 1
            return pos
        if script[pos].isdigit() or script[pos] in "$+~":
            while pos < n and (script[pos].isdigit() or script[pos] in "$+~"):
                pos += 1
            return pos
        return pos

    saw_cmd = False
    while i < n:
        while i < n and script[i] in " \t;\r\n":
            i += 1
        if i >= n:
            break
        # Optional 1 or 2 simple addresses separated by ','
        p1 = _skip_simple_addr(i)
        if p1 < 0:
            return False
        i = p1
        while i < n and script[i] in " \t":
            i += 1
        if i < n and script[i] == ",":
            i += 1
            p2 = _skip_simple_addr(i)
            if p2 < 0:
                return False
            i = p2
            while i < n and script[i] in " \t":
                i += 1
        if i < n and script[i] == "!":
            i += 1
            while i < n and script[i] in " \t":
                i += 1
        if i >= n:
            return False
        cmd = script[i]
        i += 1
        saw_cmd = True
        if cmd in ("p", "d", "q", "="):
            while i < n and script[i] in " \t":
                i += 1
            if i < n and script[i] not in ";\r\n":
                return False
        elif cmd in ("s", "y"):
            if i >= n or script[i] in "\\ \t\r\n":
                return False
            delim = script[i]
            i = _skip_delimited(i + 1, delim)
            if i < 0:
                return False
            i = _skip_delimited(i, delim)
            if i < 0:
                return False
            if cmd == "s":
                while i < n and script[i] in "gpIiMm0123456789":
                    i += 1
            while i < n and script[i] in " \t":
                i += 1
            if i < n and script[i] not in ";\r\n":
                return False
        else:
            return False
    return saw_cmd


def _sed_check_embedded_paths(script: str, ctx: _Ctx) -> None:
    """Inspect any file targets referenced inside a non-pure sed script so protected paths LOCK/DENY."""
    for m in re.finditer(r"(?:^|[;\n{}\s!/])([wWrR])\s*([^\s;}\n]+)", script):
        kind, target = m.group(1), m.group(2).strip("'\"")
        if target and (_looks_like_path_token(target) or "." in target):
            _check_path(ctx, target, "write" if kind in ("w", "W") else "read")
    for tok in re.split(r"[\s;{}]+", script):
        tok = tok.strip("'\"")
        if tok and _looks_like_path_token(tok):
            for pref in ("w", "W", "r", "R"):
                if tok.startswith(pref) and len(tok) > 1 and _looks_like_path_token(tok[1:]):
                    _check_path(ctx, tok[1:], "write" if pref in ("w", "W") else "read")
                    break
            else:
                if not tok.startswith(("s/", "s|", "s#", "s:", "/")):
                    _check_path(ctx, tok, "write")


def _sed(args: List[str], ctx: _Ctx) -> None:
    in_place = False
    unknown_opt = False
    scripts: List[str] = []
    files: List[str] = []
    explicit = False
    end_of_opts = False
    rest = list(args)
    safe_long_bool = ("--quiet", "--silent", "--regexp-extended", "--unbuffered",
                      "--separate", "--null-data", "--posix", "--sandbox")
    while rest:
        a = rest.pop(0)
        if a == "--" and not end_of_opts:
            end_of_opts = True
            continue
        if not end_of_opts and a.startswith("--") and len(a) > 2:
            opt, eq, val = a.partition("=")
            if "--in-place".startswith(opt):
                in_place = True
            elif "--expression".startswith(opt):
                explicit = True
                scripts.append(val if eq else (rest.pop(0) if rest else ""))
            elif "--file".startswith(opt):
                explicit = True
                sf = val if eq else (rest.pop(0) if rest else "")
                if sf:
                    _check_path(ctx, sf, "read")
                    _project_exec(ctx, f"sed -f {sf}")
            elif "--line-length".startswith(opt):
                if not eq and rest:
                    rest.pop(0)
            elif any(o.startswith(opt) for o in safe_long_bool):
                pass
            else:
                unknown_opt = True
                _add(ctx, L.ASK, f"sed uses unrecognized option '{a}' (owner approval)")
                if eq and _looks_like_path_token(val):
                    _check_path(ctx, val, "write")
            continue
        if not end_of_opts and a.startswith("-") and len(a) > 1 and not a.startswith("--"):
            chars = a[1:]
            k = 0
            while k < len(chars):
                ch = chars[k]
                if ch in ("n", "r", "E", "u", "s", "z"):
                    k += 1
                    continue
                if ch == "i":
                    in_place = True
                    break  # remaining chars are optional backup suffix
                if ch == "e":
                    explicit = True
                    scripts.append(chars[k + 1:] if k + 1 < len(chars) else (rest.pop(0) if rest else ""))
                    break
                if ch == "f":
                    explicit = True
                    sf = chars[k + 1:] if k + 1 < len(chars) else (rest.pop(0) if rest else "")
                    if sf:
                        _check_path(ctx, sf, "read")
                        _project_exec(ctx, f"sed -f {sf}")
                    break
                if ch == "l":
                    if k + 1 >= len(chars) and rest:
                        rest.pop(0)
                    break
                unknown_opt = True
                _add(ctx, L.ASK, f"sed uses unrecognized flag '-{ch}' (owner approval)")
                break
            continue
        if not explicit and not scripts:
            scripts.append(a)
        else:
            files.append(a)
    for s in scripts:
        if not _sed_script_is_pure(s):
            _add(ctx, L.ASK, "sed script uses commands outside the pure read/substitute allowlist (owner approval)")
            _sed_check_embedded_paths(s, ctx)
    file_mode = "write" if (in_place or unknown_opt) else "read"
    for f in files:
        _check_path(ctx, f, file_mode)


_SAFE_AWK_BUILTINS = frozenset({
    "length", "substr", "index", "split", "sub", "gsub", "match",
    "tolower", "toupper", "sprintf", "int", "sqrt", "exp", "log",
    "sin", "cos", "atan2", "rand", "srand", "strftime", "systime",
})


def _awk_program_is_pure(program: str) -> bool:
    """Strict read-only allowlist for inline awk programs.

    Fails closed (returns False -> _inline_code) on redirections/pipes (>, |, <),
    indirect calls/directives (@), backslash continuations/escapes outside quotes,
    command execution (system/getline/close/fflush), or non-allowlisted function calls.
    """
    if not program or not program.strip():
        return True
    # Any '@', '>', '|', or backslash-newline line continuation fails closed immediately
    if "@" in program or ">" in program or "|" in program or "\\\n" in program or "\\\r\n" in program:
        return False
    # Strip quoted string literals and regex literals to inspect identifiers/calls cleanly
    cleaned = re.sub(r'"(?:\\.|[^"\\])*"', '""', program)
    if "\\" in cleaned:
        return False
    if re.search(r"\b(system|getline|close|fflush|nextfile|function|func|ARGV|ARGC|ENVIRON|FILENAME|ARGIND)\b", cleaned):
        return False
    # Every function call `ident(` must be a pure safe builtin (or `printf(` / `print(` / control keywords)
    allowed_calls = _SAFE_AWK_BUILTINS | {"if", "while", "for", "print", "printf", "delete"}
    for m in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", cleaned):
        if m.group(1) not in allowed_calls:
            return False
    return True


def _awk(args: List[str], ctx: _Ctx) -> None:
    rest = list(args)
    program = None
    files: List[str] = []
    mutating = False
    end_of_opts = False
    while rest:
        a = rest.pop(0)
        if a == "--" and not end_of_opts:
            end_of_opts = True
            continue
        if not end_of_opts and a.startswith("--") and len(a) > 2:
            opt, eq, val = a.partition("=")
            if "--file".startswith(opt) or "--exec".startswith(opt):
                sf = val if eq else (rest.pop(0) if rest else "")
                if sf:
                    _check_path(ctx, sf, "read")
                    _project_exec(ctx, f"awk {opt} {sf}")
                program = ""
            elif "--include".startswith(opt) or "--load".startswith(opt):
                mutating = True
                ext = val if eq else (rest.pop(0) if rest else "")
                _add(ctx, L.ASK, f"awk {opt} loads an extension or script ({ext})")
                if ext and _looks_like_path_token(ext):
                    _check_path(ctx, ext, "read")
            elif "--assign".startswith(opt) or "--field-separator".startswith(opt):
                if not eq and rest:
                    rest.pop(0)
            elif "--sandbox".startswith(opt) or "--posix".startswith(opt) or "--traditional".startswith(opt):
                pass
            else:
                mutating = True
                _add(ctx, L.ASK, f"awk uses unrecognized option '{a}' (owner approval)")
            continue
        if not end_of_opts and a.startswith("-") and len(a) > 1 and not a.startswith("--"):
            chars = a[1:]
            k = 0
            while k < len(chars):
                ch = chars[k]
                if ch in ("f", "E"):
                    sf = chars[k + 1:] if k + 1 < len(chars) else (rest.pop(0) if rest else "")
                    if sf:
                        _check_path(ctx, sf, "read")
                        _project_exec(ctx, f"awk -{ch} {sf}")
                    program = ""
                    break
                if ch in ("i", "l"):
                    mutating = True
                    ext = chars[k + 1:] if k + 1 < len(chars) else (rest.pop(0) if rest else "")
                    _add(ctx, L.ASK, f"awk -{ch} loads an extension or inplace writer ({ext})")
                    if ext and _looks_like_path_token(ext):
                        _check_path(ctx, ext, "read")
                    break
                if ch in ("v", "F"):
                    if k + 1 >= len(chars) and rest:
                        rest.pop(0)
                    break
                if ch in ("S", "P"):
                    k += 1
                    continue
                mutating = True
                _add(ctx, L.ASK, f"awk uses unrecognized flag '-{ch}' (owner approval)")
                break
            continue
        if program is None:
            program = a
        else:
            files.append(a)
    if program and not _awk_program_is_pure(program):
        _inline_code(ctx, "awk", program)
        mutating = True
    for f in files:
        if "=" in f and not ("/" in f.split("=", 1)[0] or "\\" in f.split("=", 1)[0]):
            continue
        _check_path(ctx, f, "write" if mutating else "read")


FIND_FILTERS = {"-name", "-iname", "-path", "-ipath", "-regex", "-iregex", "-type", "-newer",
                "-mtime", "-mmin", "-atime", "-amin", "-ctime", "-cmin", "-size", "-user", "-group",
                "-empty", "-wholename", "-iwholename", "-perm", "-links", "-inum", "-samefile"}


def _find(args: List[str], ctx: _Ctx) -> None:
    roots: List[str] = []
    i = 0
    while i < len(args) and not (args[i].startswith("-") or args[i] in ("(", ")", "!", ",")):
        roots.append(args[i])
        i += 1
    if not roots:
        roots = ["."]
    expr = args[i:]
    deleting = "-delete" in expr
    # A filtered find (-name, -type, -mtime ...) deletes only matches, not the whole tree.
    selective = any(t in FIND_FILTERS for t in expr)
    exec_cmds: List[List[str]] = []
    j = 0
    while j < len(expr):
        tok = expr[j]
        if tok in ("-exec", "-execdir", "-ok", "-okdir"):
            cmd: List[str] = []
            j += 1
            while j < len(expr) and expr[j] not in (_SEMI, ";", "+"):
                cmd.append(expr[j])
                j += 1
            exec_cmds.append(cmd)
        elif tok in ("-fprint", "-fprint0", "-fprintf", "-fls") and j + 1 < len(expr):
            _check_path(ctx, expr[j + 1], "write")
            j += 1
        j += 1
    for r in roots:
        resolved = _check_path(ctx, r, "delete" if deleting else "read", recursive=deleting and not selective)
        if resolved is None:
            continue
    for cmd in exec_cmds:
        if not cmd:
            continue
        inner_bin = _canon_binary(cmd[0])
        placeholder_dir = roots[0]
        replaced = [placeholder_dir if w == "{}" else w for w in cmd]
        if inner_bin in DELETE_BINARIES:
            for r in roots:
                _check_path(ctx, r, "delete", recursive=not selective)
            continue
        _dispatch(replaced, Segment(words=replaced), ctx)


def _is_recursive_flag(word: str) -> bool:
    low = word.lower()
    if low in ("--recursive", "/s", "-recurse"):
        return True
    if low.startswith("--") or not low.startswith("-") or len(low) < 2:
        return False
    if "-recurse".startswith(low) and len(low) >= 2:      # -r, -re, -rec ... (PowerShell)
        return True
    if "-force".startswith(low):
        return False
    return bool(re.match(r"^-[a-zA-Z]{1,4}$", word)) and ("r" in word[1:] or "R" in word[1:])


def _delete(name: str, args: List[str], ctx: _Ctx) -> None:
    windows = name in ("del", "erase", "rd", "rmdir") and any(a.startswith("/") and len(a) <= 3 for a in args)
    recursive = False
    targets: List[str] = []
    end = False
    for a in args:
        low = a.lower()
        if a == "--":
            end = True
            continue
        if not end and _is_recursive_flag(a):
            recursive = True
            continue
        if not end and _is_option(a, windows):
            if ":" in a and a.startswith("-") and not a.startswith("--"):
                opt_l, _, val = a.partition(":")
                if opt_l.lower() in ("-path", "-literalpath") and val:
                    targets.append(val)
                continue
            if low.startswith("-path") or low.startswith("-literalpath"):
                continue
            if low == "--no-preserve-root":
                recursive = True
            continue
        targets.append(a)
    if name in ("rd",) :
        recursive = recursive or any(a.lower() == "/s" for a in args)
    for t in targets:
        _check_path(ctx, t, "delete", recursive=recursive)


def _robocopy(args: List[str], ctx: _Ctx) -> None:
    mirror = any(a.lower() in ("/mir", "/purge") for a in args)
    pos = [a for a in args if not _is_option(a, windows_flags=True)]
    if pos:
        _check_path(ctx, pos[0], "read")
    if len(pos) > 1:
        _check_path(ctx, pos[1], "delete" if mirror else "write", recursive=mirror)


def _copy_like(name: str, args: List[str], ctx: _Ctx) -> None:
    windows = name in CMD_BUILTINS
    value_opts = {"-t", "--target-directory", "-S", "--suffix", "-m", "--mode", "-o", "--owner",
                  "-g", "--group", "-destination", "-path", "-literalpath"}
    pos: List[str] = []
    dest: Optional[str] = None
    rest = list(args)
    while rest:
        a = rest.pop(0)
        low = a.lower()
        if low in ("-t", "--target-directory", "-destination") and rest:
            dest = rest.pop(0)
            continue
        if a.startswith("-t") and len(a) > 2 and not a.startswith("--"):
            dest = a[2:]
            continue
        if low.startswith("--target-directory="):
            dest = a.split("=", 1)[1]
            continue
        if ":" in a and a.startswith("-") and not a.startswith("--"):
            opt_l, _, val = a.partition(":")
            low_opt = opt_l.lower()
            if val and low_opt.startswith("-dest") and "-destination".startswith(low_opt):
                dest = val
                continue
            if val and low_opt in ("-path", "-literalpath"):
                pos.append(val)
                continue
        if low in value_opts and rest:
            val = rest.pop(0)
            if low in ("-path", "-literalpath"):
                pos.append(val)
            continue
        if _is_option(a, windows):
            continue
        pos.append(a)
    if dest is None and len(pos) > 1:
        dest = pos.pop()
    moving = name in ("mv", "move", "move-item", "mi")
    linking = (name == "ln") or (
        name == "cp" and any(
            a in ("-s", "--symbolic-link", "-l", "--link")
            or (a.startswith("-") and not a.startswith("--") and any(c in a[1:] for c in "sl"))
            for a in args
        )
    )
    for src in pos:
        resolved_src = _check_path(ctx, src, "move" if moving else "read")
        if linking and (_touches_sensitive_control_dir(resolved_src or src) or any(c in src for c in "*?[]{}")):
            _add(ctx, L.ASK, f"{name} links sensitive or wildcard target '{src}' (owner approval)")
    if dest is not None:
        resolved_dest = _check_path(ctx, dest, "write")
        if _touches_sensitive_control_dir(resolved_dest or dest):
            for src in pos:
                base = src.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
                if base:
                    _check_path(ctx, dest.rstrip("/\\") + "/" + base, "write")


def _link_or_new_item(name: str, args: List[str], ctx: _Ctx) -> None:
    """Check Windows mklink and PowerShell New-Item / ni link creations targeting sensitive paths."""
    _paths(ctx, args, "write", windows=True)
    if name == "mklink":
        for a in args:
            if not _is_option(a, windows_flags=True):
                resolved = _check_path(ctx, a, "read")
                if (
                    _touches_sensitive_control_dir(resolved or a)
                    or classify_sensitive(a, resolved or "", write_mode=True)
                    or any(c in a for c in "*?[]{}")
                ):
                    _add(ctx, L.ASK, f"mklink links sensitive or wildcard target '{a}' (owner approval)")
        return
    item_type = ""
    targets: List[str] = []
    i = 0
    n = len(args)
    while i < n:
        a = args[i]
        low = a.lower()
        if ":" in a and a.startswith("-") and not a.startswith("--"):
            opt_l, _, val = a.partition(":")
            if opt_l.lower() in ("-itemtype", "-type"):
                item_type = val.lower()
            elif opt_l.lower() in ("-target", "-value") and val:
                targets.append(val)
            i += 1
            continue
        if low in ("-itemtype", "-type") and i + 1 < n:
            item_type = args[i + 1].lower()
            i += 2
            continue
        if low in ("-target", "-value") and i + 1 < n:
            targets.append(args[i + 1])
            i += 2
            continue
        i += 1
    if item_type.startswith(("junction", "symboliclink", "hardlink", "symlink", "junc", "sym", "hard")):
        for t in targets:
            resolved = _check_path(ctx, t, "read")
            if (
                _touches_sensitive_control_dir(resolved or t)
                or classify_sensitive(t, resolved or "", write_mode=True)
                or any(c in t for c in "*?[]{}")
            ):
                _add(ctx, L.ASK, f"{name} links sensitive or wildcard target '{t}' (owner approval)")


def _chown(args: List[str], ctx: _Ctx) -> None:
    recursive = any(_is_recursive_flag(a) for a in args)
    pos = [a for a in args if not _is_option(a)]
    for t in pos[1:]:
        _check_path(ctx, t, "delete" if recursive else "write", recursive=recursive)


def _dd(args: List[str], ctx: _Ctx) -> None:
    for a in args:
        if a.startswith("if="):
            _check_path(ctx, a[3:], "read")
        elif a.startswith("of="):
            _check_path(ctx, a[3:], "write")


def _chmod(args: List[str], ctx: _Ctx) -> None:
    pos = [a for a in args if not _is_option(a) or re.match(r"^-[rwxXst]+$", a)]
    if not pos:
        return
    mode, targets = pos[0], pos[1:]
    recursive = any(_is_recursive_flag(a) for a in args if a not in pos)
    if re.search(r"[ugoa]*[+=][rwxXt]*s|^[0-7]?[4-7][0-7]{3}$", mode):
        _add(ctx, L.ASK, f"chmod sets setuid/setgid bits ({mode})")
    if "x" in mode or re.match(r"^[0-7]*[1357][0-7]*$", mode):
        ctx.exec_after_download = True
    for t in targets:
        _check_path(ctx, t, "delete" if recursive else "write", recursive=recursive)


def _tar(args: List[str], ctx: _Ctx) -> None:
    """Fail-closed allowlist parser for tar.

    Only standard create/extract/list flags (-c/-x/-t/-z/-j/-J/-v/-p/-k/-O/-h/-f/-C/-T/-X
    and their long equivalents) are permitted without asking. Any other flag or long option
    (e.g. -g/--listed-incremental, --index-file, -b, -A/--concatenate, --delete, --transform,
    -I/-F/--to-command) fails closed to ASK and checks all path arguments in "write" mode.
    """
    rest = list(args)
    if ctx.variables.get("TAPE"):
        _check_path(ctx, ctx.variables["TAPE"], "write")

    safe_bool_short = set("cxtzjJvpOkhmnla")
    safe_val_short = set("fCTX")
    safe_long_bool = (
        "--create", "--extract", "--get", "--list", "--gzip", "--gunzip",
        "--bzip2", "--xz", "--verbose", "--preserve-permissions", "--keep-old-files",
        "--to-stdout", "--dereference", "--auto-compress", "--no-same-owner",
        "--no-same-permissions", "--one-file-system",
    )
    safe_long_val_write = ("--directory",)
    safe_long_val_archive = ("--file",)
    safe_long_val_read = ("--files-from", "--exclude-from")
    safe_long_val_nonpath = ("--exclude",)

    creating = False
    extracting = False
    unknown_mode = False
    first_is_oldstyle = bool(rest) and not rest[0].startswith("-")
    for idx, a in enumerate(rest):
        if a == "--":
            break
        if a.startswith("--") and len(a) > 2:
            opt = a.split("=", 1)[0]
            if "--create".startswith(opt) and len(opt) >= 3:
                creating = True
            elif any(o.startswith(opt) and len(opt) >= 3 for o in ("--extract", "--get")):
                extracting = True
            elif any(o.startswith(opt) and len(opt) >= 3 for o in (
                "--append", "--update", "--catenate", "--concatenate", "--delete",
                "--listed-incremental", "--index-file", "--transform", "--xform",
                "--to-command", "--checkpoint-action", "--use-compress-program",
                "--rsh-command", "--info-script", "--new-volume-script",
            )):
                creating = True
                unknown_mode = True
                _add(ctx, L.ASK, f"tar option '{a}' modifies archives or runs programs (owner approval)")
            elif not any(o.startswith(opt) and len(opt) >= 3 for o in (
                safe_long_bool + safe_long_val_write + safe_long_val_archive
                + safe_long_val_read + safe_long_val_nonpath
            )):
                unknown_mode = True
                _add(ctx, L.ASK, f"tar uses unrecognized option '{a}' (owner approval)")
        elif a.startswith("-") and not a.startswith("--") and len(a) > 1:
            for ch in a[1:]:
                if ch == "c":
                    creating = True
                elif ch == "x":
                    extracting = True
                if ch in safe_val_short:
                    break
                if ch not in safe_bool_short:
                    unknown_mode = True
                    _add(ctx, L.ASK, f"tar uses advanced/unallowlisted flag '-{ch}' in '{a}' (owner approval)")
                    break
        elif idx == 0 and first_is_oldstyle:
            # GNU/POSIX tar always treats a non-dash first argument as old-style option letters
            for ch in a:
                if ch == "c":
                    creating = True
                elif ch == "x":
                    extracting = True
                if ch not in safe_bool_short and ch not in safe_val_short:
                    unknown_mode = True
                    _add(ctx, L.ASK, f"tar uses advanced/unallowlisted old-style flag '{ch}' in '{a}' (owner approval)")
                    break

    def _check_tar_dir(target: str) -> None:
        if not target:
            return
        if any(c in target for c in "*?[]{}"):
            _add(ctx, L.ASK, f"tar directory contains glob/brace wildcard '{target}' (owner approval)")
        resolved = _check_path(ctx, target, "write")
        if extracting or unknown_mode:
            if _touches_sensitive_control_dir(resolved or target):
                _add(ctx, L.ASK, f"tar extracts into sensitive control directory '{target}' (owner approval)")

    if extracting and ctx.cwd and _touches_sensitive_control_dir(ctx.cwd):
        _add(ctx, L.ASK, f"tar extracts inside sensitive control directory '{ctx.cwd}' (owner approval)")

    def _check_tar_archive(val: str) -> None:
        if not val:
            return
        if "://" in val or (re.match(r"^[\w.-]+@[\w.-]+:", val) and not looks_windows_path(val)):
            _add(ctx, L.ASK, f"tar to a remote archive: {val}")
            return
        _check_path(ctx, val, "write" if (creating or unknown_mode) else "read")

    end_of_opts = False
    i = 0
    n = len(rest)
    while i < n:
        a = rest[i]
        is_first = (i == 0)
        i += 1
        if a == "--" and not end_of_opts:
            end_of_opts = True
            continue
        if not end_of_opts:
            if a.startswith("--") and len(a) > 2:
                opt, eq, val = a.partition("=")
                if "--directory".startswith(opt) and len(opt) >= 3:
                    target = val if eq else (rest[i] if i < n else "")
                    if not eq and i < n:
                        i += 1
                    _check_tar_dir(target)
                    continue
                if "--file".startswith(opt) and len(opt) >= 3:
                    target = val if eq else (rest[i] if i < n else "")
                    if not eq and i < n:
                        i += 1
                    _check_tar_archive(target)
                    continue
                if any(o.startswith(opt) and len(opt) >= 3 for o in safe_long_val_read):
                    target = val if eq else (rest[i] if i < n else "")
                    if not eq and i < n:
                        i += 1
                    if target:
                        _check_path(ctx, target, "read")
                    continue
                if any(o.startswith(opt) and len(opt) >= 3 for o in safe_long_val_nonpath):
                    if not eq and i < n:
                        i += 1
                    continue
                if eq and _looks_like_path_token(val):
                    _check_path(ctx, val, "write")
                continue
            if a.startswith("-") and not a.startswith("--") and len(a) > 1:
                chars = a[1:]
                k = 0
                while k < len(chars):
                    ch = chars[k]
                    if ch == "C":
                        target = chars[k + 1:] if k + 1 < len(chars) else (rest[i] if i < n else "")
                        if k + 1 >= len(chars) and i < n:
                            i += 1
                        _check_tar_dir(target)
                        break
                    if ch == "f":
                        target = chars[k + 1:] if k + 1 < len(chars) else (rest[i] if i < n else "")
                        if k + 1 >= len(chars) and i < n:
                            i += 1
                        _check_tar_archive(target)
                        break
                    if ch in ("T", "X"):
                        target = chars[k + 1:] if k + 1 < len(chars) else (rest[i] if i < n else "")
                        if k + 1 >= len(chars) and i < n:
                            i += 1
                        if target:
                            _check_path(ctx, target, "read")
                        break
                    if ch not in safe_bool_short:
                        # Fail closed: check any attached suffix as write
                        if k + 1 < len(chars) and _looks_like_path_token(chars[k + 1:]):
                            _check_path(ctx, chars[k + 1:], "write")
                        break
                    k += 1
                continue
            if is_first and first_is_oldstyle:
                if not unknown_mode:
                    for ch in a:
                        if ch == "f" and i < n:
                            _check_tar_archive(rest[i])
                            i += 1
                        elif ch == "C" and i < n:
                            _check_tar_dir(rest[i])
                            i += 1
                        elif ch in ("T", "X") and i < n:
                            _check_path(ctx, rest[i], "read")
                            i += 1
                continue
        if "://" in a or (re.match(r"^[\w.-]+@[\w.-]+:", a) and not looks_windows_path(a)):
            _add(ctx, L.ASK, f"tar to a remote archive: {a}")
            continue
        if extracting and (_touches_sensitive_control_dir(a) or classify_sensitive(a, write_mode=True) in ("autoexec", "startup", "critical", "secret")):
            _check_path(ctx, a, "write")
            if _touches_sensitive_control_dir(a):
                _add(ctx, L.ASK, f"tar extracts sensitive control member '{a}' (owner approval)")
        else:
            _check_path(ctx, a, "write" if unknown_mode else "read")


def _archive_extract(name: str, args: List[str], ctx: _Ctx) -> None:
    """Inspect unzip / 7z / 7za output directories (-d/-o spaced or attached) and sensitive targets."""
    def _check_out_dir(target: str) -> None:
        if not target:
            return
        if any(c in target for c in "*?[]{}"):
            _add(ctx, L.ASK, f"{name} output directory contains glob/brace wildcard '{target}' (owner approval)")
        resolved = _check_path(ctx, target, "write")
        if _touches_sensitive_control_dir(resolved or target):
            _add(ctx, L.ASK, f"{name} extracts into sensitive control directory '{target}' (owner approval)")

    if ctx.cwd and _touches_sensitive_control_dir(ctx.cwd):
        _add(ctx, L.ASK, f"{name} runs inside sensitive control directory '{ctx.cwd}' (owner approval)")

    i = 0
    n = len(args)
    end_of_opts = False
    is_7z = name in ("7z", "7za")
    sub_7z = (args[0].lower() if is_7z and args and not args[0].startswith("-") else "")
    while i < n:
        a = args[i]
        i += 1
        if a == "--" and not end_of_opts:
            end_of_opts = True
            continue
        if not end_of_opts:
            if not is_7z:
                if a.startswith("-") and not a.startswith("--") and len(a) > 1:
                    chars = a[1:]
                    for k, ch in enumerate(chars):
                        if ch == "d":
                            target = chars[k + 1:] if k + 1 < len(chars) else (args[i] if i < n else "")
                            if k + 1 >= len(chars) and i < n:
                                i += 1
                            _check_out_dir(target)
                            break
                    continue
                if a.startswith("--"):
                    continue
            else:
                if a == "-o" and i < n:
                    _check_out_dir(args[i])
                    i += 1
                    continue
                if a.startswith("-o") and len(a) > 2 and not a.startswith("--"):
                    _check_out_dir(a[2:])
                    continue
                if a.startswith("-") and a != "-":
                    continue
                if i == 1 and sub_7z in ("a", "d", "e", "l", "t", "u", "x"):
                    continue
        if _touches_sensitive_control_dir(a) or classify_sensitive(a, write_mode=True) in ("autoexec", "startup", "critical", "secret"):
            _check_path(ctx, a, "write")
            if _touches_sensitive_control_dir(a):
                _add(ctx, L.ASK, f"{name} targets sensitive control path '{a}' (owner approval)")
        else:
            _check_path(ctx, a, "write" if (is_7z and sub_7z in ("a", "u", "d")) else "read")


def _rsync(args: List[str], ctx: _Ctx) -> None:
    for a in args:
        if a in ("-e", "--rsh") or a.startswith("--rsh=") or a.startswith("--rsync-path"):
            _add(ctx, L.ASK, "rsync with a custom remote shell/program")
            return
    pos = [a for a in args if not _is_option(a)]
    remote = [a for a in pos if re.match(r"^(?:[\w.-]+@)?[\w.-]+::?", a) and not re.match(r"^[A-Za-z]:\\", a) or a.startswith("rsync://")]
    if remote:
        _add(ctx, L.ASK, "rsync to/from a remote host (owner approval)")
    deleting = any(a.startswith("--delete") or a == "--remove-source-files" for a in args)
    local = [a for a in pos if a not in remote]
    for idx, a in enumerate(local):
        is_dest = idx == len(local) - 1 and len(local) > 1
        _check_path(ctx, a, "delete" if (deleting and is_dest) else ("write" if is_dest else "read"), recursive=deleting)


def _git(args: List[str], ctx: _Ctx) -> None:
    original_cwd = ctx.cwd
    try:
        _git_in_directory(args, ctx)
    finally:
        ctx.cwd = original_cwd


_SAFE_GIT_CONFIG_KEYS = {
    "core.autocrlf", "core.safecrlf", "core.eol", "core.quotepath", "core.longpaths",
    "core.filemode", "core.symlinks", "core.ignorecase",
    "user.name", "user.email", "init.defaultbranch",
    "pull.rebase", "pull.ff", "fetch.prune", "merge.ff", "rebase.autostash",
    "http.postbuffer", "http.version", "safe.directory",
    "diff.renames", "diff.algorithm", "status.showuntrackedfiles",
    "commit.gpgsign", "tag.gpgsign", "gc.auto", "pack.threads",
}


def _git_config_key_safe(raw_kv: str) -> bool:
    key = (raw_kv or "").split("=", 1)[0].strip().lower()
    if not key:
        return False
    if key in _SAFE_GIT_CONFIG_KEYS:
        return True
    if key.startswith(("color.", "advice.")):
        return True
    return False


def _git_in_directory(args: List[str], ctx: _Ctx) -> None:
    rest = list(args)
    while rest and rest[0].startswith("-"):
        opt = rest.pop(0)
        if opt in ("-C",) and rest:
            directory = _check_path(ctx, rest.pop(0), "cd")
            if directory:
                ctx.cwd = directory
        elif opt.startswith(("--git-dir", "--work-tree")):
            val = opt.split("=", 1)[1] if "=" in opt else (rest.pop(0) if rest else "")
            _check_path(ctx, val, "write")
        elif opt == "-c" or (opt.startswith("-c") and len(opt) > 2 and not opt.startswith("--")):
            cfg = opt[2:] if len(opt) > 2 else (rest.pop(0) if rest else "")
            if not _git_config_key_safe(cfg):
                _add(ctx, L.ASK, "git -c / --exec-path can run arbitrary programs (owner approval)")
        elif opt == "--config-env" or opt.startswith(("--config-env=", "--exec-path")):
            _add(ctx, L.ASK, "git -c / --exec-path can run arbitrary programs (owner approval)")
            if opt == "--config-env" and rest:
                rest.pop(0)
    if not rest:
        return
    sub, sargs = rest[0], rest[1:]
    for a in sargs:
        if a.startswith(("--upload-pack", "--receive-pack", "--exec", "-u", "--config")) and sub in ("clone", "fetch", "pull", "push", "ls-remote", "archive"):
            _add(ctx, L.ASK, f"git {sub} {a} can run arbitrary programs (owner approval)")
            return
        if a.startswith("ext::"):
            _add(ctx, L.DENY, "git ext:: transport executes arbitrary commands")
            return
    if sub == "config":
        if not any(a in ("--get", "--get-all", "--list", "-l", "--get-regexp", "--show-origin") for a in sargs):
            _add(ctx, L.ASK, "git config change (aliases/hooks/ssh commands can execute code)")
        return
    if sub == "push":
        ctx.effects.add("egress")
        forced = [a for a in sargs if a in ("-f", "--force", "--mirror", "--delete", "-d", "--prune")
                  or a.startswith(("--force-with-lease", "--force-if-includes")) or
                  (not a.startswith("-") and (a.startswith(":") or a.startswith("+")))]
        if forced:
            _add(ctx, L.ASK, f"git push {forced[0]} rewrites or deletes remote history (owner approval)")
            _git_destructive_target(ctx, "push")
        pos = [a for a in sargs if not a.startswith("-")]
        remote = pos[0] if pos else "origin"
        if "://" in remote or "@" in remote or remote.startswith(("/", ".", "~")):
            _add(ctx, L.ASK, "git push to external remote requires human owner approval")
        elif remote not in ("origin", "upstream"):
            _add(ctx, L.ASK, f"git push to remote '{remote}' requires owner approval")
        return
    if sub == "remote" and sargs and sargs[0] in ("add", "set-url", "rename"):
        for a in sargs[1:]:
            if "://" in a:
                _check_url(ctx, a, allowlist=False)
        _add(ctx, L.ASK, f"git remote {sargs[0]} changes where pushes go (owner approval)")
        return
    if sub in ("clone", "fetch", "pull", "ls-remote", "submodule"):
        ctx.effects.add("fetch")
        pos = [a for a in sargs if not a.startswith("-") and a not in ("add", "update", "init")]
        for a in pos:
            if "://" in a:
                _check_url(ctx, a)
            elif re.match(r"^[\w.-]+@[\w.-]+:", a):
                host = a.split("@", 1)[1].split(":", 1)[0]
                if not ctx.policy.host_allowed(host):
                    _add(ctx, L.ASK, f"git over SSH to a host outside the allowlist: {host}")
            elif sub == "clone" and _looks_like_path_token(a):
                _check_path(ctx, a, "write")
        return
    lost = _git_discards_work(sub, sargs)
    if lost:
        _add(ctx, L.ASK, f"{lost} (owner approval)")
        _git_destructive_target(ctx, sub)
    if sub in ("archive", "bundle", "format-patch", "worktree", "clean", "checkout", "restore",
               "add", "rm", "mv", "apply", "am", "diff", "log", "show", "status", "stash", "reset",
               "switch", "branch", "tag", "merge", "rebase", "cherry-pick", "commit", "init",
               "blame", "grep", "ls-files", "rev-parse", "describe", "shortlog", "reflog", "fsck",
               "gc", "notes", "sparse-checkout", "lfs"):
        for i, a in enumerate(sargs):
            if a in ("-o", "--output", "-F", "--file") and i + 1 < len(sargs):
                _check_path(ctx, sargs[i + 1], "write")
            elif a.startswith(("--output=", "--file=")):
                _check_path(ctx, a.split("=", 1)[1], "write")
            elif a.startswith(("-o", "-F")) and len(a) > 2 and not a.startswith("--"):
                _check_path(ctx, a[2:], "write")
            elif not a.startswith("-") and (a.startswith(("/", "~", "$", "..", "\\")) or looks_windows_path(a)):
                _check_path(ctx, a, "read")
        return
    # unknown git subcommand (possibly an alias)
    _add(ctx, L.ASK, f"Unknown git subcommand or alias '{sub}' (owner approval)")


def _git_destructive_target(ctx: _Ctx, operation: str) -> None:
    from .approval import git_root
    target = git_root(ctx.cwd or ctx.base_dir or os.getcwd())
    if ctx.base_dir and not any(is_inside(target, root) for root in ctx.policy.roots(ctx.base_dir)):
        _add(ctx, L.DENY, "Destructive Git action affects a repository outside the admitted roots")
        return
    if ctx.base_dir and operation in ("reset", "clean", "restore", "checkout"):
        hit = boundaries.check_path(target, "write", ctx.policy)
        if hit and hit[1] == "LOCK":
            raise _Lock(hit[2], hit[0])
    ctx.destructive.append({"operation": "git-" + operation, "target": target})


def _git_discards_work(sub: str, sargs: List[str]) -> Optional[str]:
    """Git commands that throw away uncommitted or unreferenced work, which cannot be undone."""
    flags = [a for a in sargs if a.startswith("-")]
    pos = [a for a in sargs if not a.startswith("-")]
    whole_tree = any(a in (".", ":/", ":(top)", "*") for a in pos)
    if sub == "reset" and "--hard" in sargs:
        return "git reset --hard discards uncommitted changes"
    if sub == "clean" and any(re.match(r"^-[a-zA-Z]*f", a) or a == "--force" for a in flags) \
            and not any(a in ("-n", "--dry-run") or re.match(r"^-[a-zA-Z]*n", a) for a in flags):
        return "git clean deletes untracked files"
    if sub == "checkout" and whole_tree and "-b" not in sargs and "-B" not in sargs:
        return "git checkout of the whole tree discards uncommitted changes"
    if sub == "restore" and whole_tree and not ("--staged" in sargs and "--worktree" not in sargs):
        return "git restore of the whole tree discards uncommitted changes"
    if sub == "stash" and pos[:1] in (["drop"], ["clear"]):
        return f"git stash {pos[0]} deletes stashed work"
    if sub == "branch" and ("-D" in sargs or ("--delete" in sargs and "--force" in sargs)):
        return "git branch -D deletes a branch that may not be merged"
    if sub == "reflog" and pos[:1] in (["expire"], ["delete"]):
        return "git reflog expire removes the safety net for lost commits"
    if sub == "gc" and any(a.startswith("--prune=now") or a == "--prune=all" for a in sargs):
        return "git gc --prune=now deletes unreferenced commits immediately"
    if sub == "update-ref" and "-d" in sargs:
        return "git update-ref -d deletes a ref"
    return None


CURL_VALUE_OPTS = {
    "-o", "--output", "-d", "--data", "--data-raw", "--data-binary", "--data-urlencode",
    "--data-ascii", "-F", "--form", "--form-string", "-H", "--header", "-T", "--upload-file",
    "-u", "--user", "-X", "--request", "-A", "--user-agent", "-e", "--referer", "-b", "--cookie",
    "-c", "--cookie-jar", "-K", "--config", "-x", "--proxy", "-m", "--max-time",
    "--connect-timeout", "-w", "--write-out", "-r", "--range", "-E", "--cert", "--key",
    "--cacert", "--capath", "-C", "--continue-at", "--retry", "--retry-delay", "-z",
    "--time-cond", "--resolve", "--connect-to", "-U", "--proxy-user", "--output-dir", "--url",
    "--json", "-D", "--dump-header", "--trace", "--trace-ascii", "--stderr", "--limit-rate",
    "-Y", "-y", "--interface", "--dns-servers", "-Q", "--quote", "--oauth2-bearer",
    "--aws-sigv4", "--variable", "--unix-socket", "--abstract-unix-socket", "--max-filesize",
}
WGET_VALUE_OPTS = {
    "-O", "--output-document", "-o", "--output-file", "-a", "--append-output", "-P",
    "--directory-prefix", "--post-file", "--post-data", "--body-file", "--body-data", "--method",
    "--header", "-U", "--user-agent", "-e", "--execute", "-i", "--input-file", "--user",
    "--password", "--http-user", "--http-password", "--load-cookies", "--save-cookies", "-t",
    "--tries", "-T", "--timeout", "-w", "--wait", "--limit-rate", "--referer", "-l", "--level",
    "-A", "--accept", "-R", "--reject", "-D", "--domains", "--exclude-domains", "--bind-address",
    "--ca-certificate", "--certificate", "--private-key", "--config",
}
PS_WEB_VALUE_OPTS = {"-uri", "-method", "-body", "-infile", "-outfile", "-headers", "-proxy",
                     "-contenttype", "-useragent", "-websession", "-sessionvariable", "-credential",
                     "-timeoutsec", "-maximumredirection", "-source", "-destination", "-form"}


def _fetch(name: str, args: List[str], ctx: _Ctx) -> None:
    ps = name in ("invoke-webrequest", "iwr", "invoke-restmethod", "irm", "start-bitstransfer") or \
        (name in ("curl", "wget") and any(a.lower() in PS_WEB_VALUE_OPTS for a in args))
    value_opts = PS_WEB_VALUE_OPTS if ps else (WGET_VALUE_OPTS if name == "wget" else CURL_VALUE_OPTS)
    urls: List[str] = []
    upload_sources: List[str] = []
    upload = False
    outputs: List[str] = []
    reads: List[str] = []
    rest = list(args)
    while rest:
        a = rest.pop(0)
        key, val = a, None
        if a.startswith("--") and "=" in a:
            key, val = a.split("=", 1)
        low = key.lower() if ps else key
        if not ps and val is None and a.startswith("-") and not a.startswith("--") and len(a) > 2:
            for k, ch in enumerate(a[1:]):
                if ("-" + ch) in value_opts:
                    key = low = "-" + ch
                    if k + 1 < len(a[1:]):
                        val = a[1 + k + 1:]
                    break
        if (low in value_opts) and val is None:
            val = rest.pop(0) if rest else ""
        if low in value_opts:
            if low in ("-o", "--output", "-O", "--output-document", "-outfile", "--output-dir", "-P",
                       "--directory-prefix", "-D", "--dump-header", "-c", "--cookie-jar", "--trace",
                       "--trace-ascii", "--stderr", "-a", "--append-output", "--save-cookies", "-destination") \
                    and not (name == "wget" and low == "-o" and False):
                outputs.append(val)
            elif low in ("-T", "--upload-file", "-infile", "--post-file", "--body-file") and not (name == "wget" and low == "-T"):
                upload = True
                upload_sources.append(val)
            elif low in ("-d", "--data", "--data-binary", "--data-raw", "--data-urlencode", "--data-ascii",
                         "--json", "--post-data", "--body-data", "-body", "-form"):
                upload = True
                if val.startswith("@") and low != "--data-raw":
                    upload_sources.append(val[1:])
            elif low in ("-F", "--form"):
                upload = True
                m = re.search(r"=[@<]([^;]+)", val)
                if m:
                    upload_sources.append(m.group(1))
            elif low in ("-K", "--config", "-i", "--input-file", "--load-cookies", "-b", "--cookie",
                         "-E", "--cert", "--key", "--cacert", "--private-key", "--certificate", "--ca-certificate"):
                if low in ("-i", "--input-file", "-K", "--config"):
                    _add(ctx, L.ASK, f"{name} reads URLs/options from a file ({val})")
                if low not in ("-b", "--cookie") or _looks_like_path_token(val):
                    reads.append(val)
            elif low in ("-x", "--proxy", "-proxy"):
                _check_url(ctx, val, allowlist=False)
            elif low in ("--resolve", "--connect-to", "--unix-socket", "--abstract-unix-socket", "-e", "--execute"):
                _add(ctx, L.ASK, f"{name} {low} can redirect traffic or run commands (owner approval)")
            elif low in ("--url", "-uri", "-source"):
                urls.append(val)
            elif low in ("-X", "--request", "--method", "-method") and val.upper() in ("POST", "PUT", "PATCH"):
                upload = True
            continue
        if a.startswith("-"):
            continue
        urls.append(a)
    for src in upload_sources:
        if src in ("-", ""):
            continue
        _check_path(ctx, src, "upload")
    for p in outputs:
        if p:
            _check_path(ctx, p, "write")
    for p in reads:
        if p:
            _check_path(ctx, p, "read")
    if not urls:
        _add(ctx, L.ASK, f"{name} without a recognizable URL (owner approval)")
        return
    for u in urls:
        _check_url(ctx, u, upload=upload)
