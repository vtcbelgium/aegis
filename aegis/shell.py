"""Aegis shell analyzer: Phase-1 threat shield + Phase-2 strict No-Shell PASS gate.

Every command passes through two deterministic phases:

1. **Threat & Hard-Boundary Classification (Phase 1):** Normalizes text, decodes
   ``$'...'`` / ``^`` escapes and ``$(...)`` substitutions, tracks inline variables
   and working-directory changes across segments, and checks hard boundaries
   (policy/state tamper, logs, backups, sentinel takeover, master secrets, system
   destruction), privilege escalation, pipes to interpreters, SSRF/exfiltration,
   live secrets/tripwires, unknown binaries (when ``unknown_binary="deny"``),
   and destructive action confirmations / blast radius.
2. **No-Shell ``PASS`` Gate (Phase 2):** ONLY ``parse_direct_command`` from
   ``aegis.direct_exec`` may return ``DecisionLevel.PASS`` (marking the verdict
   with ``direct_exec=True`` and ``direct_argv`` so Tekton executes it with
   ``shell=False``). Any command requiring shell syntax, chaining, globs,
   braces, variables, PowerShell cmdlets, scripts, or non-allowlisted tools is
   routed to ``DecisionLevel.ASK`` (or keeps any ``DENY``/``LOCK`` from Phase 1).
"""

from __future__ import annotations

import base64
import os
import re
import shlex
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from . import boundaries
from .canonicalizer import home_dir, is_inside, looks_windows_path, normalize_text, resolve_path
from .core import DecisionLevel, Verdict
from .direct_exec import parse_direct_command
from .policy import (
    DEFAULT_POLICY,
    AegisPolicy,
    classify_sensitive,
    is_catastrophic_target,
    is_exfil_sink,
)

NAME = "Tartarus"
L = DecisionLevel
MAX_DEPTH = 6

# ---------------------------------------------------------------------------
# Binary classification tables (Phase-1 threat scanning & unknown-binary policy)
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
    "nvidia-smi", "lscpu", "lspci", "lsblk", "lsusb", "ip", "ss", "hostnamectl", "timedatectl",
    "lsb_release", "sw_vers", "ipconfig", "netstat", "tasklist", "ollama",
}

READ_BINARIES = {
    "ls", "cat", "head", "tail", "less", "more", "wc", "file", "stat", "du", "tree", "diff",
    "cmp", "md5sum", "sha1sum", "sha256sum", "sha512sum", "shasum", "realpath", "readlink",
    "sort", "uniq", "cut", "paste", "join", "comm", "column", "nl", "od", "xxd", "hexdump",
    "strings", "base64", "tac", "rev", "fold", "fmt", "expand", "unexpand", "iconv", "zcat",
    "bat", "fd", "exa", "eza", "lsof", "type", "sed", "grep", "egrep", "fgrep", "rg", "ag",
    "ack", "jq", "yq", "select-string", "sls",
    "get-childitem", "gci", "dir", "get-content", "gc", "get-item", "gi", "get-itemproperty",
    "gp", "test-path", "resolve-path", "get-filehash", "get-acl", "findstr", "where", "fc", "comp",
}

WRITE_BINARIES = {
    "mkdir", "touch", "cp", "mv", "ln", "install", "truncate", "tee", "split",
    "csplit", "patch", "gzip", "gunzip", "xz", "unxz", "bzip2", "bunzip2", "zstd", "unzstd",
    "7z", "7za", "zip", "unzip", "tar", "rsync", "dd", "chmod", "chown", "chgrp", "rename",
    "set-content", "add-content", "ac", "out-file", "new-item", "ni", "md", "copy-item", "copy",
    "cpi", "move-item", "move", "mi", "rename-item", "ren", "rni", "expand-archive",
    "compress-archive", "xcopy", "robocopy", "mklink",
}

DELETE_BINARIES = {"rm", "rmdir", "unlink", "shred", "srm", "remove-item", "ri", "del", "erase", "rd"}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "ash", "busybox"}
POWERSHELLS = {"powershell", "pwsh"}
INTERPRETERS = {
    "python", "python2", "python3", "pythonw", "py", "pypy", "pypy3", "node", "nodejs", "deno",
    "bun", "perl", "ruby", "php", "lua", "luajit", "rscript", "tclsh", "julia", "ts-node", "tsx",
    "groovy", "scala", "irb", "awk", "gawk", "mawk", "nawk",
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
PS_VERBS = {
    "get", "set", "new", "remove", "copy", "move", "rename", "invoke", "start", "stop",
    "restart", "add", "out", "select", "where", "foreach", "test", "write", "clear",
    "format", "import", "export", "convertto", "convertfrom", "measure", "sort",
    "resolve", "split", "join", "expand", "compress", "initialize", "enable", "disable",
    "install", "uninstall", "update", "register", "unregister", "push", "pop", "read",
    "send", "receive", "connect", "disconnect", "suspend", "resume", "wait", "show",
}
PROJECT_TOOLS = {
    "make", "cmake", "ninja", "meson", "cargo", "rustc", "go", "gcc", "g++", "cc", "clang",
    "clang++", "javac", "java", "mvn", "gradle", "gradlew", "dotnet", "msbuild", "tsc", "vite",
    "next", "jest", "vitest", "mocha", "eslint", "prettier", "ruff", "black", "isort", "mypy",
    "pylint", "flake8", "pytest", "tox", "nox", "poetry", "pipenv", "hatch", "uv", "pdm",
    "npm", "pnpm", "yarn", "pip", "pip3", "pipx", "gem", "bundle", "composer", "swift",
    "xcodebuild", "webpack", "rollup", "esbuild", "turbo", "nx", "lerna", "playwright",
    "cypress", "storybook", "astro", "nuxt", "svelte-kit", "coverage", "pre-commit",
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
CRITICAL_ASK_BINARIES = ASK_BINARIES - {"docker", "podman", "gh", "npx", "bunx", "pnpx", "uvx"}
_WORKSPACE_DEV_BINARIES = INTERPRETERS | PROJECT_TOOLS | READ_BINARIES | WRITE_BINARIES | {"git"}
WRAPPERS = {"command", "builtin", "exec", "nohup", "time", "nice", "ionice", "stdbuf", "timeout",
            "watch", "unbuffer", "caffeinate", "call"}
CMD_BUILTINS = {"dir", "type", "copy", "move", "del", "erase", "rd", "rmdir", "md", "mkdir",
                "ren", "rename", "xcopy", "robocopy", "cls", "findstr", "where", "fc", "attrib",
                "mklink", "start", "call", "ver", "set"}
WINDOWS_SLASH_FLAG_BINARIES = CMD_BUILTINS | {
    "ipconfig", "tasklist", "systeminfo", "netstat", "taskkill", "schtasks",
    "icacls", "cacls", "takeown", "reg", "sc", "wmic", "bcdedit", "wevtutil",
    "cipher", "powercfg", "net", "netsh", "setx",
}

DANGEROUS_ENV_OVERRIDES = {
    "PATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH",
    "PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME", "PYTHONUSERBASE", "PYTHONINSPECT",
    "PYTHONBREAKPOINT", "PYTHONEXECUTABLE", "PYTHONPLATLIBDIR", "NODE_OPTIONS", "NODE_PATH",
    "NODE_EXTRA_CA_CERTS", "BASH_ENV", "ENV", "PROMPT_COMMAND", "GIT_SSH_COMMAND", "GIT_SSH",
    "GIT_EXEC_PATH", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_COUNT", "GIT_EXTERNAL_DIFF", "GIT_PAGER", "GIT_DIR", "GIT_WORK_TREE",
    "GIT_EDITOR", "GIT_ASKPASS", "GIT_TEMPLATE_DIR", "PERL5OPT", "PERL5LIB", "RUBYOPT",
    "RUBYLIB", "TAPE", "TAR_OPTIONS", "AWKPATH", "AWKLIBPATH", "LESSOPEN", "LESSCLOSE",
    "PAGER", "MANPAGER", "EDITOR", "VISUAL", "BROWSER", "SHELL", "COMSPEC", "IFS", "CDPATH",
    "GLOBIGNORE", "GCONV_PATH", "LOCPATH", "ZDOTDIR", "HOME", "USERPROFILE", "XDG_CONFIG_HOME",
}
_BENIGN_GIT_ENV_VARS = frozenset({
    "GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL", "GIT_AUTHOR_DATE",
    "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL", "GIT_COMMITTER_DATE", "GIT_TERMINAL_PROMPT",
})
_SENSITIVE_CONTROL_DIRS = frozenset({".git", ".githooks", ".husky", ".vscode", ".github", ".devcontainer", ".idea"})

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

_SUBST = "\ue000S{}\ue001"
_SUBST_RE = re.compile("\ue000S(\\d+)\ue001")
_SEMI = "\ue000SEMI\ue001"
STDIN_PATHS = {"-", "/dev/stdin", "/dev/fd/0", "/proc/self/fd/0", "/dev/tty"}
SHELL_KEYWORDS = {"if", "then", "else", "elif", "fi", "do", "done", "while", "until", "{", "}", "!", "function", "coproc"}
SKIP_SEGMENT_KEYWORDS = {"for", "select", "case", "esac", "in", ";;"}
FIND_FILTERS = {
    "-name", "-iname", "-path", "-ipath", "-regex", "-iregex", "-type", "-size", "-mtime",
    "-ctime", "-atime", "-mmin", "-cmin", "-amin", "-newer", "-empty", "-wholename", "-iwholename",
    "-perm", "-links", "-inum", "-samefile",
}


def _is_dangerous_env_var(name: str) -> bool:
    up = (name or "").strip().upper()
    if not up:
        return False
    if up in DANGEROUS_ENV_OVERRIDES or up.startswith(("LD_", "DYLD_")):
        return True
    return up.startswith("GIT_") and up not in _BENIGN_GIT_ENV_VARS


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
    variables: Dict[str, str] = field(default_factory=dict)
    force_windows: bool = False
    effects: set = field(default_factory=set)
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
    """Inspect *command* for threats and allow ``PASS`` ONLY for direct no-shell calls."""
    if not command or not command.strip():
        if _depth > 0:
            return Verdict(L.PASS, ["Empty command"], NAME)
        return Verdict(L.ASK, ["Empty command requires owner approval (no-shell PASS policy)"], NAME)

    pol = policy or DEFAULT_POLICY
    ctx = _Ctx(base_dir=base_dir, cwd=cwd or base_dir, policy=pol, depth=_depth, force_windows=windows)
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

    if ctx.findings:
        top = max(level for level, _ in ctx.findings)
        reasons = list(dict.fromkeys(r for level, r in ctx.findings if level == top))
        from .approval import bind_confirmation
        return bind_confirmation(
            Verdict(top, reasons, NAME, metadata=_meta(ctx, ctx.boundary)),
            {"command": command, "cwd": ctx.cwd, "windows": windows},
        )

    if _depth > 0:
        return Verdict(L.PASS, ["Nested command threat scan clean"], NAME, metadata=_meta(ctx))

    dc, reject_reason = parse_direct_command(
        command,
        base_dir=base_dir,
        cwd=ctx.cwd,
        policy=pol,
        windows=windows or ctx.force_windows,
    )
    if dc is not None:
        meta = {
            **_meta(ctx),
            "direct_exec": True,
            "direct_binary": dc.binary,
            "direct_argv": list(dc.argv),
            "needs_workspace": dc.needs_workspace,
        }
        return Verdict(L.PASS, [f"Direct read-only command: {dc.binary} (no shell)"], NAME, metadata=meta)

    if getattr(pol, "pass_policy", "strict") == "critical_only":
        return Verdict(L.PASS, ["Internal dev command passed Phase-1 critical threat shield"], NAME, metadata=_meta(ctx))

    return Verdict(
        L.ASK,
        [f"Requires owner approval (no-shell PASS policy): {reject_reason}"],
        NAME,
        metadata=_meta(ctx),
    )


def _meta(ctx: _Ctx, boundary: Optional[str] = None) -> dict:
    meta: dict = {"effects": sorted(ctx.effects)}
    if boundary:
        meta["boundary"] = boundary
    if ctx.impact:
        meta["impact"] = ctx.impact
    if ctx.destructive:
        meta["destructive"] = ctx.destructive
    return meta


# ---------------------------------------------------------------------------
# Phase-1 Normalization, Heredocs, Substitutions, Lexing & Hard-Boundary Scan
# ---------------------------------------------------------------------------

def _add(ctx: _Ctx, level: DecisionLevel, reason: str) -> None:
    if level >= L.LOCK:
        raise _Lock(reason)
    if level > L.PASS:
        ctx.findings.append((level, reason))


def _extract_heredocs(text: str) -> Tuple[str, List[str], List[bool]]:
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
            if m.start() > 0 and line[m.start() - 1] == "<":
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
    depth = 1
    j = open_idx + 1
    n = len(text)
    in_s = in_d = False
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
            if ((windows and c == "`") or ((not windows) and c == "\\")) and j + 1 < n:
                j += 2
                continue
            if c == '"':
                in_d = False
            j += 1
            continue
        if ((windows and c == "`") or ((not windows) and c == "\\")) and j + 1 < n:
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
        if windows and ch == "`" and i + 1 < n:
            nxt = text[i + 1]
            out.append({"$": "$", '"': "'" if in_double else '"', "n": "\n", "r": "\r", "t": "\t", "0": ""}.get(nxt, nxt))
            i += 2
            continue
        if text.startswith("$(", i) or ((text.startswith("<(", i) or text.startswith(">(", i)) and not in_double):
            inner, end_idx, _ = _scan_balanced_parens(text, i + 1, windows)
            idx = len(ctx.substitutions)
            ctx.substitutions[idx] = inner
            _analyze_nested(inner, ctx)
            out.append(_SUBST.format(idx))
            i = end_idx
            continue
        if (not windows) and ch == "`":
            j = text.find("`", i + 1)
            inner = text[i + 1 : j] if j != -1 else text[i + 1 :]
            idx = len(ctx.substitutions)
            ctx.substitutions[idx] = inner
            _analyze_nested(inner, ctx)
            out.append(_SUBST.format(idx))
            i = (j + 1) if j != -1 else n
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _lex(text: str, windows: bool) -> List[str]:
    lex = shlex.shlex(text, posix=True, punctuation_chars=";&|()<>\n")
    lex.whitespace = " \t\r"
    lex.whitespace_split = True
    lex.commenters = ""
    if windows:
        lex.escape = ""
    return list(lex)


def _split_segments(tokens: List[str]) -> List[Segment]:
    segments: List[Segment] = []
    cur = Segment()
    pending_redirect: Optional[str] = None
    for idx, tok in enumerate(tokens):
        if pending_redirect is not None:
            if pending_redirect == "<<" and tok.startswith("HEREDOC_"):
                cur.heredoc = tok
            elif pending_redirect == "<<<":
                cur.herestring = tok
            elif pending_redirect.endswith("&") and (tok.isdigit() or tok == "-"):
                pass
            else:
                cur.redirects.append((pending_redirect, tok))
            pending_redirect = None
            continue
        is_op = tok and all(c in "<>&|;()\n" for c in tok) and tok != _SEMI
        if is_op and ("<" in tok or ">" in tok):
            if cur.words and cur.words[-1].isdigit() and idx > 0:
                cur.words.pop()
            pending_redirect = tok
            continue
        if is_op:
            if cur.words or cur.redirects or cur.heredoc:
                segments.append(cur)
            cur = Segment(piped_in=tok in ("|", "|&"))
            continue
        cur.words.append(tok)
    if cur.words or cur.redirects or cur.heredoc:
        segments.append(cur)
    return segments


def _analyze_nested(command: str, ctx: _Ctx, cwd: Optional[str] = None) -> DecisionLevel:
    if _SUBST_RE.fullmatch(command.strip().strip("'\"")):
        _add(ctx, L.DENY, "Executes the output of a command substitution (dynamically generated code)")
        return L.DENY
    if ctx.depth + 1 > MAX_DEPTH:
        _add(ctx, L.ASK, "Command nesting too deep to analyze")
        return L.ASK
    v = analyze_command(
        command,
        base_dir=ctx.base_dir,
        cwd=cwd or ctx.cwd,
        policy=ctx.policy,
        _depth=ctx.depth + 1,
        windows=ctx.force_windows,
    )
    if v.level >= L.LOCK:
        raise _Lock(v.reasons[0], v.metadata.get("boundary"))
    for r in v.reasons:
        _add(ctx, v.level, r)
    if v.metadata:
        ctx.effects.update(v.metadata.get("effects") or ())
        ctx.impact.extend(v.metadata.get("impact") or ())
        ctx.destructive.extend(v.metadata.get("destructive") or ())
    return v.level


def _strip_cmd_carets(text: str) -> str:
    if "^" not in text:
        return text
    out: List[str] = []
    i, n = 0, len(text)
    in_s = in_d = False
    while i < n:
        ch = text[i]
        if ch == "'" and not in_d:
            in_s = not in_s
            out.append(ch)
            i += 1
            continue
        if ch == '"' and not in_s:
            in_d = not in_d
            out.append(ch)
            i += 1
            continue
        if ch == "^" and not in_s and not in_d and i + 1 < n:
            out.append(text[i + 1])
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _decode_ansi_c_body(inner: str) -> str:
    simple = {
        "a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f",
        "n": "\n", "r": "\r", "t": "\t", "v": "\v", "\\": "\\", "'": "'", '"': '"', "?": "?",
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
        if esc in ("x", "u", "U"):
            maxlen = {"x": 2, "u": 4, "U": 8}[esc]
            m = re.match(rf"[0-9a-fA-F]{{1,{maxlen}}}", inner[i + 2 :])
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
    if "$'" not in text:
        return text
    out: List[str] = []
    i, n = 0, len(text)
    in_s = in_d = False
    while i < n:
        ch = text[i]
        if in_s:
            if ch == "'":
                in_s = False
            out.append(ch)
            i += 1
            continue
        if in_d:
            if ch == "\\" and i + 1 < n:
                out.append(text[i : i + 2])
                i += 2
                continue
            if ch == '"':
                in_d = False
            out.append(ch)
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            out.append(text[i : i + 2])
            i += 2
            continue
        if ch == "'":
            in_s = True
            out.append(ch)
            i += 1
            continue
        if ch == '"':
            in_d = True
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
    return (
        first in CMD_BUILTINS
        or bool(ps_like and ps_like.group(1) in PS_VERBS)
        or first in POWERSHELLS
        or first == "cmd"
        or ps_var
        or first == "diskpart"
        or (first == "format" and bool(re.search(r"(?:^|\s)[A-Za-z]:(?:\s|$|\\|/)", text)))
    )


def _expand_simple_brace_token(tok: str, limit: int = 32) -> List[str]:
    """Expand at most one simple brace group ({a,b} or {a..f}) for boundary scans."""
    m = re.search(r"\{([^{}]{1,64})\}", tok)
    if not m:
        return [tok]
    inner = m.group(1)
    prefix, suffix = tok[: m.start()], tok[m.end() :]
    items: List[str] = []
    if "," in inner:
        items = inner.split(",")[:limit]
    else:
        rm = re.fullmatch(r"([A-Za-z])..([A-Za-z])|(\d+)..(\d+)", inner)
        if rm:
            if rm.group(1) and rm.group(2):
                a, b = ord(rm.group(1)), ord(rm.group(2))
                step = 1 if a <= b else -1
                if abs(b - a) < limit:
                    items = [chr(c) for c in range(a, b + step, step)]
            elif rm.group(3) and rm.group(4):
                a, b = int(rm.group(3)), int(rm.group(4))
                step = 1 if a <= b else -1
                if abs(b - a) < limit:
                    items = [str(n) for n in range(a, b + step, step)]
    if not items:
        return [tok]
    return [prefix + part + suffix for part in items]


_MUTATING_WORDS_RE = re.compile(
    r"(?:^|\s)(?:rm|rmdir|del|erase|rd|mv|move|cp|copy|tar|sed|awk|gawk|mawk|nawk|"
    r"dd|truncate|chmod|chown|touch|tee|install|unzip|7z|7za|zip|sort|uniq|xxd|iconv|"
    r"base64|less|more|tree|python|python2|python3|py|black|isort|ruff|remove-item|"
    r"set-content|add-content|out-file|new-item|copy-item|move-item)\b|\s-[a-z]*[owfOdc]\b|\s--out",
    re.IGNORECASE,
)


def _scan_protected_path_tokens(text: str, ctx: _Ctx) -> None:
    """Catch brace/flag/syntax-hidden targets of LOCK boundaries, secrets, and tripwires."""
    check_mode = "write" if (">" in text or "=" in text or bool(_MUTATING_WORDS_RE.search(text))) else "read"
    raw_pieces = re.findall(r"[^\s;&|()<>'\"`]+", text)
    candidates: List[str] = []
    for p in raw_pieces:
        expanded = _expand_simple_brace_token(p) if ("{" in p and "}" in p) else [p]
        for ep in expanded:
            candidates.append(ep)
            if any(sep in ep for sep in ("=", "{", "}", ",")):
                candidates.extend(s for s in re.split(r"[={},]", ep) if s)
    extra: List[str] = []
    for c in candidates:
        # Handle attached option/command prefixes like -oPATH, -cvfPATH, wPATH (sed write)
        if len(c) > 4 and c[0].lower() in ("w", "o", "f") and _looks_like_path_token(c[1:]):
            extra.append(c[1:])
        m_pref = re.match(r"^-[A-Za-z]{1,6}([~/.\\].*|[A-Za-z]:[/\\].*)$", c)
        if m_pref:
            extra.append(m_pref.group(1))
    candidates.extend(extra)

    seen = set()
    for cand in candidates:
        if not cand or cand in seen or len(cand) > 1024:
            continue
        seen.add(cand)
        if not _looks_like_path_token(cand) and ":" not in cand and not cand.startswith("~"):
            continue
        abs_path, _, unresolved = resolve_path(cand, base_dir=ctx.base_dir, cwd=ctx.cwd)
        if unresolved:
            continue
        _minotaur_path(ctx, abs_path, cand)
        hit = boundaries.check_path(abs_path, check_mode, ctx.policy)
        if hit and hit[1] == "LOCK":
            raise _Lock(hit[2], hit[0])
        if classify_sensitive(cand, abs_path, write_mode=(check_mode == "write")) == "critical":
            raise _Lock(f"Command accesses a credential or system store: {cand}", boundaries.MASTER_SECRET)


def _analyze(text: str, ctx: _Ctx) -> None:
    if re.search(r"([\w:.]+)\s*\(\)\s*\{[^}]*\1\s*\|\s*\1\s*&", text):
        raise _Lock("Fork bomb detected")

    from .clans.custody import CustodyClan
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
    _scan_protected_path_tokens(text, ctx)
    try:
        tokens = _lex(text, windows)
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
# Path, URL, Secret & Redirect Threat Checks
# ---------------------------------------------------------------------------

def _has_subst(word: str) -> bool:
    return bool(_SUBST_RE.search(word))


def _is_option(word: str, windows_flags: bool = False) -> bool:
    if word.startswith("-") and word != "-" and not word.startswith("--="):
        return True
    if windows_flags and re.match(r"^/[A-Za-z?][A-Za-z0-9:\-]*$", word) and len(word) <= 12:
        return True
    return False


def _looks_like_path_token(val: str) -> bool:
    if not val or "://" in val:
        return False
    return (
        val in (".", "..")
        or val.startswith(("/", "\\", "~", "./", "../", ".\\", "..\\", "$HOME", "${HOME}", "%USERPROFILE%", "$env:"))
        or looks_windows_path(val)
        or "/" in val
        or "\\" in val
    )


def _check_path(ctx: _Ctx, raw: str, mode: str = "read", recursive: bool = False) -> Optional[str]:
    if raw is None:
        return None
    word = raw
    if _has_subst(word):
        _add(ctx, L.ASK, f"Path built from a command substitution: {raw}")
        return None
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

    if mode == "delete" and not unresolved:
        ctx.destructive.append({"operation": "delete", "target": abs_path})
        globless = os.path.dirname(abs_path) or "/" if ("*" in os.path.basename(abs_path) or "?" in os.path.basename(abs_path)) else abs_path
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
        target = os.path.dirname(abs_path) if "*" in os.path.basename(abs_path) else abs_path
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
        _add(ctx, L.ASK, f"Network access to a host outside the allowlist: {host or url}")
        ctx.untrusted_download = True


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


def _is_known_command_word(name: str) -> bool:
    return (
        name in NO_PATH_BINARIES
        or name in READ_BINARIES
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
        or name in {"git", "ollama", "cmd", "env", "xargs", "cd", "pushd", "chdir", "set-location", "sl",
                    "popd", "source", ".", "eval", "systemctl", "service", "vssadmin", "btrfs", "tmutil",
                    "timeshift", "wbadmin", "reagentc", "auditctl", "journalctl", "printenv", "export",
                    "declare", "typeset", "set-mppreference", "add-mppreference", "clear-eventlog",
                    "remove-eventlog", "limit-eventlog", "clear-winevent", "stop-service", "set-service",
                    "remove-service", "suspend-service", "spsv", "remove-wbbackupset",
                    "remove-wbsystemstatebackup", "disable-computerrestore", "remove-computerrestorepoint",
                    "unregister-scheduledtask", "disable-scheduledtask", "stop-scheduledtask"}
    )


def _expand_vars(word: str, ctx: _Ctx) -> str:
    if not ctx.variables or "$" not in word:
        return word
    return re.sub(
        r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)",
        lambda m: ctx.variables.get(m.group(1) or m.group(2), m.group(0)),
        word,
    )


# ---------------------------------------------------------------------------
# Segment analysis & Phase-1 handlers
# ---------------------------------------------------------------------------

def _analyze_segment(seg: Segment, ctx: _Ctx) -> None:
    words = list(seg.words)
    for op, target in seg.redirects:
        _check_path(ctx, target, "read" if op.startswith("<") else "write")
    for w in words:
        m = SECRET_VAR_RE.search(w)
        if m and m.group(1).upper() not in {"SSH_AUTH_SOCK", "GPG_AGENT_INFO"}:
            _add(ctx, L.ASK, f"Reads a secret-like environment variable: {m.group(1)}")
            break
    if not words:
        return

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

    while words:
        m_ps_inline = re.match(r"^\$(?:env:)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$", words[0], re.I)
        m_ps_spaced = (
            re.match(r"^\$(?:env:)?([A-Za-z_][A-Za-z0-9_]*)$", words[0], re.I)
            if len(words) >= 2 and words[1] == "="
            else None
        )
        if m_ps_inline or m_ps_spaced:
            if m_ps_inline:
                name, value = m_ps_inline.group(1), m_ps_inline.group(2)
                words.pop(0)
                if value:
                    words.insert(0, value)
            else:
                name = m_ps_spaced.group(1)
                words = words[2:]
            if boundaries.GUARD_ENV_RE.match(name):
                raise _Lock(f"Hard boundary {boundaries.POLICY_TAMPER}: sets {name}", boundaries.POLICY_TAMPER)
            if _is_dangerous_env_var(name):
                _add(ctx, L.ASK, f"Overrides a security-relevant environment variable: {name}")
            if not words:
                ctx.variables[name] = ""
                return
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
            ctx.variables[name] = _expand_vars(value, ctx)
            continue
        break

    if not words:
        return
    words = [_expand_vars(w, ctx) for w in words]

    if ctx.force_windows and words and "^" in words[0]:
        if _is_known_command_word(_canon_binary(_strip_cmd_carets(words[0]))):
            words = [_strip_cmd_carets(w) for w in words]

    m_brace = re.fullmatch(r"\{([^{}]*,[^{}]*)\}", words[0])
    if m_brace:
        words = m_brace.group(1).split(",") + words[1:]

    _dispatch(words, seg, ctx)


def _dispatch(words: List[str], seg: Segment, ctx: _Ctx) -> None:
    raw_bin = words[0]
    args = words[1:]
    if _has_subst(raw_bin) or raw_bin.startswith("$"):
        _add(ctx, L.ASK, f"Binary name comes from a variable or substitution: {raw_bin}")
        return
    name = _canon_binary(raw_bin)

    if "/" in raw_bin or "\\" in raw_bin or raw_bin.startswith("~"):
        if not raw_bin.replace("\\", "/").lower().startswith(SYSTEM_BIN_DIRS):
            resolved_bin = _check_path(ctx, raw_bin, "exec")
            if resolved_bin is not None:
                ctx.exec_after_download = True
                if (
                    getattr(ctx.policy, "pass_policy", "strict") == "critical_only"
                    and ctx.policy.project_exec == "allow"
                    and (
                        name in _WORKSPACE_DEV_BINARIES
                        or name in getattr(ctx.policy, "extra_allowed_binaries", ())
                    )
                ):
                    pass
                else:
                    _add(ctx, L.ASK, f"Executes workspace/local binary {raw_bin} (owner approval)")
                    return
            else:
                return

    if name in PRIVILEGE:
        _add(ctx, L.DENY, f"Privilege escalation via {name}")
        return
    hit = boundaries.check_command(name, args, ctx.policy)
    if hit:
        raise _Lock(hit[1], hit[0])
    if name in SYSTEM_LOCK or (name in ("init", "telinit") and args and args[0] in ("0", "6")):
        raise _Lock(f"Destructive system command blocked: {name}", boundaries.SYSTEM_DESTRUCTION)
    if name == "systemctl":
        verb = next((a.lower() for a in args if not a.startswith("-")), "")
        if verb in {"poweroff", "reboot", "halt", "kexec", "suspend", "hibernate"}:
            raise _Lock("System shutdown/reboot command blocked", boundaries.SYSTEM_DESTRUCTION)
        if verb not in {"status", "is-active", "is-enabled", "is-failed", "show", "list-units", "list-unit-files", ""}:
            _add(ctx, L.ASK, "systemctl changes services (owner approval)")
        return
    if name == "vssadmin" and any(a.lower() == "delete" for a in args):
        raise _Lock("Shadow copy deletion blocked", boundaries.BACKUP_DESTRUCTION)
    if name in DENY_BINARIES:
        _add(ctx, L.DENY, f"Account/kernel administration command blocked: {name}")
        return

    if name in WRAPPERS:
        return _wrapper(name, args, seg, ctx)
    if name == "env":
        return _env_wrapper(args, seg, ctx)
    if name in ("printenv", "export", "declare", "typeset", "set"):
        return _env_builtin(name, args, ctx)
    if name == "xargs":
        return _xargs(args, seg, ctx)
    if name in ("cd", "pushd", "chdir", "set-location", "sl"):
        return _cd(args, ctx)
    if name == "busybox" and args and not args[0].startswith("-"):
        return _dispatch(args, Segment(words=args, redirects=seg.redirects, piped_in=seg.piped_in), ctx)
    if name in ("source", "."):
        if args and args[0].startswith("{"):
            body = " ".join(args).strip()[1:]
            if body.endswith("}"):
                body = body[:-1]
            if body.strip():
                _analyze_nested(body, ctx)
        elif args:
            _check_path(ctx, args[0], "exec")
        return
    if name == "eval":
        joined = " ".join(args)
        if _SUBST_RE.search(joined):
            _add(ctx, L.DENY, "eval of a command substitution executes generated code")
            return
        _analyze_nested(joined, ctx)
        return
    if name in SHELLS:
        return _shell(name, args, seg, ctx)
    if name in POWERSHELLS:
        return _powershell(args, seg, ctx)
    if name == "cmd":
        return _cmd(args, seg, ctx)
    if name in INTERPRETERS:
        return _interpreter(name, args, seg, ctx)
    if name in ("iex", "invoke-expression") and seg.piped_in:
        _add(ctx, L.DENY, "Untrusted pipeline executed directly by Invoke-Expression")
        return
    if name in DELETE_BINARIES:
        return _delete(name, args, ctx)
    if name == "find":
        return _find(args, ctx)
    if name == "git":
        return _git(args, ctx)
    if name in NETWORK_FETCHERS:
        return _fetch(name, args, ctx)
    if name in REMOTE_TOOLS:
        ctx.effects.update(("fetch", "egress"))
        _add(ctx, L.ASK, f"Remote access / transfer tool requires owner approval: {name}")
        for a in args:
            if not _is_option(a) and ":" not in a and "@" not in a and _looks_like_path_token(a):
                _check_path(ctx, a, "upload")
        return

    if name in READ_BINARIES | WRITE_BINARIES | NO_PATH_BINARIES | PROJECT_TOOLS | ASK_BINARIES | CMD_BUILTINS \
            or name in getattr(ctx.policy, "extra_allowed_binaries", ()):
        if getattr(ctx.policy, "pass_policy", "strict") == "critical_only":
            if name in CRITICAL_ASK_BINARIES and name not in getattr(ctx.policy, "extra_allowed_binaries", ()):
                _add(ctx, L.ASK, f"Critical system/admin command '{name}' requires owner approval")
                _scan_arg_threats(name, args, ctx)
                return
            if name == "gh":
                low_pos = [a.lower() for a in args if not a.startswith("-")]
                if (
                    (len(low_pos) >= 2 and (low_pos[0], low_pos[1]) in {("repo", "delete"), ("release", "delete"), ("ssh-key", "add"), ("gpg-key", "add"), ("auth", "token"), ("variable", "set")})
                    or (low_pos and low_pos[0] == "secret")
                ):
                    _add(ctx, L.ASK, f"Critical GitHub CLI action requires owner approval: gh {' '.join(args[:2])}")
            elif name in ("docker", "podman"):
                for a in args:
                    al = a.lower()
                    if al == "--privileged" or al in {"--pid=host", "--net=host", "--network=host"} or re.match(r"^(?:-v|--volume)(?:=|$)(?:/(?::|$)|[A-Za-z]:[/\\]?(?::|$))", a):
                        _add(ctx, L.ASK, f"Privileged container option requires owner approval: {name}")
                        break
                    if (a.startswith("-v=") or a.startswith("--volume=")) and (a.split("=", 1)[1].startswith("/:") or a.split("=", 1)[1] == "/"):
                        _add(ctx, L.ASK, f"Privileged container option requires owner approval: {name}")
                        break
        _scan_arg_threats(name, args, ctx)
        return

    level = L.DENY if ctx.policy.unknown_binary == "deny" else L.ASK
    _add(ctx, level, f"Unknown command '{name}' is not on the Aegis allowlist")


def _wrapper(name: str, args: List[str], seg: Segment, ctx: _Ctx) -> None:
    rest = list(args)
    if name == "timeout":
        while rest and rest[0].startswith("-"):
            opt = rest.pop(0)
            if opt in ("-s", "--signal", "-k", "--kill-after") and rest:
                rest.pop(0)
        if rest:
            rest.pop(0)
    elif name in ("nice", "ionice", "stdbuf", "watch", "time"):
        while rest and rest[0].startswith("-"):
            opt = rest.pop(0)
            if opt in ("-n", "-c", "-i", "-o", "-e", "-d", "--interval") and rest and not rest[0].startswith("-"):
                rest.pop(0)
        if name == "watch" and rest:
            _analyze_nested(" ".join(rest), ctx)
            return
    elif name in ("command", "builtin", "exec"):
        while rest and rest[0].startswith("-"):
            rest.pop(0)
    if rest:
        _dispatch(rest, Segment(words=rest, piped_in=seg.piped_in), ctx)


def _env_wrapper(args: List[str], seg: Segment, ctx: _Ctx) -> None:
    idx = 0
    while idx < len(args):
        a = args[idx]
        if a == "--":
            idx += 1
            break
        if a.startswith("--"):
            opt, eq, val = a.partition("=")
            if "--split-string".startswith(opt) and len(opt) >= 3:
                _analyze_nested(((val + " ") if eq else "") + " ".join(args[idx + 1 :]), ctx)
                return
            if "--chdir".startswith(opt) and len(opt) >= 3:
                target = val if eq else (args[idx + 1] if idx + 1 < len(args) else "")
                idx += 1 if eq else 2
                if target:
                    res = _check_path(ctx, target, "cd")
                    if res is not None:
                        ctx.cwd = res
                continue
            idx += 1 if (eq or "--unset" not in opt) else 2
            continue
        if a.startswith("-") and len(a) > 1:
            if "S" in a[1:]:
                pos = a[1:].index("S")
                tail = (a[2 + pos :] + " " + " ".join(args[idx + 1 :])).strip()
                _analyze_nested(tail, ctx)
                return
            if "C" in a[1:] or "u" in a[1:]:
                idx += 1 if (len(a) > 2 or idx + 1 >= len(args)) else 2
                continue
            idx += 1
            continue
        break
    rest = list(args[idx:])
    while rest:
        tok = rest[0]
        if tok.startswith("{") and tok.endswith("}") and "=" in tok:
            for item in tok[1:-1].split(","):
                if "=" in item:
                    var, _, val = item.strip().partition("=")
                    if boundaries.GUARD_ENV_RE.match(var):
                        raise _Lock(f"Hard boundary {boundaries.POLICY_TAMPER}: sets {var}", boundaries.POLICY_TAMPER)
                    if _is_dangerous_env_var(var):
                        _add(ctx, L.ASK, f"Overrides a security-relevant environment variable: {var}")
            rest.pop(0)
            continue
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tok):
            var, _, val = rest.pop(0).partition("=")
            if boundaries.GUARD_ENV_RE.match(var):
                raise _Lock(f"Hard boundary {boundaries.POLICY_TAMPER}: sets {var}", boundaries.POLICY_TAMPER)
            if _is_dangerous_env_var(var):
                _add(ctx, L.ASK, f"Overrides a security-relevant environment variable: {var}")
            if var.upper() == "TAPE" and val:
                _check_path(ctx, val, "write")
            continue
        break
    if not rest:
        _add(ctx, L.ASK, "Unrestricted environment variable dump (env)")
        return
    _dispatch(rest, Segment(words=rest, piped_in=seg.piped_in), ctx)


def _env_builtin(name: str, args: List[str], ctx: _Ctx) -> None:
    if name == "printenv" and not [a for a in args if not a.startswith("-")]:
        _add(ctx, L.ASK, "Environment variable dump (printenv)")
        return
    for a in args:
        tok = a.strip().strip('"').strip()
        if not tok or tok.startswith("-") or (name == "set" and tok.startswith("/")) or "=" not in tok:
            continue
        var, _, val = tok.partition("=")
        var = var.strip()
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", var):
            continue
        if boundaries.GUARD_ENV_RE.match(var):
            raise _Lock(f"Hard boundary {boundaries.POLICY_TAMPER}: sets {var}", boundaries.POLICY_TAMPER)
        if _is_dangerous_env_var(var):
            _add(ctx, L.ASK, f"Overrides a security-relevant environment variable: {var}")
        ctx.variables[var] = _expand_vars(val, ctx)


def _xargs(args: List[str], seg: Segment, ctx: _Ctx) -> None:
    rest = list(args)
    takes = {"-I", "-i", "-n", "-L", "-P", "-s", "-d", "-E", "-a", "--max-args", "--max-procs", "--delimiter", "--arg-file", "--replace"}
    while rest and rest[0].startswith("-"):
        opt = rest.pop(0)
        if opt.startswith("--arg-file="):
            _check_path(ctx, opt.split("=", 1)[1], "read")
        elif opt in takes and rest:
            val = rest.pop(0)
            if opt in ("-a", "--arg-file"):
                _check_path(ctx, val, "read")
    if rest:
        _dispatch(rest, Segment(words=rest, piped_in=seg.piped_in), ctx)


def _cd(args: List[str], ctx: _Ctx) -> None:
    targets = [a for a in args if not _is_option(a)]
    target = targets[0] if targets else "~"
    if target == "-" or any(c in target for c in "*?[]{}"):
        _add(ctx, L.ASK, f"cd target requires owner approval: {target}")
        return
    resolved = _check_path(ctx, target, "cd")
    if resolved is not None:
        ctx.cwd = resolved


def _shell(name: str, args: List[str], seg: Segment, ctx: _Ctx) -> None:
    rest = list(args)
    script_text = script_file = None
    while rest:
        a = rest.pop(0)
        if a == "-c" or (a.startswith("-") and not a.startswith("--") and "c" in a[1:]):
            if rest:
                script_text = rest.pop(0)
            break
        if a.startswith(("-", "+")):
            if a in ("-o", "+o", "-O", "+O") and rest:
                rest.pop(0)
            continue
        script_file = a
        break
    if script_text is not None:
        prev = ctx.force_windows
        ctx.force_windows = False
        try:
            _analyze_nested(script_text, ctx)
        finally:
            ctx.force_windows = prev
        return
    if script_file is not None and script_file not in STDIN_PATHS:
        if _check_path(ctx, script_file, "exec") is not None:
            ctx.exec_after_download = True
        return
    if seg.piped_in:
        _add(ctx, L.DENY, f"Untrusted pipeline executed directly by the {name} shell")
        return
    if seg.heredoc is not None or seg.herestring is not None:
        prev = ctx.force_windows
        ctx.force_windows = False
        try:
            _analyze_nested(seg.heredoc if seg.heredoc is not None else seg.herestring, ctx)
        finally:
            ctx.force_windows = prev
        return
    _add(ctx, L.ASK, f"Spawning bare interactive shell session requires owner approval: {name}")


def _cmd(args: List[str], seg: Segment, ctx: _Ctx) -> None:
    for i, a in enumerate(args):
        low = _strip_cmd_carets(a).lower()
        if low in ("/c", "/k", "/r"):
            inner = _strip_cmd_carets(" ".join(args[i + 1 :]))
            if inner:
                prev = ctx.force_windows
                ctx.force_windows = True
                try:
                    _analyze_nested(inner, ctx)
                finally:
                    ctx.force_windows = prev
            return
    if seg.piped_in:
        _add(ctx, L.DENY, "Untrusted pipeline executed directly by cmd.exe")
        return
    _add(ctx, L.ASK, "Spawning bare cmd.exe shell requires owner approval")


def _powershell(args: List[str], seg: Segment, ctx: _Ctx) -> None:
    rest = list(args)
    takes_value = {
        "-executionpolicy", "-ep", "-ex", "-windowstyle", "-w", "-inputformat", "-outputformat",
        "-of", "-if", "-configurationname", "-workingdirectory", "-wd", "-version", "-psconsolefile", "-settingsfile",
    }
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
        if low in ("-encodedcommand", "-enc", "-e", "-ec") or (len(low) >= 3 and low.startswith("-en") and "-encodedcommand".startswith(low)):
            _add(ctx, L.ASK, "PowerShell -EncodedCommand hides the command from inspection")
            if not rest or not rest[0].strip():
                _add(ctx, L.DENY, "PowerShell -EncodedCommand missing payload")
                return
            try:
                raw_bytes = base64.b64decode(rest.pop(0).strip(), validate=True)
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
            prev = ctx.force_windows
            ctx.force_windows = True
            try:
                _analyze_nested(decoded, ctx)
            finally:
                ctx.force_windows = prev
            return
        if low in ("-file", "-f"):
            if rest and _check_path(ctx, rest[0], "exec") is not None:
                ctx.exec_after_download = True
            return
        if low in takes_value:
            if rest:
                rest.pop(0)
            continue
        if low.startswith("-"):
            continue
        if a.lower().endswith(".ps1"):
            _check_path(ctx, a, "exec")
            return
        _analyze_nested(" ".join([a] + rest), ctx)
        return
    if seg.piped_in:
        _add(ctx, L.DENY, "Untrusted pipeline executed directly by PowerShell")
        return
    _add(ctx, L.ASK, "Spawning bare PowerShell session requires owner approval")


_INLINE_FS_ROOT_RE = re.compile(
    r"^/(?:etc|root|home|Users|var|usr|opt|tmp|proc|sys|boot|mnt|media|srv|run|private|Library|System|Volumes)(?:/|$)"
)


def _looks_inline_fs_path(lit: str) -> bool:
    if not lit or "://" in lit or "\n" in lit or len(lit) > 1024:
        return False
    return (
        lit in ("~", "..", ".env")
        or lit.startswith(("~/", "~\\", "../", "..\\"))
        or looks_windows_path(lit)
        or bool(_INLINE_FS_ROOT_RE.match(lit))
        or classify_sensitive(lit, lit) in ("critical", "secret", "startup")
    )


def _inline_code(ctx: _Ctx, interpreter: str, code: str) -> None:
    for lit in re.findall(r"'([^'\n]{2,})'|\"([^\"\n]{2,})\"", code):
        s = lit[0] or lit[1]
        first = _canon_binary((s.strip().split() or [""])[0])
        if first in DELETE_BINARIES | SYSTEM_LOCK | NETWORK_FETCHERS | SHELLS | POWERSHELLS | {"find", "dd", "chmod", "git", "tar", "rsync"}:
            _analyze_nested(s, ctx)
            continue
        sc = s.strip()
        if re.match(r"^https?://\S+$", sc, re.I):
            _check_url(ctx, sc)
        elif _looks_inline_fs_path(sc):
            _check_path(ctx, sc, "read")
    if REVERSE_SHELL_RE.search(code) and re.search(r"subprocess|pty\.spawn|os\.dup2|/bin/(?:ba)?sh|child_process|exec\(", code):
        _add(ctx, L.DENY, f"Reverse-shell pattern in inline {interpreter} code (socket + process)")
        return
    if DESTRUCTIVE_CODE_RE.search(code):
        _add(ctx, L.DENY, f"Destructive operation in inline {interpreter} code")
        return
    if not (
        getattr(ctx.policy, "pass_policy", "strict") == "critical_only"
        and getattr(ctx.policy, "inline_exec", "ask") == "allow"
    ):
        _add(ctx, L.ASK, f"Inline interpreter code execution ({interpreter}) requires human owner approval")


def _interpreter(name: str, args: List[str], seg: Segment, ctx: _Ctx) -> None:
    if name in ("awk", "gawk", "mawk", "nawk"):
        for a in args:
            for call in re.findall(r"system\s*\(\s*['\"]([^'\"]+)['\"]", a):
                _analyze_nested(call, ctx)
        _scan_arg_threats(name, args, ctx)
        return
    rest = list(args)
    py = name.startswith("py")
    inline_flags = INLINE_FLAGS_BY.get(name, {"-e"})
    value_opts = VALUE_OPTS_BY.get("python3" if py else ("node" if name in ("nodejs", "ts-node", "tsx") else name), set())
    if name in ("deno", "bun") and rest:
        if rest[0] == "eval" and len(rest) >= 2:
            _inline_code(ctx, name, " ".join(rest[1:]))
            return
    if seg.piped_in:
        if not rest or any(a in STDIN_PATHS for a in rest) or any("sys.stdin" in a for a in rest):
            _add(ctx, L.DENY, f"Untrusted pipeline executed directly by {name}")
            return
    if py and rest[:1] == ["-m"] and len(rest) >= 2 and rest[1] == "aegis":
        hit = boundaries.check_command("python3", rest, ctx.policy)
        if hit:
            raise _Lock(hit[1], hit[0])
    while rest:
        a = rest.pop(0)
        if a in inline_flags:
            if rest:
                _inline_code(ctx, name, rest.pop(0))
            return
        if a in value_opts and rest:
            val = rest.pop(0)
            if _looks_like_path_token(val):
                _check_path(ctx, val, "read")
            continue
        if a.startswith("-"):
            continue
        if a in STDIN_PATHS and seg.piped_in:
            _add(ctx, L.DENY, f"Untrusted pipeline executed directly by {name}")
            return
        if a not in STDIN_PATHS:
            if name == "python3" and args and "-m" in args and rest and a != "-":
                _check_path(ctx, a, "read")
            elif py and "-m" in args:
                _check_path(ctx, a, "read")
            else:
                _check_path(ctx, a, "exec")
        _scan_arg_threats(name, [x for x in rest if x != "-"], ctx)
        break
    if seg.heredoc is not None or seg.herestring is not None:
        _inline_code(ctx, name, seg.heredoc if seg.heredoc is not None else seg.herestring)
    elif seg.piped_in and not args:
        _add(ctx, L.DENY, f"Untrusted pipeline executed directly by {name}")


def _scan_arg_threats(name: str, args: List[str], ctx: _Ctx) -> None:
    """Inspect path-like/URL/sensitive tokens in known non-direct commands for Phase-1 threats."""
    mutating = name in WRITE_BINARIES
    write_opts = {"-o", "--output", "-T", "--temporary-directory", "-O", "--log-file", "--LOG-FILE",
                  "--output-file", "-out", "-destination", "-literalpath", "-path"}
    for i, a in enumerate(args):
        if a == "--" or not a:
            continue
        if name == "dd" and a.startswith(("if=", "of=")):
            key, val = a.split("=", 1)
            _check_path(ctx, val, "write" if key == "of" else "read")
            continue
        if name in ("chmod", "chown", "chgrp") and not _is_option(a) and re.fullmatch(r"[0-7]{3,4}|[ugoa]*[+-=][rwxXst]+", a):
            continue
        if name in ("chmod", "chown", "chgrp") and _looks_like_path_token(a):
            abs_p, confined, unres = resolve_path(a, base_dir=ctx.base_dir, cwd=ctx.cwd)
            if not unres and (is_catastrophic_target(abs_p, home_dir()) or abs_p.rstrip("/\\") in ("", "/", "/etc", "/var", "/usr")):
                raise _Lock(f"Catastrophic permission/ownership change on {a}", boundaries.SYSTEM_DESTRUCTION)
            _check_path(ctx, a, "write")
            continue
        if _is_option(a, windows_flags=(name in WINDOWS_SLASH_FLAG_BINARIES)):
            # Extract values from --flag=value, -Param:value, or attached write options like -oPATH / -fPATH
            val = None
            mode = "read"
            if "=" in a:
                opt, val = a.split("=", 1)
                if opt.lower() in write_opts or opt.lower().startswith("--out"):
                    mode = "write"
            elif ":" in a and a.startswith("-") and not a.startswith("--"):
                opt, val = a.split(":", 1)
                if opt.lower() in write_opts:
                    mode = "write"
            elif (mutating or name in {"sort", "iconv", "tree", "base64", "less", "more"}) and a.startswith("-") and not a.startswith("--") and len(a) > 2:
                # Attached archive/output option e.g. tar -cvfPATH, 7z -oDIR, unzip -dDIR, sort -o/etc/passwd
                for idx_c, ch in enumerate(a[1:]):
                    if ch in ("o", "O", "d", "f") and idx_c + 1 < len(a[1:]):
                        val = a[2 + idx_c :]
                        mode = "write"
                        break
            if val and (_looks_like_path_token(val) or classify_sensitive(val, val) is not None):
                _check_path(ctx, val, mode)
            continue

        # Positional arg
        if name == "sed" and re.match(r"^/[^/\r\n]+/[dpql=!](?:\s*;|)", a):
            continue
        prev_opt = args[i - 1].lower() if i > 0 else ""
        mode = "write" if (mutating or prev_opt in write_opts) else "read"
        if name in ("mv", "move", "move-item", "mi") and i == 0:
            mode = "move"
        elif name in ("cp", "mv", "ln", "copy", "move", "copy-item", "cpi", "move-item", "mi", "xcopy", "robocopy") and i + 1 == len(args):
            mode = "write"
        if _looks_like_path_token(a) or mutating or classify_sensitive(a, a, write_mode=(mode != "read")) is not None:
            _check_path(ctx, a, mode)
        else:
            abs_p, _, unres = resolve_path(a, base_dir=ctx.base_dir, cwd=ctx.cwd)
            if not unres:
                _minotaur_path(ctx, abs_p, a)
                hit = boundaries.check_path(abs_p, mode, ctx.policy)
                if hit:
                    if hit[1] == "LOCK":
                        raise _Lock(hit[2], hit[0])
                    _add(ctx, L.DENY if hit[1] == "DENY" else L.ASK, hit[2])


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
        _check_path(ctx, r, "delete" if deleting else "read", recursive=deleting and not selective)
    for cmd in exec_cmds:
        if not cmd:
            continue
        replaced = [roots[0] if w == "{}" else w for w in cmd]
        if _canon_binary(cmd[0]) in DELETE_BINARIES:
            for r in roots:
                _check_path(ctx, r, "delete", recursive=not selective)
        else:
            _dispatch(replaced, Segment(words=replaced), ctx)


def _is_recursive_flag(word: str) -> bool:
    low = word.lower()
    if low in ("--recursive", "/s", "-recurse"):
        return True
    if low.startswith("--") or not low.startswith("-") or len(low) < 2:
        return False
    if "-recurse".startswith(low):
        return True
    if "-force".startswith(low):
        return False
    return bool(re.match(r"^-[a-zA-Z]{1,4}$", word)) and ("r" in word[1:] or "R" in word[1:])


def _delete(name: str, args: List[str], ctx: _Ctx) -> None:
    windows = name in ("del", "erase", "rd", "rmdir") and any(a.startswith("/") and len(a) <= 3 for a in args)
    recursive = name == "rd" and any(a.lower() == "/s" for a in args)
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
            elif low == "--no-preserve-root":
                recursive = True
            continue
        targets.append(a)
    for t in targets:
        _check_path(ctx, t, "delete", recursive=recursive)


def _git_discards_work(sub: str, sargs: List[str]) -> Optional[str]:
    flags = [a for a in sargs if a.startswith("-")]
    pos = [a for a in sargs if not a.startswith("-")]
    whole = any(a in (".", ":/", ":(top)", "*") for a in pos)
    if sub == "reset" and "--hard" in sargs:
        return "git reset --hard discards uncommitted changes"
    if sub == "clean" and any(re.match(r"^-[a-zA-Z]*f", a) or a == "--force" for a in flags) \
            and not any(a in ("-n", "--dry-run") or re.match(r"^-[a-zA-Z]*n", a) for a in flags):
        return "git clean deletes untracked files"
    if sub == "checkout" and whole and "-b" not in sargs and "-B" not in sargs:
        return "git checkout of the whole tree discards uncommitted changes"
    if sub == "restore" and whole and not ("--staged" in sargs and "--worktree" not in sargs):
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


def _git(args: List[str], ctx: _Ctx) -> None:
    rest = list(args)
    while rest and rest[0].startswith("-"):
        flag = rest.pop(0)
        if flag == "-C" and rest:
            res = _check_path(ctx, rest.pop(0), "cd")
            if res is not None:
                ctx.cwd = res
        elif flag == "-c" and rest:
            kv = rest.pop(0)
            key = kv.split("=", 1)[0].strip().lower()
            if not (key.startswith("core.") and key in {"core.autocrlf", "core.eol", "core.filemode", "core.ignorecase", "core.quotepath"}):
                _add(ctx, L.ASK, f"git -c sets configuration '{kv}' (owner approval)")
        elif flag == "--git-dir" and rest:
            _check_path(ctx, rest.pop(0), "write")
        elif flag.startswith("--git-dir="):
            _check_path(ctx, flag.split("=", 1)[1], "write")
    if not rest:
        return
    sub = rest[0]
    sargs = rest[1:]
    if sub == "config" and any(a.startswith(("--global", "--system", "alias.", "core.hooks", "core.fsmonitor", "core.ssh", "credential.")) for a in sargs):
        _add(ctx, L.ASK, "git config sets executable/alias or global setting (owner approval)")
        return
    if sub == "push":
        ctx.effects.add("egress")
        if "--mirror" in sargs:
            _add(ctx, L.ASK, "git push --mirror overwrites all refs on remote (owner approval)")
        if any(f in sargs for f in ("-f", "--force", "--force-with-lease", "--delete")) or any(
            not a.startswith("-") and (a.startswith((":", "+")) or "://" in a) for a in sargs
        ):
            from .approval import git_root
            target = git_root(ctx.cwd or ctx.base_dir or os.getcwd())
            if "--delete" in sargs or any(a in ("-f", "--force", "--force-with-lease") for a in sargs) or any(
                not a.startswith("-") and a.startswith((":", "+")) for a in sargs
            ):
                ctx.destructive.append({"operation": "git-push-force", "target": target})
            for a in sargs:
                if "://" in a:
                    _check_url(ctx, a, upload=True, allowlist=False)
            _add(ctx, L.ASK, "git push requires owner approval")
        return
    if sub == "remote" and sargs and sargs[0] in ("add", "set-url", "rename"):
        for a in sargs[1:]:
            if "://" in a:
                _check_url(ctx, a, allowlist=False)
        _add(ctx, L.ASK, f"git remote {sargs[0]} changes remote destination (owner approval)")
        return
    if sub in ("clone", "fetch", "pull", "ls-remote", "submodule"):
        ctx.effects.add("fetch")
        for a in [x for x in sargs if not x.startswith("-") and x not in ("add", "update", "init")]:
            if "://" in a:
                _check_url(ctx, a)
            elif sub == "clone" and _looks_like_path_token(a):
                _check_path(ctx, a, "write")
        return
    lost = _git_discards_work(sub, sargs)
    if lost:
        from .approval import git_root
        target = git_root(ctx.cwd or ctx.base_dir or os.getcwd())
        if ctx.base_dir and not any(is_inside(target, r) for r in ctx.policy.roots(ctx.base_dir)):
            _add(ctx, L.DENY, "Destructive Git action affects a repository outside the admitted roots")
            return
        if ctx.base_dir and sub in ("reset", "clean", "restore", "checkout"):
            hit = boundaries.check_path(target, "write", ctx.policy)
            if hit and hit[1] == "LOCK":
                raise _Lock(hit[2], hit[0])
        ctx.destructive.append({"operation": "git-" + sub, "target": target})
        _add(ctx, L.ASK, f"{lost} (owner approval)")
    for i, a in enumerate(sargs):
        if a in ("-o", "--output", "-F", "--file") and i + 1 < len(sargs):
            _check_path(ctx, sargs[i + 1], "write")
        elif a.startswith(("--output=", "--file=")):
            _check_path(ctx, a.split("=", 1)[1], "write")
        elif not a.startswith("-") and _looks_like_path_token(a):
            _check_path(ctx, a, "read")


CURL_VALUE_OPTS = {
    "-o", "--output", "-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "--data-ascii",
    "-F", "--form", "--form-string", "-H", "--header", "-T", "--upload-file", "-u", "--user",
    "-X", "--request", "-A", "--user-agent", "-e", "--referer", "-b", "--cookie", "-c", "--cookie-jar",
    "-K", "--config", "-x", "--proxy", "-m", "--max-time", "--connect-timeout", "-w", "--write-out",
    "-E", "--cert", "--key", "--cacert", "-i", "--output-dir", "--url", "--json", "-D", "--dump-header",
}
WGET_VALUE_OPTS = {
    "-O", "--output-document", "-o", "--output-file", "-a", "--append-output", "-P", "--directory-prefix",
    "--post-file", "--post-data", "--body-file", "--body-data", "--method", "--header", "-e", "--execute",
    "-i", "--input-file", "--config",
}
PS_WEB_VALUE_OPTS = {"-uri", "-method", "-body", "-infile", "-outfile", "-headers", "-proxy", "-source", "-destination", "-form"}


def _fetch(name: str, args: List[str], ctx: _Ctx) -> None:
    ps = name in ("invoke-webrequest", "iwr", "invoke-restmethod", "irm", "start-bitstransfer")
    value_opts = PS_WEB_VALUE_OPTS if ps else (WGET_VALUE_OPTS if name == "wget" else CURL_VALUE_OPTS)
    urls: List[str] = []
    upload_sources: List[str] = []
    outputs: List[str] = []
    reads: List[str] = []
    upload = False
    rest = list(args)
    while rest:
        a = rest.pop(0)
        key, val = (a.split("=", 1) if a.startswith("--") and "=" in a else (a, None))
        low = key.lower() if ps else key
        if (low in value_opts) and val is None:
            val = rest.pop(0) if rest else ""
        if low in value_opts:
            if low in ("-o", "--output", "-O", "--output-document", "-outfile", "--output-dir", "-P", "--directory-prefix", "-D", "--dump-header", "-c", "--cookie-jar", "-destination"):
                outputs.append(val)
            elif low in ("-T", "--upload-file", "-infile", "--post-file", "--body-file") and not (name == "wget" and low == "-T"):
                upload = True
                upload_sources.append(val)
            elif low in ("-d", "--data", "--data-binary", "--data-raw", "--json", "--post-data", "--body-data", "-body", "-form"):
                upload = True
                if val.startswith("@") and low != "--data-raw":
                    upload_sources.append(val[1:])
            elif low in ("-F", "--form"):
                upload = True
                m = re.search(r"=[@<]([^;]+)", val)
                if m:
                    upload_sources.append(m.group(1))
            elif low in ("-K", "--config", "-i", "--input-file", "-b", "--cookie"):
                if low in ("-i", "--input-file", "-K", "--config"):
                    _add(ctx, L.ASK, f"{name} reads URLs/options from a file ({val})")
                if low not in ("-b", "--cookie") or _looks_like_path_token(val):
                    reads.append(val)
            elif low in ("-x", "--proxy", "-proxy"):
                _check_url(ctx, val, allowlist=False)
            elif low in ("--url", "-uri", "-source"):
                urls.append(val)
            elif low in ("-X", "--request", "--method", "-method") and val.upper() in ("POST", "PUT", "PATCH"):
                upload = True
            continue
        if not a.startswith("-"):
            urls.append(a)
    for src in upload_sources:
        if src not in ("-", ""):
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
