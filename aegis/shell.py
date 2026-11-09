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

import os
import re
import shlex
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
    is_catastrophic_target,
    is_exfil_sink,
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
    "get-process", "gps", "get-command", "gcm", "get-help", "help", "measure-object", "measure",
    "select-object", "select", "sort-object", "where-object", "foreach-object",
    "format-table", "ft", "format-list", "fl", "out-string", "out-null", "convertto-json",
    "convertfrom-json", "split-path", "join-path", "get-host", "cls", "ver", "systeminfo",
}

READ_BINARIES = {
    "ls", "cat", "head", "tail", "less", "more", "wc", "file", "stat", "du", "tree", "diff",
    "cmp", "md5sum", "sha1sum", "sha256sum", "sha512sum", "shasum", "realpath", "readlink",
    "sort", "uniq", "cut", "paste", "join", "comm", "column", "nl", "od", "xxd", "hexdump",
    "strings", "base64", "tac", "rev", "fold", "fmt", "expand", "unexpand", "iconv", "zcat",
    "bat", "fd", "exa", "eza", "lsof", "type",
    # PowerShell / cmd read-only
    "get-childitem", "gci", "dir", "get-content", "gc", "get-item", "gi", "test-path",
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
                   "py_compile", "compileall", "timeit", "cprofile", "profile", "ensurepip",
                   "build", "mypy", "black", "ruff", "flake8", "pylint", "isort", "coverage",
                   "tox", "nox", "pydoc", "site", "sysconfig", "platform", "this", "pyflakes"}

DANGEROUS_ENV_OVERRIDES = {"PATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES",
                           "DYLD_LIBRARY_PATH", "PYTHONPATH", "PYTHONSTARTUP", "NODE_OPTIONS",
                           "BASH_ENV", "ENV", "PROMPT_COMMAND", "GIT_SSH_COMMAND", "GIT_SSH",
                           "GIT_EXEC_PATH", "GIT_CONFIG_GLOBAL", "PERL5OPT", "RUBYOPT"}
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
    return Verdict(top, reasons, NAME, metadata=_meta(ctx, ctx.boundary))


def _meta(ctx: "_Ctx", boundary: Optional[str] = None) -> dict:
    meta: dict = {"effects": sorted(ctx.effects)}
    if boundary:
        meta["boundary"] = boundary
    if ctx.impact:
        meta["impact"] = ctx.impact
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


def _extract_substitutions(text: str, ctx: _Ctx) -> str:
    """Replace $(...), `...`, <(...), >(...) outside single quotes with placeholders.

    Each inner command is analyzed recursively right away.
    """
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
        if in_single:
            out.append(ch)
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            out.append(text[i:i + 2])
            i += 2
            continue
        opener = None
        if text.startswith("$((", i):
            # arithmetic expansion: no commands inside
            depth, j = 0, i + 1
            while j < n:
                if text[j] == "(":
                    depth += 1
                elif text[j] == ")":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            out.append("0")
            i = j + 1
            continue
        if text.startswith("$(", i) or ((text.startswith("<(", i) or text.startswith(">(", i)) and not in_double):
            opener = i + 2
        if opener is not None:
            depth, j = 1, opener
            while j < n and depth:
                if text[j] == "(":
                    depth += 1
                elif text[j] == ")":
                    depth -= 1
                j += 1
            inner = text[opener:j - 1] if depth == 0 else text[opener:]
            out.append(_register_subst(inner, ctx))
            i = j
            continue
        if ch == "`":
            j = text.find("`", i + 1)
            inner = text[i + 1:j] if j != -1 else text[i + 1:]
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
    # $IFS / ${IFS} word splitting evasion: rm${IFS}-rf${IFS}~
    text = re.sub(r"\$\{IFS\}|\$IFS\b", " ", text)
    text, heredocs, quoted = _extract_heredocs(text)
    for body, q in zip(heredocs, quoted):
        if not q and ("$(" in body or "`" in body):
            _extract_substitutions(body, ctx)
    text = re.sub(r"\\;|(?<![\w'\"])';'(?![\w'\"])|(?<![\w'\"])\";\"(?![\w'\"])", f" {_SEMI} ", text)
    text = _extract_substitutions(text, ctx)

    windows = ctx.force_windows or bool(re.search(r"(?:^|[\s'\"=])[A-Za-z]:\\", text))
    first = (text.strip().split() or [""])[0].strip("'\"").lower()
    if first.endswith(".exe"):
        first = first[:-4]
    ps_like = re.match(r"^([a-z]+)-[a-z]+$", first)
    if first in CMD_BUILTINS or (ps_like and ps_like.group(1) in PS_VERBS) or first in POWERSHELLS or first == "cmd":
        windows = True
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


def _check_path(ctx: _Ctx, raw: str, mode: str = "read", recursive: bool = False) -> Optional[str]:
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
    sensitivity = classify_sensitive(word, abs_path)
    if sensitivity == "critical":
        raise _Lock(f"Command accesses a credential or system store: {raw}", boundaries.MASTER_SECRET)
    if sensitivity == "startup" and mode != "read":
        _add(ctx, L.DENY, f"Command writes a startup/persistence file: {raw}")
        return None

    if mode == "delete" and not unresolved:
        globless = abs_path
        if "*" in os.path.basename(abs_path) or "?" in os.path.basename(abs_path):
            globless = os.path.dirname(abs_path) or "/"
        if is_catastrophic_target(globless, home_dir()):
            if recursive or globless != abs_path or abs_path.rstrip("/\\") in ("", "/"):
                raise _Lock(f"Catastrophic recursive deletion of root/system path: rm {raw}", boundaries.SYSTEM_DESTRUCTION)
            _add(ctx, L.DENY, f"Deleting a system/home location: {raw}")
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
            base = os.path.realpath(root) if not looks_windows_path(root) else root.replace("\\", "/")
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
    v = CustodyClan.inspect_url(url)
    if v.level >= L.LOCK:
        raise _Lock(v.reasons[0])
    if not v.passed:
        loopback_only = all("loopback" in r.lower() for r in v.reasons)
        _add(ctx, L.ASK if loopback_only else v.level,
             ("Local service access (owner approval): " if loopback_only else "") + "; ".join(v.reasons))
        return
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    scheme = (parsed.scheme or "").lower()
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

    # Leading VAR=value assignments (a segment of only assignments sets shell variables)
    assignments: List[Tuple[str, str]] = []
    while words and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", words[0]):
        name, _, value = words.pop(0).partition("=")
        if boundaries.GUARD_ENV_RE.match(name):
            raise _Lock(f"Hard boundary {boundaries.POLICY_TAMPER}: sets {name}", boundaries.POLICY_TAMPER)
        if name.upper() in DANGEROUS_ENV_OVERRIDES:
            _add(ctx, L.ASK, f"Overrides a security-relevant environment variable: {name}")
        assignments.append((name, value))
    if not words:
        for name, value in assignments:
            ctx.variables[name] = _expand_vars(value, ctx)
        return
    words = [_expand_vars(w, ctx) for w in words]

    # Brace expansion in the command word: {rm,-rf,~} -> rm -rf ~
    m_brace = re.fullmatch(r"\{([^{}]*,[^{}]*)\}", words[0])
    if m_brace:
        words = m_brace.group(1).split(",") + words[1:]

    _dispatch(words, seg, ctx)


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
        for i, a in enumerate(args):
            if a in ("-S", "--split-string") and i + 1 < len(args):
                _analyze_nested(" ".join(args[i + 1:]), ctx)
                return
            if a.startswith("--split-string="):
                _analyze_nested(a.split("=", 1)[1] + " " + " ".join(args[i + 1:]), ctx)
                return
        rest = [a for a in args if not a.startswith("-")]
        while rest and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", rest[0]):
            var = rest[0].split("=", 1)[0]
            if var.upper() in DANGEROUS_ENV_OVERRIDES:
                _add(ctx, L.ASK, f"Overrides a security-relevant environment variable: {var}")
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
        return _paths(ctx, args, "read", windows=name in CMD_BUILTINS)
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
    if name == "rsync":
        return _rsync(args, ctx)
    if name in ("zip",) and any(a in ("-TT", "--unzip-command") or a.startswith("--unzip-command=") for a in args):
        _add(ctx, L.ASK, "zip -TT runs an arbitrary test command (owner approval)")
        return
    if name in ("cp", "mv", "ln", "install", "copy", "move", "copy-item", "cpi", "move-item", "mi", "xcopy"):
        return _copy_like(name, args, ctx)
    if name in ("chown", "chgrp"):
        return _chown(args, ctx)
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
    if name in ASK_BINARIES:
        if name == "docker" and args and args[0] in {"ps", "images", "version", "info", "logs"}:
            return
        if name == "gh" and len(args) >= 2 and (args[0], args[1]) in {
            ("pr", "list"), ("pr", "view"), ("pr", "status"), ("pr", "checks"), ("pr", "diff"),
            ("issue", "list"), ("issue", "view"), ("repo", "view"), ("run", "list"),
            ("run", "view"), ("auth", "status")}:
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


def _paths(ctx: _Ctx, args: List[str], mode: str, windows: bool = False) -> None:
    end_of_opts = False
    for a in args:
        if a == "--":
            end_of_opts = True
            continue
        if not end_of_opts and _is_option(a, windows):
            if "=" in a and a.startswith("--"):
                val = a.split("=", 1)[1]
                if val and (any(c in val for c in "/\\~$") or val.startswith(".")):
                    _check_path(ctx, val, mode)
            continue
        if "://" in a:
            _check_url(ctx, a, allowlist=False)
            continue
        _check_path(ctx, a, mode)


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
    # export / declare / typeset
    if not plain or any(a in ("-p", "-x") for a in args) and not plain:
        _add(ctx, L.ASK, f"Environment variable dump ({name})")
        return
    for a in plain:
        var, eq, value = a.partition("=")
        if var.upper() in DANGEROUS_ENV_OVERRIDES and eq:
            _add(ctx, L.ASK, f"Overrides a security-relevant environment variable: {var}")
        if eq:
            ctx.variables[var] = _expand_vars(value, ctx)


def _xargs(args: List[str], seg: Segment, ctx: _Ctx) -> None:
    rest = list(args)
    takes_value = {"-I", "-i", "-n", "-L", "-P", "-s", "-d", "-E", "-a", "--max-args", "--max-procs",
                   "--delimiter", "--arg-file", "--replace"}
    while rest and rest[0].startswith("-"):
        opt = rest.pop(0)
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


def _cd(args: List[str], ctx: _Ctx) -> None:
    targets = [a for a in args if not _is_option(a)]
    target = targets[0] if targets else "~"
    if target == "-":
        _add(ctx, L.ASK, "cd - changes to an unknown previous directory")
        return
    resolved = _check_path(ctx, target, "cd")
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
        _analyze_nested(script_text, ctx)
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
        _analyze_nested(seg.heredoc if seg.heredoc is not None else seg.herestring, ctx)
        return
    _add(ctx, L.ASK, f"Spawning bare interactive shell session requires owner approval: {name}")


def _cmd(args: List[str], seg: Segment, ctx: _Ctx) -> None:
    for i, a in enumerate(args):
        if a.lower() in ("/c", "/k", "/r"):
            inner = " ".join(args[i + 1:])
            if a.lower() == "/k":
                _add(ctx, L.ASK, "cmd /k keeps an interactive shell open")
            if inner:
                _analyze_nested(inner, ctx)
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
        if low in ("-encodedcommand", "-enc", "-e", "-ec"):
            _add(ctx, L.ASK, "PowerShell -EncodedCommand hides the command from inspection")
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


def _inline_code(ctx: _Ctx, interpreter: str, code: str) -> None:
    """Inline code (-c/-e/heredoc): find embedded shell commands, else ask the owner."""
    for lit in re.findall(r"'([^'\n]{3,})'|\"([^\"\n]{3,})\"", code):
        s = lit[0] or lit[1]
        first = _canon_binary((s.strip().split() or [""])[0])
        if first in DELETE_BINARIES | SYSTEM_LOCK | NETWORK_FETCHERS | SHELLS | POWERSHELLS | {"find", "dd", "chmod", "mv", "cp", "git", "tar", "rsync"}:
            _analyze_nested(s, ctx)
    if REVERSE_SHELL_RE.search(code) and re.search(r"subprocess|pty\.spawn|os\.dup2|/bin/(?:ba)?sh|child_process|exec\(", code):
        _add(ctx, L.DENY, f"Reverse-shell pattern in inline {interpreter} code (socket + process)")
        return
    if DESTRUCTIVE_CODE_RE.search(code):
        _add(ctx, L.DENY, f"Destructive operation in inline {interpreter} code")
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
    while rest:
        a = rest.pop(0)
        if a in ("-V", "--version", "-h", "--help", "-v") and not rest:
            return
        if a in inline_flags or (a.startswith("-c") and py and len(a) > 2 and not a.startswith("--")):
            code = rest[0] if rest else (a[2:] if len(a) > 2 else "")
            return _inline_code(ctx, name, code)
        if py and a == "-m":
            mod = rest.pop(0) if rest else ""
            return _python_module(mod, rest, ctx)
        if a == "-":
            break
        if a in value_opts:
            if rest:
                val = rest.pop(0)
                if a in ("-r", "--require", "--import", "--env-file", "-I") and ("/" in val or val.startswith(".")):
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
        _paths(ctx, [x for x in rest if "/" in x or x.startswith((".", "~", "$"))], "read")
        return
    if seg.heredoc is not None or seg.herestring is not None:
        return _inline_code(ctx, name, seg.heredoc if seg.heredoc is not None else seg.herestring)
    if seg.piped_in:
        _add(ctx, L.DENY, f"Untrusted pipeline execution directly into interpreter ({name})")
        return
    _add(ctx, L.ASK, f"Interactive {name} session requires owner approval")


def _python_module(mod: str, rest: List[str], ctx: _Ctx) -> None:
    mod_l = mod.lower()
    if mod_l in ("pip", "pip3"):
        return _pip(rest, ctx)
    if mod_l in ("http.server", "smtpd", "ftplib", "telnetlib"):
        _add(ctx, L.ASK, f"python -m {mod} opens a network service (owner approval)")
        return
    if mod_l in SAFE_PY_MODULES:
        _paths(ctx, [x for x in rest if not x.startswith("-") and ("/" in x or x.startswith((".", "~", "$")))], "read")
        if mod_l in ("pytest", "unittest", "tox", "nox", "doctest", "coverage"):
            _project_exec(ctx, f"python -m {mod}")
        return
    _project_exec(ctx, f"python -m {mod}")


def _pip(args: List[str], ctx: _Ctx) -> None:
    rest = list(args)
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
                _check_path(ctx, val, "read")
        elif "://" in a:
            _check_url(ctx, a.split("+", 1)[-1] if a.startswith(("git+", "hg+", "svn+")) else a)
        elif not a.startswith("-") and ("/" in a or a.startswith((".", "~"))):
            _check_path(ctx, a, "read")


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
        elif not _is_option(a) and ("/" in a or "\\" in a or a.startswith(("~", "$", ".."))):
            _check_path(ctx, a, "read")
        elif a.startswith("--") and "=" in a:
            val = a.split("=", 1)[1]
            if "://" in val:
                _check_url(ctx, val)
            elif any(c in val for c in "/\\~") or val.startswith("$"):
                _check_path(ctx, val, "read")
    _project_exec(ctx, f"{name} {' '.join(args[:2])}".strip())


def _pattern_tool(name: str, args: List[str], ctx: _Ctx) -> None:
    rest = list(args)
    pattern_given = any(a in ("-e", "--regexp", "-f", "--file", "-Pattern", "-pattern") for a in rest)
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
        if _is_option(a):
            continue
        if first_positional and not pattern_given:
            first_positional = False
            continue
        if name in ("jq", "yq") and a.startswith("."):
            continue
        _check_path(ctx, a, "read")


def _sed(args: List[str], ctx: _Ctx) -> None:
    in_place = any(a == "-i" or a.startswith("-i") or a.startswith("--in-place") for a in args)
    scripts: List[str] = []
    files: List[str] = []
    rest = list(args)
    explicit = any(a in ("-e", "--expression", "-f", "--file") for a in rest)
    while rest:
        a = rest.pop(0)
        if a in ("-e", "--expression") and rest:
            scripts.append(rest.pop(0))
        elif a in ("-f", "--file") and rest:
            _check_path(ctx, rest.pop(0), "read")
        elif _is_option(a):
            continue
        elif not explicit and not scripts:
            scripts.append(a)
        else:
            files.append(a)
    for s in scripts:
        if re.search(r"(?:^|[;\n{}])\s*[0-9$,/]*\s*[eWw](?:\s|$)", s) or re.search(r"s(.)(?:(?!\1).)*\1(?:(?!\1).)*\1[gpIiMm0-9]*[ew]", s):
            _add(ctx, L.ASK, "sed script executes commands or writes files (owner approval)")
    for f in files:
        _check_path(ctx, f, "write" if in_place else "read")


def _awk(args: List[str], ctx: _Ctx) -> None:
    rest = list(args)
    program = None
    files: List[str] = []
    while rest:
        a = rest.pop(0)
        if a in ("-f", "--file") and rest:
            _check_path(ctx, rest.pop(0), "read")
            program = ""
        elif a in ("-v", "-F", "--assign", "--field-separator") and rest:
            rest.pop(0)
        elif _is_option(a):
            continue
        elif program is None:
            program = a
        else:
            files.append(a)
    if program and re.search(r"system\s*\(|\|\s*getline|getline\s*<|print[f]?\b[^;}]*[>|]", program):
        _inline_code(ctx, "awk", program)
    for f in files:
        if "=" in f and not ("/" in f.split("=", 1)[0]):
            continue
        _check_path(ctx, f, "read")


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
        if low.startswith("--target-directory="):
            dest = a.split("=", 1)[1]
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
    for src in pos:
        _check_path(ctx, src, "move" if moving else "read")
    if dest is not None:
        _check_path(ctx, dest, "write")


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
    rest = list(args)
    for a in rest:
        if a.startswith(("--to-command", "--checkpoint-action", "--use-compress-program", "--rsh-command", "--info-script", "--new-volume-script")) or a in ("-I", "-F"):
            _add(ctx, L.ASK, f"tar option executes a program: {a}")
            return
    skip = False
    for i, a in enumerate(rest):
        if skip:
            skip = False
            _check_path(ctx, a, "write" if rest[i - 1] in ("-C", "--directory") else "read")
            continue
        if a in ("-C", "--directory", "-f", "--file", "-T", "--files-from", "-X", "--exclude-from"):
            skip = True
            continue
        if a.startswith("--directory=") or a.startswith("--file="):
            _check_path(ctx, a.split("=", 1)[1], "write")
            continue
        if _is_option(a) or (i == 0 and re.match(r"^[cxtrufzjJvpPkO]+$", a)):
            continue
        if "://" in a or re.match(r"^[\w.-]+@[\w.-]+:", a):
            _add(ctx, L.ASK, f"tar to a remote archive: {a}")
            continue
        _check_path(ctx, a, "read")


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
    rest = list(args)
    while rest and rest[0].startswith("-"):
        opt = rest.pop(0)
        if opt in ("-C",) and rest:
            _check_path(ctx, rest.pop(0), "cd")
        elif opt.startswith(("--git-dir", "--work-tree")):
            val = opt.split("=", 1)[1] if "=" in opt else (rest.pop(0) if rest else "")
            _check_path(ctx, val, "write")
        elif opt in ("-c", "--config-env") or opt.startswith("--exec-path"):
            _add(ctx, L.ASK, "git -c / --exec-path can run arbitrary programs (owner approval)")
            if opt in ("-c", "--config-env") and rest:
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
            elif sub == "clone" and ("/" in a or a.startswith((".", "~"))):
                _check_path(ctx, a, "write")
        return
    lost = _git_discards_work(sub, sargs)
    if lost:
        _add(ctx, L.ASK, f"{lost} (owner approval)")
    if sub in ("archive", "bundle", "format-patch", "worktree", "clean", "checkout", "restore",
               "add", "rm", "mv", "apply", "am", "diff", "log", "show", "status", "stash", "reset",
               "switch", "branch", "tag", "merge", "rebase", "cherry-pick", "commit", "init",
               "blame", "grep", "ls-files", "rev-parse", "describe", "shortlog", "reflog", "fsck",
               "gc", "notes", "sparse-checkout", "lfs"):
        for i, a in enumerate(sargs):
            if a in ("-o", "--output", "-F", "--file") and i + 1 < len(sargs):
                _check_path(ctx, sargs[i + 1], "write")
            elif a.startswith("--output="):
                _check_path(ctx, a.split("=", 1)[1], "write")
            elif not a.startswith("-") and (a.startswith(("/", "~", "$", "..", "\\")) or looks_windows_path(a)):
                _check_path(ctx, a, "read")
        return
    # unknown git subcommand (possibly an alias)
    _add(ctx, L.ASK, f"Unknown git subcommand or alias '{sub}' (owner approval)")


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
        if not ps and val is None and re.match(r"^-[A-Za-z]{2,}$", a) and ("-" + a[-1]) in value_opts:
            key = low = "-" + a[-1]
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
                if low not in ("-b", "--cookie") or ("/" in val or val.startswith(".")):
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
