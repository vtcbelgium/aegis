"""Strict no-shell direct-execution parser and trusted executable resolver.

A command may return ``PASS`` (and execute via ``shell=False`` without spawning
``bash``, ``powershell``, or ``cmd.exe``) **only** when:

1. It contains a single literal invocation with zero shell metacharacters,
   expansions, escapes, globs, braces, redirects, pipes, or chaining.
2. The bare command name maps to an explicitly allowlisted read-only or
   diagnostic invocation with strictly validated options and paths.
3. Every executable path is resolved strictly from trusted system ``PATH``
   directories (never CWD, never workspace roots, never temporary directories,
   and never ``.bat`` / ``.cmd`` / script shims on Windows).
"""

from __future__ import annotations

import os
import re
import sys
import tempfile
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from . import boundaries
from .canonicalizer import is_inside, looks_windows_path, resolve_path
from .policy import DEFAULT_POLICY, AegisPolicy, classify_sensitive, has_glob

_MAX_COMMAND_LEN = 4096
_BARE_BINARY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_UNQUOTED_FORBIDDEN = set(";&|><()`${}*?[]~#^!'\"")
_DOUBLE_QUOTED_FORBIDDEN = set("`$\\!%*?[]{}~")
_SENSITIVE_CONTROL_DIRS = frozenset({".git", ".githooks", ".husky", ".vscode", ".github", ".devcontainer", ".idea"})
_REJECTED_WIN_EXTS = (".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".com", ".sh")

_SAFE_DATE_FMT_RE = re.compile(r"^\+[A-Za-z0-9%:_./ -]{1,64}$")
_SAFE_QUERY_VAL_RE = re.compile(r"^[A-Za-z0-9_,.-]{1,128}$")
_SAFE_BARE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SAFE_COUNT_RE = re.compile(r"^[0-9]{1,6}$")
_SAFE_GIT_REV_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,80}(?:/[A-Za-z0-9_.-]{1,80})?(?:[~^][0-9]{0,4})?"
    r"(?:\.\.\.?[A-Za-z0-9][A-Za-z0-9_.-]{0,80}(?:/[A-Za-z0-9_.-]{1,80})?(?:[~^][0-9]{0,4})?)?$"
)
_SAFE_RG_TYPE_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
_SHORT_NUM_FLAG_RE = re.compile(r"^-([0-9]{1,6})$")
_SECRET_ARG_LOOKALIKE_RE = re.compile(
    r"(?:sk_live_|ghp_|gho_|github_pat_|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|-----BEGIN )",
)


@dataclass(frozen=True)
class DirectCommand:
    """Validated direct-exec invocation safe to launch with ``shell=False``."""

    binary: str
    argv: Tuple[str, ...]
    path_args: Tuple[str, ...]
    needs_workspace: bool


def _is_under_any(path: str, roots: Sequence[str]) -> bool:
    real = os.path.realpath(path)
    for root in roots:
        if not root:
            continue
        r_real = os.path.realpath(root)
        if os.name == "nt":
            a = real.rstrip("\\/").lower()
            b = r_real.rstrip("\\/").lower()
            if a == b or a.startswith(b + "\\") or a.startswith(b + "/"):
                return True
        else:
            try:
                if os.path.commonpath([r_real, real]) == r_real:
                    return True
            except ValueError:
                continue
    return False


def resolve_trusted_executable(
    binary: str,
    *,
    workspace_roots: Sequence[str] = (),
    cwd: Optional[str] = None,
) -> Optional[str]:
    """Resolve *binary* strictly from non-workspace, non-temp system ``PATH`` dirs."""
    if not isinstance(binary, str) or not binary:
        return None
    if "\x00" in binary or "/" in binary or "\\" in binary or binary.startswith("."):
        return None
    low = binary.lower()
    if any(low.endswith(ext) for ext in _REJECTED_WIN_EXTS):
        return None
    if sys.platform == "win32" and low.endswith(".exe"):
        binary = binary[:-4]
    if not _BARE_BINARY_RE.fullmatch(binary):
        return None

    forbidden_roots: List[str] = []
    if cwd:
        forbidden_roots.append(cwd)
    forbidden_roots.extend(r for r in workspace_roots if r)
    try:
        tmp_dir = tempfile.gettempdir()
        if tmp_dir:
            forbidden_roots.append(tmp_dir)
    except Exception:
        pass

    raw_path = os.environ.get("PATH", "")
    for entry in raw_path.split(os.pathsep):
        cleaned = entry.strip().strip('"')
        if not cleaned or cleaned in (".", "..") or not os.path.isabs(cleaned):
            continue
        if _is_under_any(cleaned, forbidden_roots):
            continue
        if sys.platform == "win32":
            cand = os.path.join(cleaned, f"{binary}.exe")
            if not os.path.isfile(cand):
                continue
        else:
            cand = os.path.join(cleaned, binary)
            if not (os.path.isfile(cand) and os.access(cand, os.X_OK)):
                continue
        try:
            real = os.path.realpath(cand)
        except OSError:
            continue
        if not os.path.isfile(real):
            continue
        if _is_under_any(real, forbidden_roots):
            continue
        return real
    return None


def _tokenize_literal_argv(
    command: str,
    *,
    windows: bool,
) -> Tuple[Optional[List[Tuple[str, bool]]], Optional[str]]:
    """Strictly parse one literal command line without shell expansion or chaining."""
    if not isinstance(command, str) or not command.strip():
        return None, "empty command"
    if len(command) > _MAX_COMMAND_LEN:
        return None, f"command exceeds {_MAX_COMMAND_LEN} characters"
    for ch in command:
        code = ord(ch)
        if (code < 0x20 and ch != "\t") or code == 0x7F:
            return None, "command contains control or newline characters"

    tokens: List[Tuple[str, bool]] = []
    i = 0
    n = len(command)
    while i < n:
        while i < n and command[i] in " \t":
            i += 1
        if i >= n:
            break
        ch = command[i]
        if ch in ("'", '"'):
            q = ch
            i += 1
            start = i
            while i < n and command[i] != q:
                c = command[i]
                if q == '"' and c in _DOUBLE_QUOTED_FORBIDDEN:
                    return None, f"double-quoted token contains shell/expansion character {c!r}"
                if q == "'" and c == "\x00":
                    return None, "NUL byte in token"
                i += 1
            if i >= n:
                return None, "unclosed quote"
            val = command[start:i]
            i += 1
            if i < n and command[i] not in " \t":
                return None, "adjacent/mixed quoting is not allowed for direct execution"
            tokens.append((val, True))
        else:
            start = i
            while i < n and command[i] not in " \t":
                c = command[i]
                if c in _UNQUOTED_FORBIDDEN:
                    return None, f"shell metacharacter {c!r} requires shell execution"
                if c == "\\" and not windows:
                    return None, "backslash escape requires shell execution"
                if c == "%" and (windows or sys.platform == "win32"):
                    return None, "'%' expansion requires shell execution"
                i += 1
            val = command[start:i]
            if val.startswith("\\\\") or val.startswith("//"):
                return None, "UNC/network share path not allowed for direct execution"
            if windows and ":" in val and re.match(r"^[A-Za-z]+:$", val):
                return None, "PowerShell/drive provider syntax requires shell execution"
            tokens.append((val, False))

    if not tokens:
        return None, "empty command"
    return tokens, None


def _is_sensitive_control_component(raw: str) -> bool:
    parts = [p.rstrip(". ").lower() for p in raw.replace("\\", "/").split("/") if p]
    return any(p in _SENSITIVE_CONTROL_DIRS for p in parts)


def _has_windows_ads(raw: str) -> bool:
    clean = raw.replace("\\", "/")
    if re.match(r"^[A-Za-z]:(?:$|/)", clean):
        rest = clean[2:]
        return ":" in rest
    return ":" in clean


def _validate_read_path(
    raw: str,
    *,
    base_dir: Optional[str],
    cwd: Optional[str],
    policy: AegisPolicy,
) -> Optional[str]:
    """Return error string if *raw* is unsafe/disallowed for direct read-only inspection."""
    if not raw or "\x00" in raw:
        return "empty or NUL path"
    if has_glob(raw) or "{" in raw or "}" in raw:
        return f"glob or brace wildcard in path '{raw}'"
    if "$" in raw or "%" in raw or raw.startswith("~"):
        return f"shell variable or tilde in path '{raw}'"
    if raw.startswith(("\\\\", "//")):
        return f"UNC path rejected '{raw}'"
    if _has_windows_ads(raw):
        return f"colon/ADS syntax rejected '{raw}'"
    if _is_sensitive_control_component(raw):
        return f"sensitive control directory path '{raw}'"

    abs_path, confined, unresolved = resolve_path(raw, base_dir=base_dir, cwd=cwd or base_dir)
    if unresolved:
        return f"unresolved variable in path '{raw}'"
    if boundaries.check_path(abs_path, "read", policy) is not None:
        return f"hard boundary blocks read of '{raw}'"
    if classify_sensitive(raw, abs_path, write_mode=False) is not None:
        return f"sensitive file '{raw}' requires owner review"
    trip = getattr(policy, "tripwires", None)
    if trip is not None and trip.match_path(abs_path):
        return f"Minotaur tripwire path '{raw}'"

    if base_dir is not None:
        roots = policy.roots(base_dir)
        in_roots = confined is True or any(is_inside(abs_path, r) for r in roots)
        if not in_roots:
            return f"path escapes admitted workspace '{raw}'"
        if os.path.lexists(abs_path):
            try:
                real = os.path.realpath(abs_path)
            except OSError:
                return f"cannot resolve path '{raw}'"
            real_roots = [os.path.realpath(r) for r in roots if r]
            if not any(is_inside(real, rr) for rr in real_roots):
                return f"symlink resolves outside workspace '{raw}'"
            if classify_sensitive(real, write_mode=False) is not None:
                return f"symlink target is sensitive '{raw}'"
            if boundaries.check_path(real, "read", policy) is not None:
                return f"symlink target hits hard boundary '{raw}'"
    return None


def _short_bundle_ok(arg: str, allowed_chars: str) -> bool:
    return bool(arg.startswith("-") and not arg.startswith("--") and len(arg) >= 2 and all(c in allowed_chars for c in arg[1:]))


def _looks_like_path_arg(tok: str) -> bool:
    return (
        tok in (".", "..")
        or tok.startswith(("/", "\\", "./", "../", ".\\", "..\\", "~"))
        or "/" in tok
        or "\\" in tok
        or looks_windows_path(tok)
    )


# ---------------------------------------------------------------------------
# Per-binary direct-exec validators
# ---------------------------------------------------------------------------

def _validate_zero_arg(binary: str, args: List[str], **_kw) -> Tuple[Optional[DirectCommand], Optional[str]]:
    if args:
        return None, f"'{binary}' takes no arguments for direct PASS"
    return DirectCommand(binary, (binary,), (), False), None


def _validate_exact_flag_set(allowed: frozenset[str], *, bundle: str = "") -> Callable[..., Tuple[Optional[DirectCommand], Optional[str]]]:
    def _fn(binary: str, args: List[str], **_kw) -> Tuple[Optional[DirectCommand], Optional[str]]:
        for a in args:
            if a in allowed:
                continue
            if bundle and _short_bundle_ok(a, bundle):
                continue
            return None, f"option '{a}' not allowed for direct '{binary}'"
        return DirectCommand(binary, (binary, *args), (), False), None
    return _fn


def _validate_date(binary: str, args: List[str], **_kw) -> Tuple[Optional[DirectCommand], Optional[str]]:
    if not args:
        return DirectCommand(binary, (binary,), (), False), None
    if len(args) == 1 and (args[0] in ("-u", "--utc") or _SAFE_DATE_FMT_RE.fullmatch(args[0])):
        return DirectCommand(binary, (binary, args[0]), (), False), None
    if len(args) == 2 and args[0] in ("-u", "--utc") and _SAFE_DATE_FMT_RE.fullmatch(args[1]):
        return DirectCommand(binary, (binary, args[0], args[1]), (), False), None
    return None, "date flags/format not in safe direct allowlist"


def _validate_df(
    binary: str, args: List[str], *, base_dir: Optional[str], cwd: Optional[str], policy: AegisPolicy
) -> Tuple[Optional[DirectCommand], Optional[str]]:
    flags = {"-h", "-H", "-T", "-P", "-k", "-m", "-i"}
    paths: List[str] = []
    for a in args:
        if a in flags:
            continue
        if a.startswith("-"):
            return None, f"df flag '{a}' not in direct allowlist"
        if len(paths) >= 1:
            return None, "df allows at most one path for direct PASS"
        err = _validate_read_path(a, base_dir=base_dir, cwd=cwd, policy=policy)
        if err:
            return None, err
        paths.append(a)
    return DirectCommand(binary, (binary, *args), tuple(paths), bool(paths)), None


def _validate_nvidia_smi(binary: str, args: List[str], **_kw) -> Tuple[Optional[DirectCommand], Optional[str]]:
    if not args or args in (["-L"], ["--list-gpus"]):
        return DirectCommand(binary, (binary, *args), (), False), None
    for a in args:
        if a.startswith("--query-gpu=") and _SAFE_QUERY_VAL_RE.fullmatch(a.split("=", 1)[1]):
            continue
        if a.startswith("--format=") and _SAFE_QUERY_VAL_RE.fullmatch(a.split("=", 1)[1]):
            continue
        return None, f"nvidia-smi argument '{a}' requires owner approval"
    return DirectCommand(binary, (binary, *args), (), False), None


def _validate_ipconfig(binary: str, args: List[str], **_kw) -> Tuple[Optional[DirectCommand], Optional[str]]:
    if not args or (len(args) == 1 and args[0].lower() in ("/all", "/displaydns")):
        return DirectCommand(binary, (binary, *args), (), False), None
    return None, "ipconfig flag requires owner approval"


def _validate_tasklist(binary: str, args: List[str], **_kw) -> Tuple[Optional[DirectCommand], Optional[str]]:
    low = [a.lower() for a in args]
    if not low or low == ["/nh"] or (len(low) == 2 and low[0] == "/fo" and low[1] in ("csv", "table", "list")):
        return DirectCommand(binary, (binary, *args), (), False), None
    return None, "tasklist flags require owner approval"


def _validate_ip(binary: str, args: List[str], **_kw) -> Tuple[Optional[DirectCommand], Optional[str]]:
    rest = list(args)
    while rest and rest[0] in ("-4", "-6", "-br", "-j", "--json"):
        rest.pop(0)
    if len(rest) == 1 and rest[0] in ("a", "addr", "address", "r", "route", "l", "link"):
        return DirectCommand(binary, (binary, *args), (), False), None
    if len(rest) == 2 and rest[0] in ("a", "addr", "address", "r", "route", "l", "link") and rest[1] == "show":
        return DirectCommand(binary, (binary, *args), (), False), None
    return None, "ip subcommand requires owner approval"


def _validate_ps(binary: str, args: List[str], **_kw) -> Tuple[Optional[DirectCommand], Optional[str]]:
    allowed = {"-e", "-f", "-a", "-u", "-x", "-ef", "aux", "-aux"}
    if all(a in allowed for a in args):
        return DirectCommand(binary, (binary, *args), (), False), None
    return None, "ps flags require owner approval"


def _validate_which_where(binary: str, args: List[str], **_kw) -> Tuple[Optional[DirectCommand], Optional[str]]:
    if not (1 <= len(args) <= 5):
        return None, f"{binary} expects 1..5 command names"
    for a in args:
        if not _SAFE_BARE_NAME_RE.fullmatch(a):
            return None, f"invalid command name '{a}' for {binary}"
    return DirectCommand(binary, (binary, *args), (), False), None


def _validate_echo(binary: str, args: List[str], **_kw) -> Tuple[Optional[DirectCommand], Optional[str]]:
    if len(args) > 16:
        return None, "too many echo arguments"
    if args and args[0].startswith("-"):
        return None, f"echo option '{args[0]}' not allowed for direct PASS"
    for a in args:
        if _SECRET_ARG_LOOKALIKE_RE.search(a) or _looks_like_path_arg(a):
            return None, "echo path-like or sensitive argument requires review"
    return DirectCommand(binary, (binary, *args), (), False), None


def _validate_version_only(extra: Tuple[str, ...] = ()) -> Callable[..., Tuple[Optional[DirectCommand], Optional[str]]]:
    def _fn(binary: str, args: List[str], **_kw) -> Tuple[Optional[DirectCommand], Optional[str]]:
        if args in (["--version"], ["-V"]) or (len(args) == 1 and args[0] in extra):
            return DirectCommand(binary, (binary, *args), (), False), None
        return None, f"{binary} only allows version/read-only status check for direct PASS"
    return _fn


def _validate_ls(
    binary: str, args: List[str], *, base_dir: Optional[str], cwd: Optional[str], policy: AegisPolicy
) -> Tuple[Optional[DirectCommand], Optional[str]]:
    long_flags = {"--all", "--almost-all", "--human-readable", "--directory", "--classify", "--color=never"}
    paths: List[str] = []
    for a in args:
        if a in long_flags or _short_bundle_ok(a, "laAh1RtrSdF"):
            continue
        if a.startswith("-"):
            return None, f"ls option '{a}' not allowed for direct PASS"
        err = _validate_read_path(a, base_dir=base_dir, cwd=cwd, policy=policy)
        if err:
            return None, err
        paths.append(a)
    return DirectCommand(binary, (binary, *args), tuple(paths), True), None


def _validate_cat_or_hash(
    allowed_bundle: str,
) -> Callable[..., Tuple[Optional[DirectCommand], Optional[str]]]:
    def _fn(binary: str, args: List[str], *, base_dir: Optional[str], cwd: Optional[str], policy: AegisPolicy) -> Tuple[Optional[DirectCommand], Optional[str]]:
        paths: List[str] = []
        for a in args:
            if allowed_bundle and _short_bundle_ok(a, allowed_bundle):
                continue
            if a.startswith("-"):
                return None, f"{binary} option '{a}' not allowed for direct PASS"
            err = _validate_read_path(a, base_dir=base_dir, cwd=cwd, policy=policy)
            if err:
                return None, err
            paths.append(a)
        if not paths:
            return None, f"{binary} requires at least one file path"
        return DirectCommand(binary, (binary, *args), tuple(paths), True), None
    return _fn


def _validate_head_tail(
    binary: str, args: List[str], *, base_dir: Optional[str], cwd: Optional[str], policy: AegisPolicy
) -> Tuple[Optional[DirectCommand], Optional[str]]:
    paths: List[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-q", "-v"):
            i += 1
            continue
        if _SHORT_NUM_FLAG_RE.fullmatch(a):
            val = int(a[1:])
            if not (1 <= val <= 100_000):
                return None, f"count out of bounds: {a}"
            i += 1
            continue
        if a in ("-n", "-c"):
            if i + 1 >= len(args) or not _SAFE_COUNT_RE.fullmatch(args[i + 1]):
                return None, f"{binary} {a} requires positive integer"
            val = int(args[i + 1])
            if not (1 <= val <= 100_000):
                return None, f"count out of bounds: {val}"
            i += 2
            continue
        if a.startswith(("-n", "-c")) and not a.startswith("--") and _SAFE_COUNT_RE.fullmatch(a[2:]):
            val = int(a[2:])
            if not (1 <= val <= 100_000):
                return None, f"count out of bounds: {val}"
            i += 1
            continue
        if a.startswith("-"):
            return None, f"{binary} option '{a}' not allowed for direct PASS"
        err = _validate_read_path(a, base_dir=base_dir, cwd=cwd, policy=policy)
        if err:
            return None, err
        paths.append(a)
        i += 1
    if not paths:
        return None, f"{binary} requires at least one file path"
    return DirectCommand(binary, (binary, *args), tuple(paths), True), None


def _validate_stat(
    binary: str, args: List[str], *, base_dir: Optional[str], cwd: Optional[str], policy: AegisPolicy
) -> Tuple[Optional[DirectCommand], Optional[str]]:
    paths: List[str] = []
    for a in args:
        if a in ("-t", "--terse"):
            continue
        if a.startswith("-"):
            return None, f"stat option '{a}' not allowed for direct PASS"
        err = _validate_read_path(a, base_dir=base_dir, cwd=cwd, policy=policy)
        if err:
            return None, err
        paths.append(a)
    if not paths:
        return None, "stat requires at least one path"
    return DirectCommand(binary, (binary, *args), tuple(paths), True), None


def _validate_diff(
    binary: str, args: List[str], *, base_dir: Optional[str], cwd: Optional[str], policy: AegisPolicy
) -> Tuple[Optional[DirectCommand], Optional[str]]:
    long_flags = {"--brief", "--unified", "--stat"}
    paths: List[str] = []
    for a in args:
        if a in long_flags or _short_bundle_ok(a, "uqrwb i".replace(" ", "")):
            continue
        if a.startswith("-"):
            return None, f"diff option '{a}' not allowed for direct PASS"
        err = _validate_read_path(a, base_dir=base_dir, cwd=cwd, policy=policy)
        if err:
            return None, err
        paths.append(a)
    if len(paths) != 2:
        return None, "diff requires exactly two file paths for direct PASS"
    return DirectCommand(binary, (binary, *args), tuple(paths), True), None


def _validate_rg(
    binary: str, args: List[str], *, base_dir: Optional[str], cwd: Optional[str], policy: AegisPolicy
) -> Tuple[Optional[DirectCommand], Optional[str]]:
    if args in (["--version"], ["-V"]):
        return DirectCommand(binary, (binary, *args), (), False), None
    bool_long = {"--files", "--json", "--hidden", "--no-ignore", "--line-number", "--ignore-case",
                 "--smart-case", "--fixed-strings", "--files-with-matches", "--count"}
    int_opts = {"-C", "-A", "-B", "-m", "--max-count", "--max-depth"}
    type_opts = {"-t", "-T", "--type", "--type-not"}
    files_mode = False
    pos: List[str] = []
    end_opts = False
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--" and not end_opts:
            end_opts = True
            i += 1
            continue
        if not end_opts and a.startswith("-"):
            if a == "--files":
                files_mode = True
                i += 1
                continue
            if a in bool_long or _short_bundle_ok(a, "niSFwlcHI"):
                i += 1
                continue
            opt, eq, eq_val = a.partition("=")
            if opt in int_opts:
                val = eq_val if eq else (args[i + 1] if i + 1 < len(args) else "")
                if not _SAFE_COUNT_RE.fullmatch(val) or int(val) > 10000:
                    return None, f"rg {opt} expects bounded non-negative int"
                i += 1 if eq else 2
                continue
            if opt in type_opts:
                val = eq_val if eq else (args[i + 1] if i + 1 < len(args) else "")
                if not _SAFE_RG_TYPE_RE.fullmatch(val):
                    return None, f"rg invalid type '{val}'"
                i += 1 if eq else 2
                continue
            return None, f"rg option '{a}' not allowed for direct PASS"
        pos.append(a)
        i += 1

    path_candidates = pos if files_mode else pos[1:]
    if not files_mode and not pos:
        return None, "rg requires a search pattern"
    for p in path_candidates:
        err = _validate_read_path(p, base_dir=base_dir, cwd=cwd, policy=policy)
        if err:
            return None, err
    return DirectCommand(binary, (binary, *args), tuple(path_candidates), True), None


def _validate_git(
    binary: str, args: List[str], *, base_dir: Optional[str], cwd: Optional[str], policy: AegisPolicy
) -> Tuple[Optional[DirectCommand], Optional[str]]:
    if args in (["--version"], ["-V"]):
        return DirectCommand(binary, (binary, *args), (), False), None
    rest = list(args)
    c_dir: Optional[str] = None
    c_dir_abs: Optional[str] = None
    if rest and rest[0] == "-C":
        if len(rest) < 2:
            return None, "git -C missing directory"
        err = _validate_read_path(rest[1], base_dir=base_dir, cwd=cwd, policy=policy)
        if err:
            return None, err
        c_dir = rest[1]
        c_dir_abs, _, _ = resolve_path(c_dir, base_dir=base_dir, cwd=cwd or base_dir)
        rest = rest[2:]
    if not rest:
        return None, "git missing subcommand"
    if rest[0].startswith("-"):
        return None, f"git global flag '{rest[0]}' not allowed for direct PASS"
    sub = rest[0]
    sargs = rest[1:]

    ro_subcommands = {"status", "diff", "log", "show", "branch", "rev-parse",
                      "describe", "ls-files", "shortlog", "blame", "tag", "remote"}
    if sub not in ro_subcommands:
        return None, f"git subcommand '{sub}' requires owner approval"

    paths: List[str] = [c_dir] if c_dir else []
    sub_base_cwd = c_dir_abs or cwd
    if sub == "branch":
        allowed_branch = {"-a", "--all", "-r", "--remotes", "-v", "-vv", "--list", "--show-current", "--merged", "--no-merged"}
        for a in sargs:
            if a not in allowed_branch:
                return None, f"git branch arg '{a}' requires owner approval"
    elif sub == "tag":
        if sargs and sargs not in (["-l"], ["--list"]):
            return None, "git tag with arguments requires owner approval"
    elif sub == "remote":
        if sargs and sargs not in (["-v"], ["--verbose"]):
            return None, "git remote modification/inspection with args requires owner approval"
    elif sub == "status":
        allowed_status = {
            "-s", "--short", "-b", "--branch", "--porcelain", "--porcelain=v1", "--porcelain=v2",
            "-u", "--untracked-files", "--untracked-files=all", "--untracked-files=normal",
            "--untracked-files=no", "--ignored",
        }
        after_dd = False
        for a in sargs:
            if a == "--" and not after_dd:
                after_dd = True
                continue
            if not after_dd and a.startswith("-"):
                if a not in allowed_status:
                    return None, f"git status flag '{a}' not allowed for direct PASS"
                continue
            err = _validate_read_path(a, base_dir=base_dir, cwd=sub_base_cwd, policy=policy)
            if err:
                return None, err
            paths.append(a)
    else:
        allowed_ro_flags = {
            "--stat", "--numstat", "--shortstat", "--name-only", "--name-status", "--oneline",
            "--abbrev-commit", "--no-merges", "--first-parent", "--all", "--graph", "--decorate",
            "--staged", "--cached", "--patch", "-p", "--word-diff", "--compact-summary",
            "--summary", "--reverse", "--full-index", "--short", "--abbrev-ref",
            "--show-toplevel", "--is-inside-work-tree", "--verify", "--tags",
            "--exact-match", "--always", "--others", "--exclude-standard", "--modified",
            "--deleted", "--cached", "--full-name", "--relative", "-s", "-q", "-n",
        }
        after_dd = False
        expect_count = False
        for a in sargs:
            if expect_count:
                if not _SAFE_COUNT_RE.fullmatch(a):
                    return None, f"git expects numeric count after flag, got '{a}'"
                expect_count = False
                continue
            if a == "--" and not after_dd:
                after_dd = True
                continue
            if not after_dd and a.startswith("-"):
                if a in ("-n", "--max-count") and sub in ("log", "shortlog", "show"):
                    if a == "-n":
                        expect_count = True
                    continue
                if sub in ("log", "shortlog") and _SHORT_NUM_FLAG_RE.fullmatch(a):
                    continue
                if sub in ("log", "show") and a.startswith("--max-count=") and _SAFE_COUNT_RE.fullmatch(a.split("=", 1)[1]):
                    continue
                if sub in ("log", "show") and a in ("--format=oneline", "--format=short", "--format=medium", "--pretty=oneline", "--date=short", "--date=iso", "--date=relative"):
                    continue
                if sub in ("diff", "show") and re.fullmatch(r"-U[0-9]{1,3}|--unified=[0-9]{1,3}", a):
                    continue
                if sub == "rev-parse" and re.fullmatch(r"--short=[0-9]{1,2}", a):
                    continue
                if a in allowed_ro_flags:
                    continue
                return None, f"git {sub} flag '{a}' not allowed for direct PASS"
            if after_dd or _looks_like_path_arg(a) or sub in ("ls-files", "blame"):
                err = _validate_read_path(a, base_dir=base_dir, cwd=sub_base_cwd, policy=policy)
                if err:
                    return None, err
                paths.append(a)
            else:
                if _is_sensitive_control_component(a) or classify_sensitive(a, write_mode=False) is not None:
                    return None, f"sensitive git arg '{a}' rejected"
                if ".." in a and not _SAFE_GIT_REV_RE.fullmatch(a):
                    return None, f"git revision/path '{a}' rejected"
                if not _SAFE_GIT_REV_RE.fullmatch(a):
                    return None, f"git revision/arg '{a}' not in safe rev allowlist"
                # Also reject if it matches a path on disk that would fail _validate_read_path
                cand_abs, _, _ = resolve_path(a, base_dir=base_dir, cwd=sub_base_cwd or base_dir)
                if os.path.lexists(cand_abs):
                    err = _validate_read_path(a, base_dir=base_dir, cwd=sub_base_cwd, policy=policy)
                    if err:
                        return None, err
                    paths.append(a)
        if expect_count:
            return None, "git -n missing count"

    hardened: List[str] = ["git"]
    if c_dir:
        hardened.extend(["-C", c_dir])
    hardened.extend([
        "-c", "core.pager=cat",
        "-c", "core.fsmonitor=false",
        "-c", "core.sshCommand=false",
        "-c", "diff.external=",
        "-c", "credential.helper=",
        "--no-pager",
        sub,
    ])
    if sub in ("diff", "log", "show"):
        hardened.extend(["--no-ext-diff", "--no-textconv"])
    hardened.extend(sargs)
    return DirectCommand("git", tuple(hardened), tuple(paths), True), None


_DIRECT_HANDLERS: Dict[str, Callable[..., Tuple[Optional[DirectCommand], Optional[str]]]] = {
    "hostname": _validate_zero_arg,
    "whoami": _validate_zero_arg,
    "pwd": _validate_zero_arg,
    "systeminfo": _validate_zero_arg,
    "id": _validate_exact_flag_set(frozenset({"-u", "-g", "-G", "-n", "-un", "-gn"})),
    "uname": _validate_exact_flag_set(frozenset({"-a", "-s", "-n", "-r", "-v", "-m", "-p", "-i", "-o"}), bundle="asnrvm pio".replace(" ", "")),
    "uptime": _validate_exact_flag_set(frozenset({"-p", "-s"})),
    "nproc": _validate_exact_flag_set(frozenset({"--all"})),
    "date": _validate_date,
    "df": _validate_df,
    "free": _validate_exact_flag_set(frozenset({"-b", "-k", "-m", "-g", "-h", "-t", "-w"})),
    "lscpu": _validate_exact_flag_set(frozenset({"-a", "-v", "-k", "-f", "-l", "-s", "-J", "--json"})),
    "lspci": _validate_exact_flag_set(frozenset({"-a", "-v", "-k", "-f", "-l", "-s", "-J", "--json"})),
    "lsblk": _validate_exact_flag_set(frozenset({"-a", "-v", "-k", "-f", "-l", "-s", "-J", "--json"})),
    "lsusb": _validate_exact_flag_set(frozenset({"-a", "-v", "-k", "-f", "-l", "-s", "-J", "--json"})),
    "sw_vers": _validate_exact_flag_set(frozenset({"-productVersion", "-productName", "-buildVersion"})),
    "lsb_release": _validate_exact_flag_set(frozenset({"-a", "-i", "-d", "-r", "-c", "-s", "--all", "--short"})),
    "hostnamectl": _validate_exact_flag_set(frozenset({"status"})),
    "timedatectl": _validate_exact_flag_set(frozenset({"status"})),
    "nvidia-smi": _validate_nvidia_smi,
    "ipconfig": _validate_ipconfig,
    "netstat": _validate_exact_flag_set(frozenset(), bundle="anoesrtulp"),
    "ss": _validate_exact_flag_set(frozenset(), bundle="tulnpar46"),
    "ip": _validate_ip,
    "tasklist": _validate_tasklist,
    "ps": _validate_ps,
    "which": _validate_which_where,
    "where": _validate_which_where,
    "echo": _validate_echo,
    # Version / runtime checks
    "python": _validate_version_only(),
    "python3": _validate_version_only(),
    "py": _validate_version_only(),
    "node": _validate_version_only(),
    "npm": _validate_version_only(),
    "pnpm": _validate_version_only(),
    "yarn": _validate_version_only(),
    "cargo": _validate_version_only(),
    "rustc": _validate_version_only(),
    "go": _validate_version_only(("version",)),
    "dotnet": _validate_version_only(),
    "uv": _validate_version_only(),
    "pytest": _validate_version_only(),
    "ruff": _validate_version_only(),
    "fd": _validate_version_only(),
    "bwrap": _validate_version_only(),
    "docker": _validate_version_only(("version",)),
    "gh": _validate_version_only(),
    "ollama": _validate_version_only(("list", "ps")),
    # Read-only workspace inspection
    "ls": _validate_ls,
    "cat": _validate_cat_or_hash("nbsET"),
    "head": _validate_head_tail,
    "tail": _validate_head_tail,
    "wc": _validate_cat_or_hash("lwcmL"),
    "stat": _validate_stat,
    "diff": _validate_diff,
    "sha256sum": _validate_cat_or_hash(""),
    "sha1sum": _validate_cat_or_hash(""),
    "md5sum": _validate_cat_or_hash(""),
    "rg": _validate_rg,
    "git": _validate_git,
}


def parse_direct_command(
    command: str,
    *,
    base_dir: Optional[str] = None,
    cwd: Optional[str] = None,
    policy: Optional[AegisPolicy] = None,
    windows: bool = False,
) -> Tuple[Optional[DirectCommand], Optional[str]]:
    """Return ``(DirectCommand, None)`` iff *command* is safe for no-shell ``PASS``.

    Otherwise returns ``(None, human_reason)``.
    """
    toks, tok_err = _tokenize_literal_argv(command, windows=windows)
    if tok_err or not toks:
        return None, tok_err or "invalid literal command"

    raw_bin, bin_quoted = toks[0]
    if bin_quoted:
        return None, "quoted executable name not allowed for direct PASS"
    if "/" in raw_bin or "\\" in raw_bin or raw_bin.startswith("."):
        return None, "path-qualified executable requires owner approval"
    low_bin = raw_bin.lower()
    if any(low_bin.endswith(ext) for ext in _REJECTED_WIN_EXTS):
        return None, "script/batch shim extension requires owner approval"
    if (windows or sys.platform == "win32") and low_bin.endswith(".exe"):
        low_bin = low_bin[:-4]
    if not _BARE_BINARY_RE.fullmatch(low_bin):
        return None, f"executable '{raw_bin}' is not a simple command name"

    handler = _DIRECT_HANDLERS.get(low_bin)
    if handler is None:
        return None, f"command '{low_bin}' is not in the direct no-shell allowlist"

    pol = policy or DEFAULT_POLICY
    args = [text for text, _ in toks[1:]]
    dc, reason = handler(low_bin, args, base_dir=base_dir, cwd=cwd, policy=pol)
    if dc is None:
        return None, reason or f"command '{low_bin}' requires owner approval"
    return dc, None
