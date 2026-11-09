"""Aegis Canonicalizer: Evasion-Proof Input Normalization.

Defeats attacks that bypass string/regex matching:
    1. Multi-level URL encoding (%252e%252e/ -> ../)
    2. Unicode homoglyphs and fullwidth characters (NFKC normalization)
    3. Null-byte truncation (\x00, %00)
    4. Alternative IP representations (hex, dword, octal, IPv6 mapped)
"""

from __future__ import annotations

import ipaddress
import os
import re
import socket
import unicodedata
import urllib.parse
from typing import List, Optional, Tuple


# Invisible characters used to split or smuggle text past pattern matching:
# zero-width chars, soft hyphen, word joiner, bidi controls, Mongolian vowel separator,
# and the Unicode "tag" block (ASCII smuggling).
_INVISIBLE_RE = re.compile(
    "[\u00AD\u180E\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]|[\U000E0000-\U000E007F]"
)


def normalize_text(text: str) -> str:
    """Normalize text using Unicode NFKC and strip invisible / bidi / tag characters."""
    if not isinstance(text, str):
        return ""
    # NFKC normalizes fullwidth characters, ligatures, and homoglyphs
    normalized = unicodedata.normalize("NFKC", text)
    return _INVISIBLE_RE.sub("", normalized)


def normalize_for_matching(text: str) -> str:
    """normalize_text + casefold + collapsed whitespace, for natural-language pattern matching."""
    return re.sub(r"\s+", " ", normalize_text(text).casefold())


# ---------------------------------------------------------------------------
# Path variable expansion and resolution (one normalizer used everywhere)
# ---------------------------------------------------------------------------

_HOME_VARS = {"HOME", "USERPROFILE"}
_TEMP_VARS = {"TMPDIR", "TEMP", "TMP"}
_WIN_ABS_RE = re.compile(r"^(?:[A-Za-z]:[\\/]|[A-Za-z]:$|\\\\|//)")
_VAR_RE = re.compile(
    r"\$\{env:(?P<a>[A-Za-z_][A-Za-z0-9_]*)\}"      # ${env:NAME}   (PowerShell)
    r"|\$env:(?P<b>[A-Za-z_][A-Za-z0-9_]*)"           # $env:NAME     (PowerShell)
    r"|\$\{(?P<c>[A-Za-z_][A-Za-z0-9_]*)(?P<cmod>[^}]*)\}"  # ${NAME} / ${NAME:-x}
    r"|\$(?P<d>[A-Za-z_][A-Za-z0-9_]*)"               # $NAME
    r"|%(?P<e>[A-Za-z_][A-Za-z0-9_]*)%",              # %NAME%        (cmd.exe)
    re.IGNORECASE,
)


def home_dir() -> str:
    return os.path.expanduser("~")


def expand_path_vars(path: str, cwd: Optional[str] = None) -> Tuple[str, bool]:
    """Expand ~, home/temp/cwd variables in every shell spelling.

    Returns (expanded, unresolved) where unresolved is True if a variable remains that
    Aegis cannot know the value of (the caller should then ask the owner).
    """
    unresolved = False
    home = home_dir()

    def repl(m: "re.Match[str]") -> str:
        nonlocal unresolved
        name = next(g for g in (m.group("a"), m.group("b"), m.group("c"), m.group("d"), m.group("e")) if g)
        upper = name.upper()
        if upper in _HOME_VARS:
            return home
        if upper in _TEMP_VARS:
            import tempfile
            return tempfile.gettempdir()
        if upper in {"PWD", "CD"} and cwd:
            return cwd
        if upper == "HOMEPATH":
            return home
        if upper == "HOMEDRIVE":
            return ""
        unresolved = True
        return m.group(0)

    expanded = _VAR_RE.sub(repl, path)
    if expanded.startswith("~"):
        expanded = os.path.expanduser(expanded)
        if expanded.startswith("~"):          # ~unknownuser
            parent = os.path.dirname(home)
            name, _, rest = expanded[1:].partition("/")
            expanded = os.path.join(parent, name, rest) if name else home
    return expanded, unresolved


def looks_windows_path(path: str) -> bool:
    return bool(_WIN_ABS_RE.match(path or ""))


def is_inside(abs_path: str, root: str) -> bool:
    """True when abs_path is root or below it (Windows paths compared case-insensitively)."""
    if not abs_path or not root:
        return False
    if looks_windows_path(root) or looks_windows_path(abs_path):
        import ntpath
        a = ntpath.normpath(abs_path).replace("\\", "/").lower().rstrip("/")
        b = ntpath.normpath(root).replace("\\", "/").lower().rstrip("/")
        return a == b or a.startswith(b + "/")
    root_abs = os.path.realpath(os.path.abspath(os.path.expanduser(root)))
    try:
        return os.path.commonpath([root_abs, abs_path]) == root_abs
    except ValueError:
        return False


def resolve_path(path: str, base_dir: Optional[str] = None, cwd: Optional[str] = None) -> Tuple[str, Optional[bool], bool]:
    """Resolve path the way the target shell would see it.

    Returns (absolute_path, confined, unresolved):
        confined is None when no base_dir is set, otherwise whether the path stays inside it.
        unresolved is True when the path contains a variable Aegis cannot expand.
    Windows-style paths are resolved with ntpath semantics even on a POSIX host,
    so a gate running on Linux still understands C:\\Users when guarding a Windows machine.
    """
    import ntpath
    import posixpath

    clean, _ = unquote_recursively(normalize_text(path))
    clean = clean.replace("\x00", "").strip()
    start = cwd or base_dir
    clean, unresolved = expand_path_vars(clean, cwd=start)

    base_is_win = bool(base_dir and looks_windows_path(base_dir))
    target_is_win = looks_windows_path(clean)

    if target_is_win or base_is_win:
        mod = ntpath
        # Python 3.13 changed ntpath.isabs('/x') to False. Preserve foreign-root
        # spellings so POSIX destruction/logging rules remain identical on Windows.
        if mod.isabs(clean) or target_is_win or clean.startswith(("/", "\\")):
            abs_target = mod.normpath(clean)
        else:
            abs_target = mod.normpath(mod.join(start or "", clean))
        abs_target = abs_target.replace("\\", "/")
        if base_dir is None:
            return abs_target, None, unresolved
        abs_base = mod.normpath(base_dir).replace("\\", "/")
        if not base_is_win:
            return abs_target, False, unresolved     # Windows path vs POSIX workspace
        a, b = abs_target.lower().rstrip("/"), abs_base.lower().rstrip("/")
        return abs_target, (a == b or a.startswith(b + "/")), unresolved

    if os.name == "nt":
        clean = clean.replace("/", "\\")
    if os.path.isabs(clean):
        abs_target = os.path.realpath(clean)
    else:
        abs_target = os.path.realpath(os.path.join(start or os.getcwd(), clean))
    if base_dir is None:
        return abs_target, None, unresolved
    abs_base = os.path.realpath(os.path.abspath(base_dir))
    try:
        confined = os.path.commonpath([abs_base, abs_target]) == abs_base
    except ValueError:                         # different drives on Windows
        confined = False
    return abs_target, confined, unresolved


def unquote_recursively(text: str, max_depth: int = 4) -> Tuple[str, bool]:
    """Recursively decode URL-encoded sequences to defeat multi-layered evasion."""
    current = text
    evasion_detected = False
    for depth in range(max_depth):
        decoded = urllib.parse.unquote(current)
        if decoded == current:
            break
        current = decoded
        if depth > 0:
            evasion_detected = True
    return current, evasion_detected


def detect_null_bytes(text: str) -> bool:
    """Detect raw or encoded null bytes used for path truncation attacks."""
    if "\x00" in text or "%00" in text or "\\0" in text:
        return True
    return False


def canonicalize_path(base_dir: str, target_path: str) -> Tuple[str, bool]:
    """Resolve target_path and verify it remains strictly confined within base_dir.
    Expands user home directory (~) and normalizes Unicode/URL encoding.

    Returns:
        (resolved_path, is_confined)
    """
    try:
        expanded_base, _ = expand_path_vars(base_dir.strip())
        abs_target, confined, unresolved = resolve_path(target_path, base_dir=expanded_base)
        if unresolved:
            return abs_target, False
        return abs_target, bool(confined)
    except Exception:
        return "", False


def parse_mixed_int(s: str) -> int:
    """Parse integer that might be hex (0x...), octal (0...), or decimal."""
    s = s.strip()
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)
    if s.startswith("0") and len(s) > 1 and s.isdigit():
        return int(s, 8)
    return int(s, 10)


def canonicalize_ip(host_or_ip: str) -> Tuple[Optional[ipaddress.IPv4Address | ipaddress.IPv6Address], bool]:
    """Canonicalize host/IP strings, converting hex, dword, octal, short notation or standard.

    Supports:
        - Dotted-decimal: 127.0.0.1
        - 2-part BSD: 127.1 -> 127.0.0.1
        - 3-part BSD: 127.0.1 -> 127.0.0.1
        - Mixed hex/octal: 0x7f.1 -> 127.0.0.1, 0177.0.0.1
        - Dword integer: 2130706433 -> 127.0.0.1
        - Hex integer: 0x7f000001 -> 127.0.0.1

    Returns:
        (ip_obj, is_valid_ip)
    """
    cleaned = host_or_ip.strip().strip("[]").lower()

    # Try standard parse
    try:
        return ipaddress.ip_address(cleaned), True
    except ValueError:
        pass

    # Try single integer representation (decimal, octal, or hex)
    if cleaned.isdigit() or cleaned.startswith("0x") or (cleaned.startswith("0") and len(cleaned) > 1 and cleaned[1:].isdigit()):
        try:
            val = parse_mixed_int(cleaned)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val), True
        except ValueError:
            pass

    # Try dotted mixed representations (1, 2, 3, or 4 parts according to BSD socket inet_aton rules)
    if "." in cleaned:
        parts = cleaned.split(".")
        if 1 <= len(parts) <= 4:
            try:
                nums = [parse_mixed_int(p) for p in parts]
                if len(nums) == 4:
                    if all(0 <= n <= 255 for n in nums):
                        dotted = ".".join(str(n) for n in nums)
                        return ipaddress.IPv4Address(dotted), True
                elif len(nums) == 3:
                    # a.b.c -> a.b.0.c (where c is 16-bit)
                    if 0 <= nums[0] <= 255 and 0 <= nums[1] <= 255 and 0 <= nums[2] <= 0xFFFF:
                        val = (nums[0] << 24) | (nums[1] << 16) | nums[2]
                        return ipaddress.IPv4Address(val), True
                elif len(nums) == 2:
                    # a.b -> a.0.0.b (where b is 24-bit, e.g. 127.1 -> 127.0.0.1)
                    if 0 <= nums[0] <= 255 and 0 <= nums[1] <= 0xFFFFFF:
                        val = (nums[0] << 24) | nums[1]
                        return ipaddress.IPv4Address(val), True
            except ValueError:
                pass

    return None, False


def resolve_host_ips(hostname: str) -> List[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Resolve a hostname to its IP addresses to detect DNS rebinding or nip.io/sslip.io evasions."""
    ips: List[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    clean_host = hostname.strip().lower()

    # Check if host is already an IP address
    direct_ip, is_ip = canonicalize_ip(clean_host)
    if is_ip and direct_ip is not None:
        return [direct_ip]

    # Check nip.io, sslip.io or direct embedded IP in hostname
    nip_match = re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\.(nip|sslip)\.io\b", clean_host)
    if nip_match:
        try:
            return [ipaddress.ip_address(nip_match.group(1))]
        except ValueError:
            pass

    if clean_host in {"localhost", "localhost.localdomain"}:
        return [ipaddress.ip_address("127.0.0.1"), ipaddress.ip_address("::1")]

    # Live DNS resolution fallback only for domain names with dots
    if "." in clean_host and not clean_host.endswith(".internal"):
        try:
            results = socket.getaddrinfo(clean_host, None)
            for res in results:
                sockaddr = res[4]
                ip_str = sockaddr[0]
                try:
                    ip_obj = ipaddress.ip_address(ip_str)
                    if ip_obj not in ips:
                        ips.append(ip_obj)
                except ValueError:
                    pass
        except Exception:
            pass

    return ips
