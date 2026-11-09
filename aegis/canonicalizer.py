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


def normalize_text(text: str) -> str:
    """Normalize text using Unicode NFKC and strip non-printable zero-width control chars."""
    if not isinstance(text, str):
        return ""
    # NFKC normalizes fullwidth characters, ligatures, and homoglyphs
    normalized = unicodedata.normalize("NFKC", text)
    # Strip zero-width spaces used in indirect prompt injection
    normalized = re.sub(r"[\u200B-\u200D\uFEFF]", "", normalized)
    return normalized


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

    Returns:
        (resolved_path, is_confined)
    """
    try:
        # Normalize and unquote
        clean_target, _ = unquote_recursively(normalize_text(target_path))
        clean_target = clean_target.replace("\x00", "")

        # Compute absolute paths
        abs_base = os.path.realpath(os.path.abspath(base_dir))
        # If target is relative, join with base_dir; if absolute, realpath it
        if os.path.isabs(clean_target):
            abs_target = os.path.realpath(os.path.abspath(clean_target))
        else:
            abs_target = os.path.realpath(os.path.abspath(os.path.join(abs_base, clean_target)))

        # Verify containment using commonpath
        is_confined = os.path.commonpath([abs_base, abs_target]) == abs_base
        return abs_target, is_confined
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
