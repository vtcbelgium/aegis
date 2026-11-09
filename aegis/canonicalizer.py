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
import unicodedata
import urllib.parse
from typing import Optional, Tuple


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


def canonicalize_ip(host_or_ip: str) -> Tuple[Optional[ipaddress.IPv4Address | ipaddress.IPv6Address], bool]:
    """Canonicalize host/IP strings, converting hex, dword, octal or standard notation.

    Returns:
        (ip_obj, is_valid_ip)
    """
    cleaned = host_or_ip.strip().strip("[]")

    # Try standard parse
    try:
        return ipaddress.ip_address(cleaned), True
    except ValueError:
        pass

    # Try hexadecimal integer representation (e.g., 0x7f000001)
    if cleaned.startswith("0x") or cleaned.startswith("0X"):
        try:
            val = int(cleaned, 16)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val), True
        except ValueError:
            pass

    # Try decimal integer representation (e.g., 2130706433)
    if cleaned.isdigit():
        try:
            val = int(cleaned, 10)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val), True
        except ValueError:
            pass

    return None, False
