"""Tests for Evasion Canonicalization."""

import os
import unittest
from aegis.canonicalizer import (
    canonicalize_ip,
    canonicalize_path,
    detect_null_bytes,
    normalize_text,
    unquote_recursively,
)


class TestCanonicalizer(unittest.TestCase):

    def test_recursive_unquote(self):
        # Double URL encoding: %252e%252e%252f -> %2e%2e%2f -> ../
        decoded, evasion = unquote_recursively("%252e%252e%252f")
        self.assertEqual(decoded, "../")
        self.assertTrue(evasion)

    def test_unicode_normalization(self):
        # Fullwidth slash: ／ (U+FF0F)
        fullwidth = "etc\uFF0Fpasswd"
        normalized = normalize_text(fullwidth)
        self.assertEqual(normalized, "etc/passwd")

    def test_null_byte_detection(self):
        self.assertTrue(detect_null_bytes("safe.txt\x00.exe"))
        self.assertTrue(detect_null_bytes("safe.txt%00.exe"))
        self.assertFalse(detect_null_bytes("safe_file.txt"))

    def test_ip_canonicalization(self):
        # Standard loopback
        ip, ok = canonicalize_ip("127.0.0.1")
        self.assertTrue(ok)
        self.assertTrue(ip.is_loopback)

        # Hex representation: 0x7f000001 (127.0.0.1)
        ip_hex, ok_hex = canonicalize_ip("0x7f000001")
        self.assertTrue(ok_hex)
        self.assertEqual(str(ip_hex), "127.0.0.1")

        # Decimal integer representation: 2130706433 (127.0.0.1)
        ip_dec, ok_dec = canonicalize_ip("2130706433")
        self.assertTrue(ok_dec)
        self.assertEqual(str(ip_dec), "127.0.0.1")

    def test_path_containment(self):
        base = os.path.abspath("C:/safe/workspace")
        # Safe subfolder
        _, confined = canonicalize_path(base, "sub/file.txt")
        self.assertTrue(confined)

        # Escaping path
        _, confined = canonicalize_path(base, "../../windows/system32")
        self.assertFalse(confined)


if __name__ == "__main__":
    unittest.main()
