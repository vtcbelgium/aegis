"""Tests for the 4 Defensive Clans."""

import unittest
from aegis.core import DecisionLevel
from aegis.clans import LabyrinthClan, TartarusClan, CustodyClan, HecatoncheiresClan


class TestClans(unittest.TestCase):

    def test_labyrinth_traversal_detection(self):
        v1 = LabyrinthClan.inspect_path("../../secret.key")
        self.assertEqual(v1.level, DecisionLevel.WARN)
        self.assertFalse(v1.passed if v1.level >= DecisionLevel.RESTRICT else False)

        v2 = LabyrinthClan.inspect_path("safe.txt\x00.exe")
        self.assertEqual(v2.level, DecisionLevel.LOCK)

    def test_tartarus_catastrophic_commands(self):
        v = TartarusClan.inspect_command("rm -rf / --no-preserve-root")
        self.assertEqual(v.level, DecisionLevel.LOCK)

        v_chain = TartarusClan.inspect_command("echo hello; rm file.txt")
        self.assertEqual(v_chain.level, DecisionLevel.DENY)

        v_clean = TartarusClan.inspect_command("npm run build")
        self.assertEqual(v_clean.level, DecisionLevel.PASS)

    def test_tartarus_sql_injection(self):
        v_bad = TartarusClan.inspect_sql("SELECT * FROM users WHERE id = '1' OR '1'='1'")
        self.assertEqual(v_bad.level, DecisionLevel.DENY)

        v_clean = TartarusClan.inspect_sql("SELECT id, name FROM users WHERE id = ?")
        self.assertEqual(v_clean.level, DecisionLevel.PASS)

    def test_custody_secrets_detection(self):
        sample_token = "ghp_" + "123456789012345678901234567890123456"
        v_key = CustodyClan.inspect_secrets(sample_token)
        self.assertEqual(v_key.level, DecisionLevel.LOCK)

        v_clean = CustodyClan.inspect_secrets("const PORT = 3000;")
        self.assertEqual(v_clean.level, DecisionLevel.PASS)

    def test_custody_ssrf_metadata_blocking(self):
        v_meta = CustodyClan.inspect_url("http://169.254.169.254/latest/meta-data/")
        self.assertEqual(v_meta.level, DecisionLevel.LOCK)

        v_private = CustodyClan.inspect_url("http://192.168.1.1/admin")
        self.assertEqual(v_private.level, DecisionLevel.DENY)

        v_clean = CustodyClan.inspect_url("https://api.github.com/repos")
        self.assertEqual(v_clean.level, DecisionLevel.PASS)

    def test_hecatoncheires_runaway_loop(self):
        clan = HecatoncheiresClan(loop_threshold=3, window_seconds=10.0)
        v1 = clan.inspect_loop("write_file:['path']")
        self.assertTrue(v1.passed)
        v2 = clan.inspect_loop("write_file:['path']")
        self.assertTrue(v2.passed)
        # 3rd identical call trips the brake
        v3 = clan.inspect_loop("write_file:['path']")
        self.assertEqual(v3.level, DecisionLevel.DENY)


if __name__ == "__main__":
    unittest.main()
