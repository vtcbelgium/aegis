"""Tests for Aegis Mathematical Monotonicity and Supreme Law."""

import unittest
from aegis.core import AegisGate, DecisionLevel, SUPREME_LAW, Verdict


class TestMonotonicGate(unittest.TestCase):

    def setUp(self):
        self.gate = AegisGate()

    def test_initial_level_is_pass(self):
        self.assertEqual(self.gate.current_level, DecisionLevel.PASS)

    def test_monotonic_escalation(self):
        # PASS -> WARN
        self.gate.escalate(DecisionLevel.WARN)
        self.assertEqual(self.gate.current_level, DecisionLevel.WARN)

        # Attempt to de-escalate back to OBSERVE -> Must stay at WARN
        self.gate.escalate(DecisionLevel.OBSERVE)
        self.assertEqual(self.gate.current_level, DecisionLevel.WARN)

        # Escalation to LOCK
        self.gate.escalate(DecisionLevel.LOCK)
        self.assertEqual(self.gate.current_level, DecisionLevel.LOCK)

        # Attempt to de-escalate back to PASS -> Must stay at LOCK
        self.gate.escalate(DecisionLevel.PASS)
        self.assertEqual(self.gate.current_level, DecisionLevel.LOCK)

    def test_supreme_law_in_snapshot(self):
        snapshot = self.gate.snapshot()
        self.assertEqual(snapshot["supremeLaw"], SUPREME_LAW)
        self.assertEqual(snapshot["authorityDelta"], "SUBTRACTIVE_ONLY")

    def test_verdict_passed_property(self):
        v_pass = Verdict(DecisionLevel.PASS, ["ok"])
        v_obs = Verdict(DecisionLevel.OBSERVE, ["anomaly"])
        v_warn = Verdict(DecisionLevel.WARN, ["heuristic"])
        v_res = Verdict(DecisionLevel.RESTRICT, ["sanitized"])
        v_deny = Verdict(DecisionLevel.DENY, ["blocked"])
        v_lock = Verdict(DecisionLevel.LOCK, ["fatal"])

        self.assertTrue(v_pass.passed)
        self.assertTrue(v_obs.passed)
        self.assertTrue(v_warn.passed)
        self.assertFalse(v_res.passed)
        self.assertFalse(v_deny.passed)
        self.assertFalse(v_lock.passed)


if __name__ == "__main__":
    unittest.main()
