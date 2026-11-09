"""Tests for Agent Harness Interceptor and MCP Proxy."""

import unittest
from aegis.core import AegisGate, DecisionLevel
from aegis.harness import AegisHarness
from aegis.mcp_proxy import AegisMcpProxy


class TestHarness(unittest.TestCase):

    def setUp(self):
        self.gate = AegisGate()
        self.harness = AegisHarness(gate=self.gate)

    def test_safe_tool_call_passes(self):
        v = self.harness.evaluate_tool_call(
            "run_command",
            {"command": "pytest tests/"}
        )
        self.assertTrue(v.passed)
        self.assertEqual(self.gate.current_level, DecisionLevel.PASS)

    def test_ssrf_tool_call_locked(self):
        v = self.harness.evaluate_tool_call(
            "fetch_web_page",
            {"url": "http://169.254.169.254/secret"}
        )
        self.assertFalse(v.passed)
        self.assertEqual(v.level, DecisionLevel.LOCK)
        self.assertEqual(self.gate.current_level, DecisionLevel.LOCK)

    def test_protected_tool_decorator(self):
        @self.harness.protect_tool
        def dangerous_action(command: str):
            return "executed"

        # Safe command works
        self.assertEqual(dangerous_action(command="echo 'clean'"), "executed")

        # Injection command raises PermissionError
        with self.assertRaises(PermissionError):
            dangerous_action(command="rm -rf /")

    def test_mcp_proxy_filtering(self):
        proxy = AegisMcpProxy(gate=self.gate)

        # 1. Non-tool request passes through untouched
        pass_through, _, _ = proxy.filter_request({"method": "tools/list", "id": 1})
        self.assertTrue(pass_through)

        # 2. Dangerous tool call is blocked and returns MCP error payload
        should_forward, err_response, v = proxy.filter_request({
            "method": "tools/call",
            "id": 2,
            "params": {
                "name": "bash",
                "arguments": {"command": "rm -rf /"}
            }
        })
        self.assertFalse(should_forward)
        self.assertIsNotNone(err_response)
        self.assertTrue(err_response["result"]["isError"])
        self.assertIn("AEGIS NEGATIVE GATE BLOCKED", err_response["result"]["content"][0]["text"])


if __name__ == "__main__":
    unittest.main()
