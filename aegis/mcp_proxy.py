"""Aegis MCP Security Proxy: Guardrail for Model Context Protocol Servers.

Intercepts MCP JSON-RPC requests (tools/call) and validates arguments
against the Aegis Negative Gate before routing them to the upstream MCP server.
Also inspects tool responses for indirect prompt injection and leaked credentials.
"""

from __future__ import annotations

import os
import re
import secrets
from typing import Any, Dict, Optional, Tuple
from .core import AegisGate, DecisionLevel, Verdict
from .harness import AegisHarness
from .clans import CustodyClan


INDIRECT_INJECTION_PATTERNS = [
    r"(?i)ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions",
    r"(?i)system\s+prompt\s*:",
    r"(?i)you\s+are\s+now\s+in\s+(?:dan|developer|god|unrestricted)\s+mode",
    r"(?i)new\s+instructions\s+follow\s*:",
    r"(?i)(?:call|execute)\s+tool\s+(?:execute_bash|run_command|write_file|delete_file)",
    r"!\[.*?\]\(https?://[^\s'\"|;&]+(?:\?|&)(?:token|cookie|auth|leak|key)=",
]


class AegisMcpProxy:
    """Security proxy for Model Context Protocol servers (evaluates requests and responses)."""

    def __init__(
        self,
        gate: Optional[AegisGate] = None,
        base_dir: Optional[str] = None,
        strict_mode: bool = False,
        fail_closed: bool = True,
        owner_secret: Optional[str] = None,
    ) -> None:
        secret = owner_secret or os.environ.get("AEGIS_OWNER_SECRET")
        if not secret:
            secret = secrets.token_hex(16)
        self.owner_secret = secret

        self.gate = gate or AegisGate(
            base_dir=base_dir,
            strict_mode=strict_mode,
            fail_closed=fail_closed,
            owner_secret=self.owner_secret,
        )
        self.harness = AegisHarness(gate=self.gate, base_dir=self.gate.base_dir)

    def filter_request(self, rpc_request: Any) -> Tuple[bool, Optional[Dict[str, Any]], Optional[Verdict]]:
        """Filter an incoming MCP JSON-RPC request with fail-closed crash prevention.

        Returns:
            (should_forward, error_response_if_blocked, verdict)
        """
        try:
            if not isinstance(rpc_request, dict):
                raise ValueError("RPC request must be a dictionary")

            method = rpc_request.get("method")
            params = rpc_request.get("params")
            request_id = rpc_request.get("id")

            if method == "tools/call":
                if not isinstance(params, dict):
                    raise ValueError("RPC params must be a dictionary")

                tool_name = params.get("name", "unknown")
                arguments = params.get("arguments")

                # The MCP specification strictly requires arguments to be a JSON object
                if not isinstance(arguments, dict):
                    verdict = self.gate.record(
                        Verdict(
                            DecisionLevel.DENY,
                            ["MCP protocol violation: 'arguments' parameter must be a dictionary object"],
                            "McpProxyGuard",
                        )
                    )
                    error_response = {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "error": {
                            "code": -32602,
                            "message": "Invalid params: 'arguments' must be a JSON object",
                        },
                    }
                    return False, error_response, verdict

                verdict = self.harness.evaluate_tool_call(tool_name, arguments)
                if not verdict.passed:
                    # Synthesize standard MCP tool error result
                    error_response = {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "result": {
                            "isError": True,
                            "content": [
                                {
                                    "type": "text",
                                    "text": (
                                        f"🛑 AEGIS NEGATIVE GATE BLOCKED [{verdict.level.name}]: "
                                        f"{'; '.join(verdict.reasons)}. "
                                        f"Supreme Law: Aegis may subtract authority, never create it."
                                    ),
                                }
                            ],
                        },
                    }
                    return False, error_response, verdict

                return True, None, verdict

            # Pass through non-tool requests (initialize, list_tools, etc.)
            return True, None, None

        except Exception as exc:
            # Malformed params or unexpected crash -> Fail closed to LOCK
            lock_verdict = self.gate.record(
                Verdict(
                    DecisionLevel.LOCK,
                    [f"MCP request evaluation crashed (fail closed): {exc}"],
                    "McpProxyGuard",
                )
            )
            req_id = rpc_request.get("id") if isinstance(rpc_request, dict) else None
            error_response = {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32600,
                    "message": f"Aegis Gate LOCKED session: {exc}",
                },
            }
            return False, error_response, lock_verdict

    def filter_response(self, rpc_response: Any) -> Tuple[bool, Optional[Dict[str, Any]], Optional[Verdict]]:
        """Scan tool execution output for indirect prompt injections and credential leaks."""
        try:
            if not isinstance(rpc_response, dict):
                return True, None, None

            result = rpc_response.get("result", {})
            if isinstance(result, dict) and "content" in result:
                content_list = result["content"]
                if isinstance(content_list, list):
                    for item in content_list:
                        if isinstance(item, dict) and item.get("type") == "text":
                            text = item.get("text", "")

                            # 1. Check for indirect prompt injection signatures
                            for pattern in INDIRECT_INJECTION_PATTERNS:
                                if re.search(pattern, text):
                                    inj_verdict = self.gate.record(
                                        Verdict(
                                            DecisionLevel.DENY,
                                            [f"Indirect prompt injection attempt neutralized: {pattern}"],
                                            "McpResponseGuard",
                                        )
                                    )
                                    item["text"] = "[REDACTED BY AEGIS: Untrusted indirect prompt injection stripped]"
                                    return False, rpc_response, inj_verdict

                            # 2. Check for leaked credentials in tool output (single atomic record)
                            sec_verdict = CustodyClan.inspect_secrets(text)
                            if not sec_verdict.passed:
                                recorded = self.gate.record(sec_verdict)
                                item["text"] = "[REDACTED BY AEGIS: Leaked credentials stripped from tool response]"
                                return False, rpc_response, recorded

            return True, None, None
        except Exception as exc:
            if self.gate.fail_closed:
                lock_v = self.gate.record(
                    Verdict(
                        DecisionLevel.LOCK,
                        [f"Response filter crashed (fail closed): {exc}"],
                        "McpResponseGuard",
                    )
                )
                return False, None, lock_v
            return True, None, None
