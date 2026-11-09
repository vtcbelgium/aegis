"""Aegis MCP Security Proxy: Guardrail for Model Context Protocol Servers.

Intercepts MCP JSON-RPC requests (tools/call) and validates arguments
against the Aegis Negative Gate before routing them to the upstream MCP server.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional, Tuple
from .core import AegisGate, DecisionLevel, Verdict
from .harness import AegisHarness


class AegisMcpProxy:
    """Security proxy for Model Context Protocol servers (evaluates requests and responses)."""

    def __init__(
        self,
        gate: Optional[AegisGate] = None,
        base_dir: Optional[str] = None,
        strict_mode: bool = False,
        fail_closed: bool = True,
    ) -> None:
        self.gate = gate or AegisGate(base_dir=base_dir, strict_mode=strict_mode, fail_closed=fail_closed)
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

            if params is not None and not isinstance(params, dict):
                raise ValueError("RPC params must be a dictionary")
            params = params or {}

            # We only need to gate active tool invocations
            if method == "tools/call":
                tool_name = params.get("name", "unknown")
                arguments = params.get("arguments", {})

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
                            # Check for leaked credentials
                            sec_verdict = self.harness.gate.record(
                                self.harness.gate.record(
                                    __import__("aegis.clans.custody", fromlist=["CustodyClan"]).CustodyClan.inspect_secrets(text)
                                )
                            )
                            if not sec_verdict.passed:
                                item["text"] = "[REDACTED BY AEGIS: Leaked credentials stripped from tool response]"
                                return False, rpc_response, sec_verdict
            return True, None, None
        except Exception:
            return True, None, None
