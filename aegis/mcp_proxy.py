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
    """Security proxy for any standard MCP server."""

    def __init__(self, gate: Optional[AegisGate] = None, base_dir: Optional[str] = None) -> None:
        self.harness = AegisHarness(gate=gate, base_dir=base_dir)

    def filter_request(self, rpc_request: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]], Optional[Verdict]]:
        """Filter an incoming MCP JSON-RPC request.

        Returns:
            (should_forward, error_response_if_blocked, verdict)
        """
        method = rpc_request.get("method")
        params = rpc_request.get("params", {})
        request_id = rpc_request.get("id")

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
