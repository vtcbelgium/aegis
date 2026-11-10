"""Aegis MCP Security Proxy: Guardrail for Model Context Protocol Servers.

Intercepts MCP JSON-RPC requests (tools/call) and validates arguments
against the Aegis Negative Gate before routing them to the upstream MCP server.
Also inspects tool responses for indirect prompt injection and leaked credentials.
"""

from __future__ import annotations

import os
import re
import secrets
from typing import Any, Callable, Dict, List, Optional, Tuple
from .core import AegisGate, DecisionLevel, Verdict
from .harness import AegisHarness
from .canonicalizer import normalize_for_matching
from .clans import CustodyClan
from .clans.custody import CRITICAL_SECRET_SIGNATURES, MILD_SECRET_SIGNATURES


# Patterns run on normalize_for_matching(text): NFKC, invisible characters removed,
# casefolded, whitespace collapsed. They catch the common phrasings; a determined attacker
# can always paraphrase, so response scanning is a redaction layer, not a guarantee.
INDIRECT_INJECTION_PATTERNS = [
    r"\b(?:ignore|disregard|forget|override|bypass|skip)\b.{0,20}\b(?:all|any|the|your|these|those)?\s*"
    r"(?:previous|prior|earlier|above|preceding|original|existing|initial)\s+"
    r"(?:instructions?|guidance|rules|directions|prompts?|context|messages|guidelines|directives)",
    r"\byour\s+(?:new|real|actual|true)\s+(?:task|instructions?|goal|objective|role|mission)\b",
    r"\bnew\s+instructions?\s*(?:follow)?\s*:",
    r"\bfrom\s+now\s+on,?\s+you\s+(?:are|will|must|should)\b",
    r"\bsystem\s+prompt\s*:",
    r"\byou\s+are\s+now\s+(?:in\s+)?(?:dan|developer|god|unrestricted|jailbreak(?:ed)?)\s*(?:mode)?\b",
    r"\b(?:call|execute|run|invoke)\s+(?:the\s+)?(?:tool|function)\s+[a-z_][a-z0-9_]*",
    r"\b(?:curl|wget|iwr|irm|invoke-webrequest)\b[^\n]{0,200}\|\s*(?:ba|z)?sh\b",
    r"\b(?:curl|wget|iwr|irm|invoke-webrequest)\b[^\n]{0,200}\|\s*iex\b",
    r"!\[[^\]]*\]\(https?://[^\s)]+[?&](?:token|cookie|auth|leak|key|session|secret|data|q)=",
    # Dutch, French, German, Spanish
    r"\bnegeer\s+(?:alle\s+)?(?:vorige|eerdere|voorgaande)\s+(?:instructies|opdrachten|regels)",
    r"\bignore[rz]?\s+(?:toutes\s+)?les\s+instructions\s+(?:pr[eé]c[eé]dentes|ant[eé]rieures)",
    r"\bignorier(?:e|en)?\s+(?:alle\s+)?(?:vorherigen|bisherigen|obigen)\s+(?:anweisungen|instruktionen)",
    r"\bignora\s+(?:todas\s+)?las\s+instrucciones\s+(?:anteriores|previas)",
]
_INJECTION_RES = [re.compile(p) for p in INDIRECT_INJECTION_PATTERNS]


class AegisMcpProxy:
    """Security proxy for Model Context Protocol servers (evaluates requests and responses)."""

    def __init__(
        self,
        gate: Optional[AegisGate] = None,
        base_dir: Optional[str] = None,
        strict_mode: bool = False,
        fail_closed: bool = True,
        owner_secret: Optional[str] = None,
        approval_callback: Optional[Callable[[Verdict], Any]] = None,
        policy: Optional[Any] = None,
        tool_pins: Optional[Any] = None,
        server_id: Optional[str] = None,
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
            approval_callback=approval_callback,
            policy=policy,
        )
        if gate is not None and approval_callback is not None:
            self.gate.approval_callback = approval_callback
        self.harness = AegisHarness(gate=self.gate, base_dir=self.gate.base_dir)
        if tool_pins is not None and not server_id:
            raise ValueError("Pinned MCP proxies require a stable server_id")
        self.tool_pins = tool_pins
        self.server_id = server_id
        self._catalogue_tools = set()

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
                if self.tool_pins is not None and tool_name not in self._catalogue_tools:
                    verdict = self.gate.record(Verdict(DecisionLevel.DENY,
                        ["Tool catalogue has not passed fingerprint verification"], "McpToolPins"))
                    return False, {"jsonrpc": "2.0", "id": request_id, "error": {
                        "code": -32000, "message": verdict.reasons[0]}}, verdict
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
                                        ("⏸ AEGIS: OWNER APPROVAL REQUIRED [ASK]: " if verdict.level == DecisionLevel.ASK
                                         else f"🛑 AEGIS NEGATIVE GATE BLOCKED [{verdict.level.name}]: ")
                                        + f"{'; '.join(verdict.reasons)}. "
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

    def _scan_text(self, text: str) -> Tuple[str, Optional[Verdict]]:
        """Return (sanitized_text, verdict_if_anything_was_redacted)."""
        if not isinstance(text, str) or not text:
            return text, None
        # A canary token in tool output means a decoy was read: LOCK the session.
        minotaur = getattr(self.gate, "minotaur", None)
        if minotaur is not None:
            trip = minotaur.inspect_content(text)
            if trip is not None:
                self.gate.record(trip)  # this one DOES escalate: the agent exfiltrated a decoy
                return "[REDACTED BY AEGIS: decoy credential — session locked]", trip
        matched = normalize_for_matching(text)
        for rx in _INJECTION_RES:
            if rx.search(matched):
                return (
                    "[REDACTED BY AEGIS: Untrusted indirect prompt injection stripped]",
                    Verdict(DecisionLevel.DENY, [f"Indirect prompt injection in tool output: {rx.pattern[:60]}"],
                            "McpResponseGuard", metadata={"source": "response"}),
                )
        sec = CustodyClan.inspect_secrets(text)
        if not sec.passed:
            masked = text
            for pattern, _label in CRITICAL_SECRET_SIGNATURES + MILD_SECRET_SIGNATURES:
                masked = re.sub(pattern, "[REDACTED SECRET]", masked)
            return masked, Verdict(sec.level, sec.reasons, "McpResponseGuard", metadata={"source": "response"})
        return text, None

    def _scan_structure(self, obj: Any, found: List[Verdict]) -> Any:
        if isinstance(obj, str):
            new, v = self._scan_text(obj)
            if v is not None:
                found.append(v)
            return new
        if isinstance(obj, dict):
            return {k: self._scan_structure(v, found) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._scan_structure(v, found) for v in obj]
        return obj

    def filter_response(self, rpc_response: Any) -> Tuple[bool, Optional[Dict[str, Any]], Optional[Verdict]]:
        """Scan tool output for indirect prompt injection and leaked credentials.

        Findings are redacted and logged but never escalate the session: the agent did not
        do anything wrong by *receiving* hostile content, and escalating would let any
        website lock the agent. Secrets are masked in place; injected text is replaced.
        """
        try:
            if not isinstance(rpc_response, dict):
                return True, None, None
            result = rpc_response.get("result")
            if not isinstance(result, dict):
                return True, None, None
            if self.tool_pins is not None and "tools" in result:
                self._catalogue_tools.clear()
                changes = self.tool_pins.check(self.server_id, result["tools"])
                if changes:
                    verdict = self.gate.record(Verdict(DecisionLevel.DENY,
                        [f"MCP tool catalogue requires owner review: {c.kind} ({c.tool})" for c in changes],
                        "McpToolPins"), escalate=False)
                    return False, {"jsonrpc": "2.0", "id": rpc_response.get("id"), "error": {
                        "code": -32000, "message": "Aegis withheld an untrusted tool catalogue"}}, verdict
                self._catalogue_tools = {tool["name"] for tool in result["tools"]}
            found: List[Verdict] = []
            content_list = result.get("content")
            if isinstance(content_list, list):
                for item in content_list:
                    if not isinstance(item, dict):
                        continue
                    if item.get("type") == "text":
                        new_text, v = self._scan_text(item.get("text", ""))
                        if v is not None:
                            item["text"] = new_text
                            found.append(v)
                    elif item.get("type") == "resource" and isinstance(item.get("resource"), dict):
                        res = item["resource"]
                        if isinstance(res.get("text"), str):
                            new_text, v = self._scan_text(res["text"])
                            if v is not None:
                                res["text"] = new_text
                                found.append(v)
            if "structuredContent" in result:
                result["structuredContent"] = self._scan_structure(result["structuredContent"], found)
            if not found:
                return True, None, None
            worst = max(found, key=lambda v: v.level)
            recorded = self.gate.record(worst, escalate=False)
            return False, rpc_response, recorded
        except Exception as exc:
            # Fail closed for the content (do not forward unscanned output) without locking the session.
            v = self.gate.record(
                Verdict(DecisionLevel.DENY, [f"Response could not be scanned and was withheld: {exc}"],
                        "McpResponseGuard", metadata={"source": "response"}),
                escalate=False,
            )
            req_id = rpc_response.get("id") if isinstance(rpc_response, dict) else None
            return False, {"jsonrpc": "2.0", "id": req_id, "result": {"isError": True, "content": [
                {"type": "text", "text": "[AEGIS: tool output withheld because it could not be scanned]"}]}}, v
