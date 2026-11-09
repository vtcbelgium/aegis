"""Aegis Harness Middleware: Interceptor for Agent Execution Harnesses.

Supports:
    - Custom Python tool-calling agents
    - LangChain / LlamaIndex Tool Callables
    - AutoGen / CrewAI / SWE-bench agent loops
    - OpenAI / Anthropic tool use interception

Usage:
    gate = AegisGate(base_dir="/safe/workspace")
    harness = AegisHarness(gate)

    @harness.protect_tool
    def execute_bash(command: str):
        ...
"""

from __future__ import annotations

import functools
from typing import Any, Callable, Dict, Optional
from .core import AegisGate, DecisionLevel, Verdict
from .clans import LabyrinthClan, TartarusClan, CustodyClan, HecatoncheiresClan


class AegisHarness:
    """Interceptor that gates tool execution in agent harnesses."""

    def __init__(self, gate: Optional[AegisGate] = None, base_dir: Optional[str] = None) -> None:
        self.gate = gate or AegisGate(base_dir=base_dir)
        self.base_dir = self.gate.base_dir
        self.hecatoncheires = HecatoncheiresClan()

    def evaluate_tool_call(self, tool_name: str, arguments: Dict[str, Any]) -> Verdict:
        """Evaluate an arbitrary tool call before it executes."""
        # 1. Check if the session is locked
        if self.gate.current_level >= DecisionLevel.LOCK:
            return Verdict(
                DecisionLevel.LOCK,
                ["Session is LOCKED due to previous security violations"],
                "HarnessGuard",
            )

        # 2. Runaway loop detection
        loop_sig = f"{tool_name}:{sorted(arguments.keys())}"
        loop_verdict = self.hecatoncheires.inspect_loop(loop_sig)
        if not loop_verdict.passed:
            return self.gate.record(loop_verdict)

        # 3. Path inspection if arguments reference files/paths
        for key in ("path", "file_path", "filename", "target", "dir"):
            if key in arguments and isinstance(arguments[key], str):
                path_verdict = LabyrinthClan.inspect_path(arguments[key], base_dir=self.base_dir)
                if not path_verdict.passed:
                    return self.gate.record(path_verdict)

        # 4. Command inspection for bash/shell execution tools
        for key in ("command", "cmd", "script", "bash", "shell"):
            if key in arguments and isinstance(arguments[key], str):
                cmd_verdict = TartarusClan.inspect_command(arguments[key])
                if not cmd_verdict.passed:
                    return self.gate.record(cmd_verdict)

        # 5. SQL inspection for database tools
        for key in ("query", "sql"):
            if key in arguments and isinstance(arguments[key], str):
                sql_verdict = TartarusClan.inspect_sql(arguments[key])
                if not sql_verdict.passed:
                    return self.gate.record(sql_verdict)

        # 6. URL inspection for HTTP/browse tools
        for key in ("url", "uri", "endpoint"):
            if key in arguments and isinstance(arguments[key], str):
                url_verdict = CustodyClan.inspect_url(arguments[key])
                if not url_verdict.passed:
                    return self.gate.record(url_verdict)

        # 7. Secrets inspection in content writes
        for key in ("content", "body", "data", "patch"):
            if key in arguments and isinstance(arguments[key], str):
                sec_verdict = CustodyClan.inspect_secrets(arguments[key])
                if not sec_verdict.passed:
                    return self.gate.record(sec_verdict)

        # All clans satisfied -> Zero authority added
        return self.gate.record(Verdict(DecisionLevel.PASS, ["Tool call verified safe"], "AegisHarness"))

    def protect_tool(self, func: Callable[..., Any]) -> Callable[..., Any]:
        """Decorator for Python tool functions to enforce Aegis negative gating."""
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            tool_name = func.__name__
            # Synthesize arguments dictionary
            call_kwargs = dict(kwargs)
            verdict = self.evaluate_tool_call(tool_name, call_kwargs)
            if not verdict.passed:
                raise PermissionError(
                    f"Aegis Gate {verdict.level.name}: {'; '.join(verdict.reasons)}"
                )
            return func(*args, **kwargs)
        return wrapper
