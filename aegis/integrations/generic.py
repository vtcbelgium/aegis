"""The reusable, process-safe evaluator every hook adapter uses.

Given a tool call in a neutral form — tool name, arguments, working directory, session id —
it builds a gate (ledger + Minotaur), rehydrates the session so a LOCK stays locked across
processes, evaluates, persists, and returns a decision. It knows nothing about any model.

Host tool names are normalised to Aegis's schema where known (so Claude Code's `Bash`, Gemini
CLI's `run_shell_command`, etc. all reach the shell analyzer); any unknown tool still has its
arguments walked and every path/URL/command-looking string checked.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from ..core import AegisGate, DecisionLevel, Verdict
from ..harness import AegisHarness
from ..ledger import DecisionLedger, default_ledger_path
from ..policy import AegisPolicy

L = DecisionLevel

# Map common host tool names -> (aegis schema tool, {host arg: aegis arg}).
# Unlisted tools pass through unchanged; the harness classifies their arguments by name.
_TOOL_MAP: Dict[str, Tuple[str, Dict[str, str]]] = {
    # Claude Code
    "bash": ("start_process", {"command": "command"}),
    "read": ("read_file", {"file_path": "path"}),
    "write": ("write_file", {"file_path": "path", "content": "content"}),
    "edit": ("edit_block", {"file_path": "file_path", "old_string": "old_string", "new_string": "new_string"}),
    "multiedit": ("edit_block", {"file_path": "file_path"}),
    "glob": ("search", {"path": "path", "pattern": "pattern"}),
    "grep": ("search", {"path": "path", "pattern": "pattern"}),
    "notebookedit": ("edit_block", {"notebook_path": "file_path", "new_source": "new_string"}),
    "webfetch": ("fetch_url", {"url": "url"}),
    "websearch": ("websearch", {}),
    # Gemini CLI / others
    "run_shell_command": ("start_process", {"command": "command"}),
    "read_file": ("read_file", {"path": "path", "file_path": "path", "absolute_path": "path"}),
    "write_file": ("write_file", {"path": "path", "file_path": "path", "content": "content"}),
    "replace": ("edit_block", {"file_path": "file_path"}),
    "run_terminal_cmd": ("start_process", {"command": "command"}),
}


@dataclass
class HookDecision:
    decision: str            # "allow", "ask", "deny"
    reason: str
    level: str
    verdict: Verdict

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"


def normalize(tool_name: str, tool_input: Any) -> Tuple[str, Dict[str, Any]]:
    args = dict(tool_input) if isinstance(tool_input, dict) else {"__arg__": tool_input}
    mapped = _TOOL_MAP.get((tool_name or "").lower())
    if not mapped:
        return tool_name or "unknown_tool", args
    schema_name, keymap = mapped
    if not keymap:
        return schema_name, args
    out: Dict[str, Any] = {}
    for host_key, val in args.items():
        out[keymap.get(host_key, host_key)] = val
    return schema_name, out


def load_policy(workspace: Optional[str] = None) -> AegisPolicy:
    """Build a policy from environment variables, so any host can configure Aegis the same way.

    AEGIS_PROJECT_EXEC, AEGIS_SECRET_LEVEL, AEGIS_LEAK_GUARD, AEGIS_CODE_AUDIT,
    AEGIS_UNKNOWN_BINARY, AEGIS_EXTRA_ROOTS (os.pathsep-separated), AEGIS_STRICT_TOOLS.
    """
    env = os.environ.get
    roots = [r for r in (env("AEGIS_EXTRA_ROOTS", "") or "").split(os.pathsep) if r]
    pol = AegisPolicy(
        project_exec=env("AEGIS_PROJECT_EXEC", "allow"),
        secret_level=env("AEGIS_SECRET_LEVEL", "lock"),
        leak_guard=env("AEGIS_LEAK_GUARD", "ask"),
        code_audit=env("AEGIS_CODE_AUDIT", "warn"),
        unknown_binary=env("AEGIS_UNKNOWN_BINARY", "ask"),
        strict_tools=(env("AEGIS_STRICT_TOOLS", "") or "").lower() in ("1", "true", "yes"),
        extra_roots=roots,
    )
    return pol


def _decision_for(level: DecisionLevel) -> str:
    if level <= DecisionLevel.WARN:
        return "allow"
    if level == DecisionLevel.ASK:
        return "ask"
    return "deny"


def evaluate(tool_name: str, tool_input: Any, *, cwd: Optional[str] = None,
             session_id: str = "default", policy: Optional[AegisPolicy] = None,
             ledger: bool = True) -> HookDecision:
    """Evaluate one tool call. Process-safe: rehydrates and persists session state."""
    from .. import session as session_store

    workspace = cwd or os.getcwd()
    pol = policy or load_policy(workspace)
    led = DecisionLedger(default_ledger_path(), min_level=DecisionLevel.ASK) if ledger else None
    gate = AegisGate(base_dir=workspace, policy=pol, ledger=led)
    session_store.apply_to_gate(gate, session_id)

    name, args = normalize(tool_name, tool_input)
    # A plain web fetch: judge the URL through the command path's URL check.
    if name == "fetch_url" and isinstance(args.get("url"), str):
        verdict = AegisHarness(gate).evaluate_tool_call("start_process", {"command": f"curl {args['url']}"})
    elif name == "websearch":
        verdict = Verdict(DecisionLevel.PASS, ["web search"], "AegisHarness")
    else:
        verdict = AegisHarness(gate).evaluate_tool_call(name, args)

    session_store.persist_from_gate(gate, session_id)
    decision = _decision_for(verdict.level)
    reason = "; ".join(verdict.reasons) if verdict.reasons else verdict.level.name
    return HookDecision(decision, reason, verdict.level.name, verdict)


def render(d: "HookDecision", fmt: str = "claude", event_name: str = "PreToolUse") -> Tuple[str, int]:
    """Turn a decision into (stdout, exit_code) in one of three vendor shapes.

    - claude : {"hookSpecificOutput": {...}} — Claude Code, Gemini CLI, Copilot CLI (same shape).
    - json   : {"decision","reason","level"} — any custom integration that reads stdout.
    - exit   : exit code only (0 allow, 2 block) with the reason on stderr — the lowest common
               denominator, works with any agent that honours a hook's exit code.
    """
    import json as _json
    reason = f"Aegis {d.level}: {d.reason}"
    if fmt == "json":
        return _json.dumps({"decision": d.decision, "reason": reason, "level": d.level}), 0
    if fmt == "exit":
        # exit mode cannot express "ask", so a non-allow decision blocks and explains why.
        return ("" if d.allowed else reason), (0 if d.allowed else 2)
    return _json.dumps({"hookSpecificOutput": {
        "hookEventName": event_name,
        "permissionDecision": d.decision,
        "permissionDecisionReason": reason}}), 0
