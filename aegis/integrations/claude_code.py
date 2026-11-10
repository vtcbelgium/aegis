"""Claude Code (and Gemini CLI / Copilot CLI) PreToolUse + PostToolUse hook.

These hosts run a hook as a subprocess, pass the tool call as JSON on stdin, and read a JSON
decision on stdout. This adapter is thin: it reads the event, calls the shared evaluator
(aegis.integrations.generic), and prints the host's decision shape. The security logic is not
here and is not specific to any model.

Install (Claude Code ~/.claude/settings.json), covering all tools:

    {
      "hooks": {
        "PreToolUse":  [{"matcher": "*", "hooks": [{"type": "command", "command": "aegis hook"}]}],
        "PostToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "aegis hook --post"}]}]
      }
    }

PreToolUse maps Aegis verdicts to permissionDecision allow/ask/deny. PostToolUse scans the
tool's output for decoy canary tokens and feeds a block reason back if one appears.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Dict

from .generic import evaluate


def _read_event() -> Dict[str, Any]:
    try:
        raw = sys.stdin.read()
        event = json.loads(raw)
        if not isinstance(event, dict):
            raise ValueError("Hook event must be an object")
        return event
    except (ValueError, OSError) as exc:
        raise ValueError("Invalid hook input") from exc


def run_pretooluse(event: Dict[str, Any]) -> int:
    tool_name = event.get("tool_name") or ""
    tool_input = event.get("tool_input", {})
    cwd = event.get("cwd")
    session_id = event.get("session_id") or "default"
    try:
        d = evaluate(tool_name, tool_input, cwd=cwd, session_id=session_id)
    except Exception as exc:  # fail closed: ask the human rather than silently allow
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse", "permissionDecision": "deny",
            "permissionDecisionReason": f"Aegis could not evaluate this call ({type(exc).__name__})."}}))
        return 0

    reason = f"Aegis {d.level}: {d.reason}"
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": d.decision,            # allow | ask | deny
        "permissionDecisionReason": reason}}))
    return 0


def run_posttooluse(event: Dict[str, Any], fmt: str = "claude") -> int:
    """Scan tool output for a decoy canary; if found, tell the model the session is compromised."""
    from ..core import AegisGate
    from .. import session as session_store
    from ..ledger import DecisionLedger, default_ledger_path
    text = json.dumps(event.get("tool_response") or event.get("tool_output") or "")
    gate = AegisGate(ledger=DecisionLedger(default_ledger_path()))
    sid = event.get("session_id") or "default"
    with session_store.transaction(sid):
        session_store.apply_to_gate(gate, sid)
        trip = gate.minotaur.inspect_content(text) if gate.minotaur else None
        if trip is not None:
            gate.record(trip)
            gate.ledger.record(trip, tool=event.get("tool_name"), source="response")
        session_store.persist_from_gate(gate, sid)
    if trip is not None:
        if fmt != "claude":
            from .generic import HookDecision, render
            output, code = render(HookDecision("deny", "A decoy credential appeared in tool output",
                                               "LOCK", trip), fmt=fmt)
            (sys.stderr if fmt == "exit" else sys.stdout).write(output + "\n")
            return code
        print(json.dumps({"decision": "block",
                          "reason": "Aegis Minotaur: a decoy credential appeared in this tool's output. "
                                    "The session is compromised; stop and tell the owner."}))
    return 0


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    from ..cli import run_hook
    return run_hook(post="--post" in argv)


if __name__ == "__main__":
    raise SystemExit(main())
