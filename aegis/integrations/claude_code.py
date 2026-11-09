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
        return json.loads(raw) if raw.strip() else {}
    except (ValueError, OSError):
        return {}


def run_pretooluse(event: Dict[str, Any]) -> int:
    tool_name = event.get("tool_name") or ""
    tool_input = event.get("tool_input") or {}
    cwd = event.get("cwd")
    session_id = event.get("session_id") or "default"
    try:
        d = evaluate(tool_name, tool_input, cwd=cwd, session_id=session_id)
    except Exception as exc:  # fail closed: ask the human rather than silently allow
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse", "permissionDecision": "ask",
            "permissionDecisionReason": f"Aegis could not evaluate this call ({type(exc).__name__}); approve manually."}}))
        return 0

    reason = f"Aegis {d.level}: {d.reason}"
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": d.decision,            # allow | ask | deny
        "permissionDecisionReason": reason}}))
    return 0


def run_posttooluse(event: Dict[str, Any]) -> int:
    """Scan tool output for a decoy canary; if found, tell the model the session is compromised."""
    from ..clans.minotaur import MinotaurClan, Tripwires
    text = json.dumps(event.get("tool_response") or event.get("tool_output") or "")
    minotaur = MinotaurClan(tripwires=Tripwires.load())
    trip = minotaur.inspect_content(text)
    if trip is not None:
        print(json.dumps({"decision": "block",
                          "reason": "Aegis Minotaur: a decoy credential appeared in this tool's output. "
                                    "The session is compromised; stop and tell the owner."}))
    return 0


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    event = _read_event()
    post = "--post" in argv or event.get("hook_event_name") == "PostToolUse"
    return run_posttooluse(event) if post else run_pretooluse(event)


if __name__ == "__main__":
    raise SystemExit(main())
