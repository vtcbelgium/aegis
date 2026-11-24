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
    """Build a policy from defaults -> ~/.aegis/policy.json -> AEGIS_* environment variables.

    Supported env overrides:
    AEGIS_PROJECT_EXEC, AEGIS_SECRET_LEVEL, AEGIS_LEAK_GUARD, AEGIS_CODE_AUDIT,
    AEGIS_UNKNOWN_BINARY, AEGIS_EXTRA_ROOTS (os.pathsep-separated), AEGIS_STRICT_TOOLS,
    AEGIS_INLINE_EXEC.
    """
    from ..config import build_policy_from_sources
    return build_policy_from_sources(workspace=workspace)


def _decision_for(level: DecisionLevel) -> str:
    if level <= DecisionLevel.WARN:
        return "allow"
    if level == DecisionLevel.ASK:
        return "ask"
    return "deny"


def _extract_target_path(args: Dict[str, Any]) -> Optional[str]:
    for key in ("path", "file_path", "target", "destination"):
        val = args.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return None


def evaluate(tool_name: str, tool_input: Any, *, cwd: Optional[str] = None,
             session_id: str = "default", policy: Optional[AegisPolicy] = None,
             ledger: bool = True) -> HookDecision:
    """Evaluate one tool call. Process-safe: rehydrates and persists gate, Hecatoncheires & Detective state."""
    from .. import session as session_store
    from ..detective import (
        check_install_slopsquatting,
        check_write_drift,
        checkpoint_file_before_edit,
        is_test_file,
        load_detective_config,
        start_turn_baseline,
    )

    workspace = cwd or os.getcwd()
    pol = policy or load_policy(workspace)
    led = DecisionLedger(default_ledger_path()) if ledger else None
    gate = AegisGate(base_dir=workspace, policy=pol, ledger=led)
    if not isinstance(tool_name, str) or not tool_name.strip() or not isinstance(tool_input, dict):
        raise ValueError("Tool name and object arguments are required")
    harness = AegisHarness(gate)
    det_cfg = load_detective_config()
    with session_store.transaction(session_id):
        det_state = session_store.apply_to_harness(harness, session_id)
        name, args = normalize(tool_name, tool_input)
        verdict = harness.evaluate_tool_call(name, args)

        # Detective Mode (Clan Lynceus) pre-execution tracking & deterministic guards
        if det_cfg.get("mode", "passive") != "off":
            seq = int(det_state.get("callSeq") or 0) + 1
            det_state["callSeq"] = seq
            if not det_state.get("turnId"):
                base_rec = start_turn_baseline(workspace, session_id=session_id)
                det_state["turnId"] = base_rec["turnId"]

            target_path = _extract_target_path(args)
            if name in ("write_file", "edit_block", "move_file", "create_directory") and target_path:
                abs_t = target_path if os.path.isabs(target_path) else os.path.join(workspace, target_path)
                drift_hits = check_write_drift(abs_t, det_state, det_cfg)
                for hit in drift_hits:
                    sev = L.DENY if hit["severity"] == "DENY" else (L.ASK if hit["severity"] == "ASK" else L.WARN)
                    if sev > verdict.level:
                        verdict = gate.record(Verdict(sev, [hit["detail"]], "Lynceus", metadata={"detective": hit}))
                if verdict.level <= L.WARN:
                    checkpoint_file_before_edit(det_state["turnId"], abs_t)
                    ever = list(det_state.get("everMutated") or [])
                    if abs_t not in ever:
                        ever.append(abs_t)
                    det_state["everMutated"] = ever[-200:]
                    direct = list(det_state.get("directEdits") or [])
                    rel_t = os.path.relpath(abs_t, workspace).replace("\\", "/") if abs_t.startswith(workspace) else abs_t
                    if rel_t not in direct:
                        direct.append(rel_t)
                    det_state["directEdits"] = direct[-200:]
                    det_state["lastEditSeq"] = seq
                    det_state["readCallsSinceLastWrite"] = 0
                    if not is_test_file(abs_t):
                        det_state["prodEditsSinceLastFail"] = int(det_state.get("prodEditsSinceLastFail") or 0) + 1
            elif name in ("read_file", "read_multiple_files", "search", "list_directory", "get_file_info"):
                det_state["readCallsSinceLastWrite"] = int(det_state.get("readCallsSinceLastWrite") or 0) + 1
                if target_path:
                    fread = list(det_state.get("filesRead") or [])
                    if target_path not in fread:
                        fread.append(target_path)
                    det_state["filesRead"] = fread[-200:]
            elif name == "start_process" and isinstance(args.get("command"), str):
                slop_hits = check_install_slopsquatting(args["command"], workspace=workspace)
                for hit in slop_hits:
                    if L.ASK > verdict.level:
                        verdict = gate.record(Verdict(L.ASK, [hit["detail"]], "Lynceus", metadata={"detective": hit}))

        session_store.persist_from_harness(harness, session_id, detective_state=det_state)
    decision = _decision_for(verdict.level)
    reason = "; ".join(verdict.reasons) if verdict.reasons else verdict.level.name
    return HookDecision(decision, reason, verdict.level.name, verdict)


def evaluate_post(
    tool_name: str,
    tool_input: Any,
    tool_response: Any,
    *,
    cwd: Optional[str] = None,
    session_id: str = "default",
    exit_code: Optional[int] = None,
    call_id: Optional[str] = None,
    ledger: bool = True,
) -> Dict[str, Any]:
    """Record paired PostToolUse execution outcome and update Detective turn state."""
    import json as _json
    from .. import session as session_store
    from ..detective import (
        git_snapshot,
        infer_exit_code,
        load_detective_config,
        parse_verifier_output,
        sha256_text,
    )

    workspace = cwd or os.getcwd()
    det_cfg = load_detective_config()
    if det_cfg.get("mode", "passive") == "off":
        return {"recorded": False, "mode": "off"}

    name, args = normalize(tool_name, tool_input if isinstance(tool_input, dict) else {})
    raw_text = tool_response if isinstance(tool_response, str) else _json.dumps(tool_response or "", default=str)
    command = str(args.get("command") or "") if isinstance(args, dict) else ""
    rc = exit_code if exit_code is not None else infer_exit_code({"tool_response": tool_response}, raw_text)
    ver_summary = parse_verifier_output(command, raw_text, exit_code=rc) if (command or name == "start_process") else None

    led = DecisionLedger(default_ledger_path()) if ledger else None
    gate = AegisGate(base_dir=workspace, ledger=led)
    harness = AegisHarness(gate)
    with session_store.transaction(session_id):
        det_state = session_store.apply_to_harness(harness, session_id)
        seq = int(det_state.get("callSeq") or 0) + 1
        det_state["callSeq"] = seq
        turn_id = det_state.get("turnId")
        if ver_summary and ver_summary.get("isVerifier"):
            det_state["lastVerifier"] = ver_summary
            if ver_summary.get("ok"):
                det_state["lastPassVerifySeq"] = seq
                det_state["consecutiveTestFailures"] = 0
                det_state["testFailureArmed"] = False
            else:
                det_state["consecutiveTestFailures"] = int(det_state.get("consecutiveTestFailures") or 0) + 1
                det_state["testFailureArmed"] = True
                det_state["prodEditsSinceLastFail"] = 0
        if led is not None:
            snap = git_snapshot(workspace)
            led.record_outcome(
                tool=name,
                call_id=call_id,
                turn_id=turn_id,
                exit_code=ver_summary["exitCode"] if ver_summary else rc,
                stdout_digest=sha256_text(raw_text),
                verifier_summary=ver_summary if (ver_summary and ver_summary.get("isVerifier")) else None,
                git_tree_digest=snap.get("treeDigest"),
                command=command or None,
            )
        session_store.persist_from_harness(harness, session_id, detective_state=det_state)
    return {"recorded": True, "verifier": ver_summary, "callSeq": seq}


def evaluate_stop(
    reply_text: str,
    *,
    cwd: Optional[str] = None,
    session_id: str = "default",
    mode: Optional[str] = None,
) -> Dict[str, Any]:
    """Cross-examine a draft final reply against recorded session telemetry before delivery."""
    from .. import session as session_store
    from ..detective import verify_reply

    workspace = cwd or os.getcwd()
    led = DecisionLedger(default_ledger_path())
    verify_res = led.verify()
    with session_store.transaction(session_id):
        data = session_store.load(session_id)
        det_state = data.get("detective") if isinstance(data.get("detective"), dict) else {}
    return verify_reply(
        reply_text,
        cwd=workspace,
        detective_state=det_state,
        mode=mode,
        ledger_tip=verify_res.tip if verify_res.ok else None,
    )


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
