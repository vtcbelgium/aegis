"""Context-triggered Detective Tips engine (zero filler, strictly telemetry-driven)."""

from __future__ import annotations

from typing import Any, Dict, List, Optional


def get_tips(
    detective_state: Optional[Dict[str, Any]] = None,
    findings: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, str]]:
    """Produce actionable operator tips driven by observed session telemetry and findings."""
    state = detective_state or {}
    found = findings or []
    tips: List[Dict[str, str]] = []
    seen = set()

    def add(code: str, trigger: str, tip: str) -> None:
        if code not in seen:
            seen.add(code)
            tips.append({"code": code, "trigger": trigger, "tip": tip})

    fail_streak = int(state.get("consecutiveTestFailures") or 0)
    if fail_streak >= 2:
        add(
            "PANIC_RISK",
            f"{fail_streak} consecutive failing verifier runs",
            "Failure streaks are when agents most often tamper with tests or fake green output. Enable `aegis detective freeze-tests` or ask for raw tracebacks only.",
        )

    last_edit = int(state.get("lastEditSeq") or 0)
    last_pass = int(state.get("lastPassVerifySeq") or 0)
    if last_edit > 0 and last_edit > last_pass:
        add(
            "STALE_PROOF",
            "Files edited after the last passing verification run",
            "Require a fresh test run (or `aegis detective verify-clean`) after the last edit before accepting completion.",
        )

    reads_since_write = int(state.get("readCallsSinceLastWrite") or 0)
    total_calls = int(state.get("callSeq") or 0)
    if reads_since_write >= 20 or total_calls >= 30:
        add(
            "INSTRUCTION_DRIFT",
            f"{total_calls} session calls ({reads_since_write} reads since last write)",
            "Long sessions lose adherence to early constraints. Check `aegis detective status` or compact context before more edits.",
        )

    finding_classes = {f.get("class") for f in found}
    if "D04" in finding_classes:
        add(
            "TEST_INTEGRITY",
            "Test-file modification flagged",
            "Run `aegis detective verify-clean` to replay the production diff against untouched HEAD tests, or `aegis detective mutate` to test assertion strength.",
        )
    if "D01" in finding_classes or "D02" in finding_classes or "D10" in finding_classes:
        add(
            "EVIDENCE_PROTOCOL",
            "Claim contradicted recorded execution telemetry",
            "Do not ask the agent 'are you sure?'; models double down under verbal interrogation. Demand raw command output and `git diff`, or start a fresh verifier thread.",
        )
    if "D05" in finding_classes or "D08" in finding_classes:
        add(
            "MUTATION_AUDIT",
            "Concealed mutation or reverted config detected",
            "Inspect `aegis detective report` and use `aegis detective undo` if you want to revert this turn cleanly from protected checkpoints.",
        )
    if "D06" in finding_classes:
        add(
            "ATTRIBUTION_RECEIPT",
            "Truth Box values differed from ledger/git ground truth",
            "Rely on Aegis's machine-generated `aegis.truth-receipt.v1` block instead of prose summaries.",
        )

    if not tips:
        add(
            "BASELINE_DISCIPLINE",
            "No anomalies recorded in current session",
            "Reward honest blocks explicitly in prompts ('stopping with the exact error is success') and freeze test files during bug fixes.",
        )
    return tips
