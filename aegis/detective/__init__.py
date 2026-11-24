"""Aegis Detective Mode (Clan Lynceus): Deterministic Epistemic Verification Plane.

Detects, coaches against, prevents, and resolves AI agent lies, reward hacking,
edit-after-verify stale proofs, synthetic green theater, and instruction drift
using zero LLM tokens and tamper-protected local telemetry.
"""

from __future__ import annotations

from .ast_integrity import inspect_production_theater, inspect_test_edit, inspect_unified_diff
from .baseline import (
    checkpoint_file_before_edit,
    compute_dirty_delta,
    detective_dir,
    git_snapshot,
    latest_turn_id,
    load_turn_baseline,
    start_turn_baseline,
)
from .claims import extract_claims
from .coach import get_tips
from .drift import (
    check_install_slopsquatting,
    check_spin_budget,
    check_write_drift,
    load_detective_config,
    save_detective_config,
    set_freeze_tests,
)
from .outcomes import infer_exit_code, is_test_file, is_verifier_command, parse_verifier_output, sha256_text
from .resolver import mutate_probe, undo_turn, verify_clean
from .verifier import build_truth_receipt, verify_reply

__all__ = [
    "build_truth_receipt",
    "check_install_slopsquatting",
    "check_spin_budget",
    "check_write_drift",
    "checkpoint_file_before_edit",
    "compute_dirty_delta",
    "detective_dir",
    "extract_claims",
    "get_tips",
    "git_snapshot",
    "infer_exit_code",
    "inspect_production_theater",
    "inspect_test_edit",
    "inspect_unified_diff",
    "is_test_file",
    "is_verifier_command",
    "latest_turn_id",
    "load_detective_config",
    "load_turn_baseline",
    "mutate_probe",
    "parse_verifier_output",
    "save_detective_config",
    "set_freeze_tests",
    "sha256_text",
    "start_turn_baseline",
    "undo_turn",
    "verify_clean",
    "verify_reply",
]
