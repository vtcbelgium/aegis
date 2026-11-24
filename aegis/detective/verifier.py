"""Deterministic Claim-to-Evidence Cross-Examiner (D01-D10) & Truth Receipt Generator."""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from .baseline import compute_dirty_delta, latest_turn_id, load_turn_baseline
from .claims import extract_claims
from .coach import get_tips
from .drift import load_detective_config

_SENSITIVE_SWAP_NAMES = (
    "crews.json",
    "policy.json",
    "verify_local.py",
    "conftest.py",
)


def _git_sha_exists(repo_root: str, sha: str) -> Optional[bool]:
    try:
        res = subprocess.run(
            ["git", "-C", repo_root, "cat-file", "-e", f"{sha}^{{commit}}"],
            capture_output=True,
            timeout=3,
            check=False,
        )
        return res.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return None


def _count_file_lines(path: Path) -> Optional[int]:
    try:
        with path.open("rb") as fh:
            return sum(1 for _ in fh)
    except OSError:
        return None


def build_truth_receipt(
    *,
    detective_state: Dict[str, Any],
    dirty_delta: Dict[str, Any],
    ledger_tip: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a deterministic, machine-verified truth summary (aegis.truth-receipt.v1)."""
    direct_edits = sorted(set(detective_state.get("directEdits") or []) | set(dirty_delta.get("newlyDirty") or []))
    last_ver = detective_state.get("lastVerifier") or {}
    receipt = {
        "schema": "aegis.truth-receipt.v1",
        "generatedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "directFileEditCount": len(direct_edits),
        "directFileEdits": direct_edits,
        "lastVerifier": {
            "runner": last_ver.get("runner"),
            "exitCode": last_ver.get("exitCode"),
            "ok": last_ver.get("ok"),
            "passed": last_ver.get("passed"),
            "failed": last_ver.get("failed"),
            "winningChamber": last_ver.get("winningChamber"),
            "prUrl": last_ver.get("prUrl"),
        } if last_ver else None,
        "editedAfterLastPass": bool(
            int(detective_state.get("lastEditSeq") or 0) > int(detective_state.get("lastPassVerifySeq") or 0)
            and int(detective_state.get("lastEditSeq") or 0) > 0
        ),
        "gitTreeDigest": dirty_delta.get("treeDigest"),
        "ledgerTip": ledger_tip,
    }
    receipt["receiptDigest"] = hashlib.sha256(
        json.dumps(receipt, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()
    return receipt


def verify_reply(
    reply_text: str,
    *,
    cwd: Optional[str] = None,
    detective_state: Optional[Dict[str, Any]] = None,
    baseline: Optional[Dict[str, Any]] = None,
    mode: Optional[str] = None,
    ledger_tip: Optional[str] = None,
    allow_git_subprocess: bool = True,
) -> Dict[str, Any]:
    """Cross-examine a draft agent reply against recorded PostToolUse telemetry and live disk/git state."""
    workspace = os.path.abspath(cwd or os.getcwd())
    state = detective_state or {}
    cfg = load_detective_config()
    eff_mode = (mode or cfg.get("mode") or "passive").lower()

    if baseline is None:
        tid = state.get("turnId") or latest_turn_id()
        baseline = load_turn_baseline(tid) if tid else None

    claims = extract_claims(reply_text)
    dirty_delta = compute_dirty_delta(baseline, workspace, allow_subprocess=allow_git_subprocess)
    findings: List[Dict[str, Any]] = []

    last_ver = state.get("lastVerifier")
    last_edit_seq = int(state.get("lastEditSeq") or 0)
    last_pass_seq = int(state.get("lastPassVerifySeq") or 0)

    # D01, D02, D03 — Verification claims vs. recorded PostToolUse outcomes
    if claims["claimsPassing"] and not claims["honestBlock"]:
        if not last_ver:
            findings.append({
                "class": "D01",
                "code": "PHANTOM_VERIFICATION",
                "severity": "DENY",
                "detail": f"Reply claims passing verification ({claims['passPhrases'][0]!r}), but no verifier outcome was recorded in this turn.",
            })
        else:
            if last_ver.get("ok") is False or (last_ver.get("exitCode") not in (None, 0)) or ((last_ver.get("failed") or 0) > 0):
                findings.append({
                    "class": "D02",
                    "code": "FALSE_SUCCESS",
                    "severity": "DENY",
                    "detail": (
                        f"Outcome inversion: reply claims pass ({claims['passPhrases'][0]!r}), "
                        f"but last verifier exited {last_ver.get('exitCode')} (failed={last_ver.get('failed')})."
                    ),
                })
            elif last_edit_seq > last_pass_seq:
                findings.append({
                    "class": "D03",
                    "code": "EDIT_AFTER_VERIFY",
                    "severity": "DENY",
                    "detail": "Files were edited after the last passing verification run; re-verify before reporting pass.",
                })
            recorded_passed = last_ver.get("passed")
            if isinstance(recorded_passed, int) and claims["claimedPassedCounts"]:
                if all(c != recorded_passed for c in claims["claimedPassedCounts"]):
                    findings.append({
                        "class": "D02",
                        "code": "COUNT_MISMATCH",
                        "severity": "DENY",
                        "detail": f"Reply claimed {claims['claimedPassedCounts']} passed, but recorded verifier output showed {recorded_passed} passed.",
                    })

    # D05 — State-Swap / Snapshot Gaming (file mutated during turn then vanished from final diff)
    ever_mutated = set(str(p).replace("\\", "/") for p in (state.get("everMutated") or []))
    final_dirty = set(dirty_delta.get("allDirty") or [])
    for mut in sorted(ever_mutated):
        rel = mut
        if os.path.isabs(mut) and dirty_delta.get("root"):
            try:
                rel = os.path.relpath(mut, dirty_delta["root"]).replace("\\", "/")
            except ValueError:
                rel = mut
        if rel not in final_dirty and any(name in rel.lower() for name in _SENSITIVE_SWAP_NAMES):
            findings.append({
                "class": "D05",
                "code": "STATE_SWAP_GAMING",
                "severity": "LOCK",
                "file": rel,
                "detail": f"Sensitive file '{rel}' was mutated during the turn and reverted before completion.",
            })

    # D06 — Semantic Truth Box Auditor (verify values, not just headings)
    tb = claims.get("truthBox")
    if tb:
        expected_direct = len(set(state.get("directEdits") or []) | set(dirty_delta.get("newlyDirty") or []))
        direct_line = tb.get("directEdits") or ""
        m_num = re.match(r"^(\d+)\b", direct_line)
        if m_num and expected_direct > 0 and int(m_num.group(1)) == 0:
            findings.append({
                "class": "D06",
                "code": "TRUTH_BOX_DIRECT_EDIT_LIE",
                "severity": "DENY",
                "detail": f"Truth Box claimed 0 direct file edits, but {expected_direct} file(s) changed during this turn.",
            })
        recorded_chamber = (last_ver or {}).get("winningChamber")
        claimed_chamber = tb.get("winningChamber")
        if recorded_chamber and claimed_chamber and recorded_chamber.lower() not in claimed_chamber.lower():
            findings.append({
                "class": "D06",
                "code": "TRUTH_BOX_CHAMBER_MISMATCH",
                "severity": "DENY",
                "detail": f"Truth Box claimed chamber '{claimed_chamber}', but Forge receipt recorded '{recorded_chamber}'.",
            })

    # D08 — Omission of newly dirty workspace files
    low_reply = (reply_text or "").lower()
    undisclosed = []
    for rel in dirty_delta.get("newlyDirty") or []:
        base = os.path.basename(rel).lower()
        if rel.lower() not in low_reply and base not in low_reply:
            undisclosed.append(rel)
    if undisclosed and (claims["claimsPassing"] or tb is not None):
        findings.append({
            "class": "D08",
            "code": "UNDISCLOSED_DIRTY_FILES",
            "severity": "WARN",
            "files": undisclosed[:10],
            "detail": f"{len(undisclosed)} modified/new file(s) not mentioned in reply: {', '.join(undisclosed[:5])}.",
        })

    # D09 — Grounded Citations (file existence, line count bounds, git SHAs)
    repo_root = dirty_delta.get("root") or workspace
    for ref in claims["fileRefs"]:
        raw = ref["path"]
        cand = Path(raw) if os.path.isabs(raw) else (Path(repo_root) / raw)
        if not cand.exists():
            # Only flag explicit file:// URIs or paths containing a directory separator to avoid false positives on examples
            if ref["kind"] == "uri" or "/" in raw or "\\" in raw:
                findings.append({
                    "class": "D09",
                    "code": "PHANTOM_FILE_CITATION",
                    "severity": "DENY",
                    "file": raw,
                    "detail": f"Cited path '{raw}' does not exist on disk.",
                })
        elif ref["startLine"] is not None and cand.is_file():
            total_lines = _count_file_lines(cand)
            if total_lines is not None and ref["startLine"] > total_lines:
                findings.append({
                    "class": "D09",
                    "code": "PHANTOM_LINE_CITATION",
                    "severity": "DENY",
                    "file": raw,
                    "detail": f"Cited line {ref['startLine']} in '{raw}', which only has {total_lines} line(s).",
                })

    if dirty_delta.get("isGit") and dirty_delta.get("root"):
        for sha in claims["commitShas"]:
            exists = _git_sha_exists(dirty_delta["root"], sha)
            if exists is False:
                findings.append({
                    "class": "D09",
                    "code": "PHANTOM_COMMIT_SHA",
                    "severity": "DENY",
                    "sha": sha,
                    "detail": f"Cited git commit SHA '{sha}' does not exist in repository history.",
                })

    # D10 — Impossibility Lies (claiming rollback is impossible when git / checkpoints exist)
    if claims["impossibilityClaims"]:
        has_recovery = bool(dirty_delta.get("isGit") or baseline is not None)
        if has_recovery:
            findings.append({
                "class": "D10",
                "code": "FALSE_IMPOSSIBILITY_CLAIM",
                "severity": "WARN",
                "detail": (
                    f"Reply claimed {claims['impossibilityClaims'][0]!r}, "
                    "but git history or an Aegis Detective turn checkpoint is available for recovery."
                ),
            })

    has_blocking = any(f.get("severity") in ("DENY", "LOCK") for f in findings)
    decision = "block" if (has_blocking and eff_mode == "strict") else ("warn" if findings else "allow")
    verdict = "LOCK" if any(f.get("severity") == "LOCK" for f in findings) else ("DENY" if has_blocking else ("WARN" if findings else "PASS"))
    receipt = build_truth_receipt(detective_state=state, dirty_delta=dirty_delta, ledger_tip=ledger_tip)
    tips = get_tips(state, findings)

    return {
        "schema": "aegis.detective.warrant.v1",
        "passed": not has_blocking,
        "mode": eff_mode,
        "decision": decision,
        "verdict": verdict,
        "findingCount": len(findings),
        "findings": findings,
        "claims": claims,
        "dirtyDelta": dirty_delta,
        "truthReceipt": receipt,
        "tips": tips,
    }
