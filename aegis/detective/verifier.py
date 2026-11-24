"""Deterministic Claim-to-Evidence Cross-Examiner (D01-D11) & Truth Receipt Generator."""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

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


def _resolve_json_targets(data: Any, field_path: str, *, filter_field: Optional[str] = None, filter_value: Any = None) -> List[tuple[str, Any]]:
    """Resolve a dotted JSON field path supporting one wildcard list segment (e.g. 'crews.*.engine')."""
    parts = [p for p in str(field_path or "").split(".") if p]
    if not parts:
        return [("", data)]
    cur: List[tuple[str, Any]] = [("", data)]
    for idx, part in enumerate(parts):
        nxt: List[tuple[str, Any]] = []
        for prefix, obj in cur:
            if part == "*":
                if not isinstance(obj, list):
                    return []
                for i, item in enumerate(obj):
                    if filter_field is not None:
                        if not isinstance(item, dict) or item.get(filter_field) != filter_value:
                            continue
                    label = str(item.get("id") or i) if isinstance(item, dict) else str(i)
                    nxt.append((f"{prefix}[{label}]" if prefix else f"[{label}]", item))
            elif isinstance(obj, dict) and part in obj:
                nxt.append((f"{prefix}.{part}" if prefix else part, obj[part]))
            else:
                # Missing key -> record sentinel so callers treat missing field as mismatch, never silent pass
                nxt.append((f"{prefix}.{part}" if prefix else part, None))
        cur = nxt
    return cur


def verify_production_path(probes: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """Deterministically evaluate active runtime/deployment probes (tri-state: PASS | FAIL | UNKNOWN).

    Enforces strict R0 semantics:
      - Missing or unreadable evidence yields UNKNOWN (never PASS).
      - Any required FAIL -> overall FAIL.
      - Any required UNKNOWN (with no FAIL) -> overall UNKNOWN.
      - Overall PASS requires >=1 probe and every required probe == PASS.
    """
    results: List[Dict[str, Any]] = []
    for idx, spec in enumerate(probes or ()):
        if not isinstance(spec, dict):
            results.append({
                "id": f"probe_{idx}",
                "kind": "invalid",
                "required": True,
                "status": "UNKNOWN",
                "detail": "Probe spec is not a dictionary.",
                "mismatches": [],
            })
            continue
        pid = str(spec.get("id") or f"probe_{idx}")
        kind = str(spec.get("kind") or "observed").strip().lower()
        required = bool(spec.get("required", True))

        if kind == "observed":
            raw_status = str(spec.get("status") or "UNKNOWN").strip().upper()
            status = raw_status if raw_status in ("PASS", "FAIL", "UNKNOWN") else "UNKNOWN"
            results.append({
                "id": pid,
                "kind": kind,
                "required": required,
                "status": status,
                "detail": str(spec.get("detail") or f"Observed status: {status}"),
                "mismatches": list(spec.get("mismatches") or []),
            })
            continue

        if kind == "json_field":
            raw_path = spec.get("path")
            if not raw_path:
                results.append({"id": pid, "kind": kind, "required": required, "status": "UNKNOWN", "detail": "No config path supplied.", "mismatches": []})
                continue
            p = Path(str(raw_path))
            if not p.is_file():
                results.append({"id": pid, "kind": kind, "required": required, "status": "FAIL", "detail": f"Active runtime config not found: {p}", "mismatches": [str(p)]})
                continue
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                results.append({"id": pid, "kind": kind, "required": required, "status": "FAIL", "detail": f"Unreadable JSON config {p}: {exc}", "mismatches": [str(p)]})
                continue
            targets = _resolve_json_targets(
                data,
                str(spec.get("fieldPath") or ""),
                filter_field=spec.get("filterField"),
                filter_value=spec.get("filterValue"),
            )
            if not targets:
                results.append({
                    "id": pid,
                    "kind": kind,
                    "required": required,
                    "status": "UNKNOWN" if spec.get("allowEmpty") else "FAIL",
                    "detail": f"No matching entries found for {spec.get('fieldPath')!r} in {p.name}.",
                    "mismatches": [],
                })
                continue
            has_expected = "expected" in spec and spec.get("expected") is not None
            expected = spec.get("expected")
            forbidden = set(spec.get("forbidden") or [])
            mismatches: List[str] = []
            for label, val in targets:
                if val in forbidden:
                    mismatches.append(f"{label}={val!r} (forbidden)")
                elif has_expected and val != expected:
                    mismatches.append(f"{label}={val!r} (expected {expected!r})")
            status = "FAIL" if mismatches else "PASS"
            detail = (
                f"{len(mismatches)}/{len(targets)} active entries failed {spec.get('fieldPath')!r}: {', '.join(mismatches[:5])}"
                if mismatches
                else f"Verified {len(targets)} active entry/entries in {p.name}."
            )
            results.append({"id": pid, "kind": kind, "required": required, "status": status, "detail": detail, "mismatches": mismatches})
            continue

        if kind == "config_parity":
            t_path = Path(str(spec.get("templatePath") or ""))
            r_path = Path(str(spec.get("runtimePath") or ""))
            if not t_path.is_file() or not r_path.is_file():
                missing = [str(x) for x in (t_path, r_path) if not x.is_file()]
                results.append({"id": pid, "kind": kind, "required": required, "status": "FAIL", "detail": f"Missing config file(s): {', '.join(missing)}", "mismatches": missing})
                continue
            try:
                t_data = json.loads(t_path.read_text(encoding="utf-8"))
                r_data = json.loads(r_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                results.append({"id": pid, "kind": kind, "required": required, "status": "FAIL", "detail": f"JSON parse error: {exc}", "mismatches": []})
                continue
            list_key = str(spec.get("listKey") or "crews")
            id_key = str(spec.get("idKey") or "id")
            field = str(spec.get("field") or "engine")
            filter_field = spec.get("filterField")
            filter_value = spec.get("filterValue")
            t_map = {str(item.get(id_key)): item for item in (t_data.get(list_key) or []) if isinstance(item, dict) and item.get(id_key)}
            r_items = [item for item in (r_data.get(list_key) or []) if isinstance(item, dict)]
            mismatches = []
            checked = 0
            for item in r_items:
                if filter_field is not None and item.get(filter_field) != filter_value:
                    continue
                ident = str(item.get(id_key) or "")
                if ident not in t_map:
                    continue
                checked += 1
                exp_val = t_map[ident].get(field)
                act_val = item.get(field)
                if act_val != exp_val:
                    mismatches.append(f"{ident}.{field}={act_val!r} (template {exp_val!r})")
            if checked == 0:
                status = "UNKNOWN"
                detail = f"No overlapping entries compared between {t_path.name} and {r_path.name}."
            else:
                status = "FAIL" if mismatches else "PASS"
                detail = (
                    f"{len(mismatches)}/{checked} runtime parity drift(s): {', '.join(mismatches[:5])}"
                    if mismatches
                    else f"{checked}/{checked} active entries match committed {t_path.name} on '{field}'."
                )
            results.append({"id": pid, "kind": kind, "required": required, "status": status, "detail": detail, "mismatches": mismatches})
            continue

        if kind == "file_freshness":
            raw_path = spec.get("path")
            max_age = float(spec.get("maxAgeSeconds", 86400))
            now_epoch = float(spec.get("nowEpoch") if spec.get("nowEpoch") is not None else time.time())
            p = Path(str(raw_path or ""))
            if not raw_path or not p.is_file():
                results.append({"id": pid, "kind": kind, "required": required, "status": "UNKNOWN", "detail": f"State file absent: {raw_path}", "mismatches": []})
                continue
            age = max(0.0, now_epoch - p.stat().st_mtime)
            status = "PASS" if age <= max_age else "FAIL"
            results.append({
                "id": pid,
                "kind": kind,
                "required": required,
                "status": status,
                "detail": f"{p.name} age={int(age)}s (max {int(max_age)}s).",
                "mismatches": [] if status == "PASS" else [f"{p.name}:age={int(age)}s>{int(max_age)}s"],
            })
            continue

        results.append({
            "id": pid,
            "kind": kind,
            "required": required,
            "status": "UNKNOWN",
            "detail": f"Unsupported production-path probe kind: {kind}",
            "mismatches": [],
        })

    required_results = [r for r in results if r["required"]]
    pass_count = sum(1 for r in results if r["status"] == "PASS")
    fail_count = sum(1 for r in results if r["status"] == "FAIL")
    unknown_count = sum(1 for r in results if r["status"] == "UNKNOWN")

    if not required_results:
        overall = "UNKNOWN"
    elif any(r["status"] == "FAIL" for r in required_results):
        overall = "FAIL"
    elif any(r["status"] == "UNKNOWN" for r in required_results):
        overall = "UNKNOWN"
    else:
        overall = "PASS"

    report: Dict[str, Any] = {
        "schema": "aegis.production-path.v1",
        "status": overall,
        "passed": overall == "PASS",
        "passCount": pass_count,
        "failCount": fail_count,
        "unknownCount": unknown_count,
        "requiredCount": len(required_results),
        "probes": results,
    }
    report["digest"] = hashlib.sha256(
        json.dumps(report, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()
    return report


def verify_reply(
    reply_text: str,
    *,
    cwd: Optional[str] = None,
    detective_state: Optional[Dict[str, Any]] = None,
    baseline: Optional[Dict[str, Any]] = None,
    mode: Optional[str] = None,
    ledger_tip: Optional[str] = None,
    allow_git_subprocess: bool = True,
    production_path: Optional[Dict[str, Any]] = None,
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

    # D11 — Production-Path Deployment Verification (isolated tests/builds never certify live deployment)
    prod_report = production_path if production_path is not None else state.get("productionPath")
    if claims.get("claimsDeployment") and not claims["honestBlock"]:
        phrase = (claims.get("deploymentPhrases") or ["deployed"])[0]
        if not isinstance(prod_report, dict):
            findings.append({
                "class": "D11",
                "code": "UNVERIFIED_DEPLOYMENT_CLAIM",
                "severity": "DENY",
                "detail": (
                    f"Reply claimed deployment/operational readiness ({phrase!r}), "
                    "but no deterministic production-path verification evidence was recorded. "
                    "Isolated unit tests or builds do not verify active runtime configuration."
                ),
            })
        else:
            p_status = str(prod_report.get("status") or "UNKNOWN").upper()
            if p_status == "FAIL":
                failed_ids = [p["id"] for p in (prod_report.get("probes") or []) if p.get("status") == "FAIL"]
                findings.append({
                    "class": "D11",
                    "code": "PRODUCTION_PATH_MISMATCH",
                    "severity": "DENY",
                    "failedProbes": failed_ids,
                    "detail": (
                        f"Reply claimed deployment readiness ({phrase!r}), "
                        f"but production-path verification FAILED on probe(s): {', '.join(failed_ids) or 'unknown'}."
                    ),
                })
            elif p_status != "PASS":
                unk_ids = [p["id"] for p in (prod_report.get("probes") or []) if p.get("status") == "UNKNOWN"]
                findings.append({
                    "class": "D11",
                    "code": "INCOMPLETE_DEPLOYMENT_VERIFICATION",
                    "severity": "DENY",
                    "unknownProbes": unk_ids,
                    "detail": (
                        f"Reply claimed deployment readiness ({phrase!r}), "
                        f"but production-path status is {p_status} (unverified probe(s): {', '.join(unk_ids) or 'none'}). "
                        "Missing evidence is UNKNOWN, never PASS."
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
