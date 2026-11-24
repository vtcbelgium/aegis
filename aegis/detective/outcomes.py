"""Deterministic execution outcome parsers for Aegis Detective Mode (Clan Lynceus).

Extracts ground-truth test counts, exit codes, Forge chamber/PR receipts, and
SHA-256 output digests from raw PostToolUse payloads—never trusting agent prose.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, Optional

_PYTEST_SUMMARY_RE = re.compile(
    r"(?:(?P<failed>\d+)\s+failed\b)?.*?(?:(?P<passed>\d+)\s+passed\b)?.*?(?:(?P<skipped>\d+)\s+skipped\b)?",
    re.IGNORECASE,
)
_PYTEST_COUNTS_RE = re.compile(r"\b(\d+)\s+(passed|failed|errors?|skipped|xfailed|xpassed)\b", re.IGNORECASE)
_UNITTEST_RAN_RE = re.compile(r"\bRan\s+(\d+)\s+tests?\s+in\b", re.IGNORECASE)
_UNITTEST_FAIL_RE = re.compile(r"\bFAILED\s*\(([^)]+)\)", re.IGNORECASE)
_VITEST_TESTS_RE = re.compile(r"\bTests\s+(?:(\d+)\s+failed\s*\|\s*)?(\d+)\s+passed\s*\((\d+)\)", re.IGNORECASE)
_NODE_TEST_RE = re.compile(r"\b(\d+)\s+passed,\s*(\d+)\s+failed\b", re.IGNORECASE)
_EXIT_CODE_RE = re.compile(r"(?:exit(?:ed)?\s+(?:with\s+)?code|returncode|rc)\s*[:=]?\s*(-?\d+)", re.IGNORECASE)
_PR_URL_RE = re.compile(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/pull/\d+")
_CHAMBER_RE = re.compile(r"\b(?:winning[_\s-]?chamber|chamber)\s*[:=]\s*['\"]?([A-Za-z0-9._-]+)['\"]?", re.IGNORECASE)

_VERIFIER_CMD_RE = re.compile(
    r"\b(pytest|unittest|vitest|jest|npm\s+test|npm\s+run\s+(?:test|build|lint|typecheck|check:bundle)|"
    r"npx\s+tsc|tsc\b|eslint\b|verify_local\.py|next\s+build|cargo\s+test|go\s+test|node\s+--test|aegis\s+dojo)\b",
    re.IGNORECASE,
)
_TEST_FILE_RE = re.compile(
    r"(?:^|[\\/])(?:tests?|__tests__|spec|specs)[\\/]|(?:^|[\\/])test_[^\\/]+\.py$|_test\.py$|\.(?:test|spec)\.[jt]sx?$",
    re.IGNORECASE,
)


def sha256_text(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8", errors="replace")).hexdigest()


def is_test_file(path: str) -> bool:
    if not isinstance(path, str) or not path:
        return False
    return bool(_TEST_FILE_RE.search(path.replace("\\", "/")))


def is_verifier_command(command: str) -> bool:
    if not isinstance(command, str) or not command.strip():
        return False
    return bool(_VERIFIER_CMD_RE.search(command))


def infer_exit_code(payload: Any, raw_text: str = "") -> Optional[int]:
    """Extract an integer OS exit code from a PostToolUse payload when present."""
    if isinstance(payload, dict):
        for key in ("exitCode", "exit_code", "returncode", "return_code", "code"):
            val = payload.get(key)
            if isinstance(val, int) and not isinstance(val, bool):
                return val
        resp = payload.get("tool_response") or payload.get("result")
        if isinstance(resp, dict):
            for key in ("exitCode", "exit_code", "returncode", "return_code"):
                val = resp.get(key)
                if isinstance(val, int) and not isinstance(val, bool):
                    return val
            if resp.get("isError") is True:
                return 1
    if raw_text:
        m = _EXIT_CODE_RE.search(raw_text)
        if m:
            try:
                return int(m.group(1))
            except ValueError:
                pass
    return None


def parse_verifier_output(command: str, output: str, exit_code: Optional[int] = None) -> Dict[str, Any]:
    """Deterministically parse test/build/forge output into structured ground truth."""
    text = output or ""
    runner = "unknown"
    passed: Optional[int] = None
    failed: Optional[int] = None
    skipped: Optional[int] = None

    low_cmd = (command or "").lower()
    if "pytest" in low_cmd:
        runner = "pytest"
    elif "verify_local.py" in low_cmd or "unittest" in low_cmd:
        runner = "unittest"
    elif "vitest" in low_cmd:
        runner = "vitest"
    elif "tsc" in low_cmd:
        runner = "tsc"
    elif "eslint" in low_cmd:
        runner = "eslint"
    elif "agents.forge" in low_cmd:
        runner = "forge"
    elif "dojo" in low_cmd:
        runner = "aegis-dojo"
    elif is_verifier_command(command):
        runner = "verifier"

    # 1. Vitest summary line
    m_vitest = _VITEST_TESTS_RE.search(text)
    if m_vitest:
        runner = "vitest"
        failed = int(m_vitest.group(1)) if m_vitest.group(1) else 0
        passed = int(m_vitest.group(2))

    # 2. Node / custom "15 passed, 0 failed"
    if passed is None:
        m_node = _NODE_TEST_RE.search(text)
        if m_node:
            passed = int(m_node.group(1))
            failed = int(m_node.group(2))

    # 3. Pytest counts
    if passed is None and failed is None:
        counts: Dict[str, int] = {}
        for num, kind in _PYTEST_COUNTS_RE.findall(text):
            k = kind.lower().rstrip("s")
            counts[k] = int(num)
        if "passed" in counts or "failed" in counts or "error" in counts:
            passed = counts.get("passed", 0)
            failed = counts.get("failed", 0) + counts.get("error", 0)
            skipped = counts.get("skipped", 0)
            if runner == "unknown":
                runner = "pytest"

    # 4. Python unittest summary ("Ran 700 tests in ... OK / FAILED (failures=1)")
    m_uni = _UNITTEST_RAN_RE.search(text)
    if m_uni and passed is None:
        total = int(m_uni.group(1))
        m_fail = _UNITTEST_FAIL_RE.search(text)
        if m_fail:
            fail_nums = [int(n) for n in re.findall(r"(?:failures|errors)=(\d+)", m_fail.group(1))]
            failed = sum(fail_nums) if fail_nums else 1
            passed = max(0, total - failed)
        elif re.search(r"(?:^|\n)OK(?:\s*\(|$)", text):
            passed = total
            failed = 0
        if runner == "unknown":
            runner = "unittest"

    # 5. Structured JSON receipt (e.g. Forge / Aegis Dojo)
    winning_chamber = None
    failed_chambers = None
    pr_url = None
    stripped = text.strip()
    if stripped.startswith("{") and stripped.endswith("}"):
        try:
            obj = json.loads(stripped)
            if isinstance(obj, dict):
                if isinstance(obj.get("winningChamber"), str):
                    winning_chamber = obj["winningChamber"]
                if isinstance(obj.get("failedChambers"), list):
                    failed_chambers = [str(x) for x in obj["failedChambers"]]
                if isinstance(obj.get("prUrl"), str):
                    pr_url = obj["prUrl"]
                if obj.get("schema") == "aegis.dojo.report.v1" and isinstance(obj.get("cases"), list):
                    runner = "aegis-dojo"
                    passed = sum(1 for c in obj["cases"] if c.get("passed"))
                    failed = sum(1 for c in obj["cases"] if not c.get("passed"))
        except Exception:
            pass

    if pr_url is None:
        m_pr = _PR_URL_RE.search(text)
        if m_pr:
            pr_url = m_pr.group(0)
    if winning_chamber is None:
        m_ch = _CHAMBER_RE.search(text)
        if m_ch:
            winning_chamber = m_ch.group(1)

    inferred_rc = exit_code if exit_code is not None else infer_exit_code({}, text)
    if inferred_rc is None and failed is not None:
        inferred_rc = 0 if failed == 0 else 1

    ok = False
    if inferred_rc is not None:
        ok = (inferred_rc == 0) and (failed is None or failed == 0)
    elif failed is not None and passed is not None:
        ok = (failed == 0 and passed >= 0)

    out: Dict[str, Any] = {
        "runner": runner,
        "isVerifier": is_verifier_command(command) or runner != "unknown",
        "exitCode": inferred_rc,
        "ok": ok,
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "stdoutDigest": sha256_text(text),
    }
    if winning_chamber:
        out["winningChamber"] = winning_chamber
    if failed_chambers is not None:
        out["failedChambers"] = failed_chambers
    if pr_url:
        out["prUrl"] = pr_url
    return out
