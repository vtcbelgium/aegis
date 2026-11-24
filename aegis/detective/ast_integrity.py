"""AST Test-Integrity, Rashomon Temporal Sequence & Synthetic Green Theater Scanner.

Covers:
    - D04: Test tampering / reward hacking (assertion count drop, sys.exit(0), @skip,
           trivial assert True, runner monkeypatching, red -> test-file-only edit).
    - D07: Synthetic green theater in production code (tautological identical-arg
           heartbeats, error-swallowing fake greens, hardcoded fallback scores).
"""

from __future__ import annotations

import ast
import re
from typing import Any, Dict, List, Optional

from .outcomes import is_test_file

# Forbidden test-escape hatches newly added inside test files
_JS_ESCAPE_PATTERNS = [
    (re.compile(r"\b(?:it|test|describe)\.skip\s*\("), "TEST_SKIP_INJECTED", "Test skipped via .skip()"),
    (re.compile(r"\bx(?:it|test|describe)\s*\("), "TEST_SKIP_INJECTED", "Test disabled via xit/xtest/xdescribe"),
    (re.compile(r"\bprocess\.exit\s*\(\s*0\s*\)"), "TEST_FORCED_EXIT_ZERO", "Forced process.exit(0) inside test"),
    (re.compile(r"\bexpect\s*\(\s*true\s*\)\s*\.toBe\s*\(\s*true\s*\)"), "TRIVIAL_ASSERTION", "Tautological expect(true).toBe(true)"),
]

_PY_RUNNER_TAMPER_RE = re.compile(
    r"\b(?:sys\.exit\s*\(\s*0\s*\)|os\._exit\s*\(\s*0\s*\)|pytest\.exit\s*\(\s*.*returncode\s*=\s*0)",
    re.IGNORECASE,
)

# Synthetic Green Theater patterns in non-test production code
_THEATER_LINE_PATTERNS = [
    (
        re.compile(r"evaluate_[a-z0-9_]*heartbeat\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,\s*\1\s*\)"),
        "SYNTHETIC_HEARTBEAT_TAUTOLOGY",
        "Identical arguments passed to heartbeat check (always green by tautology)",
    ),
    (
        re.compile(r"\b(?:score|health_score|trust_score)['\"]?\s*[:=]\s*(?:95|98|99|100)\b.*\b(?:fallback|default|unavailable|error|catch|except)\b", re.IGNORECASE),
        "SYNTHETIC_FALLBACK_SCORE",
        "Hardcoded high fallback score masks missing or failed live telemetry",
    ),
]


def _count_python_assertions(source: str) -> Optional[Dict[str, Any]]:
    """Parse Python AST and count real assertions plus suspicious escape hatches."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None

    real_asserts = 0
    trivial_asserts = 0
    skips = 0
    forced_exits = 0

    for node in ast.walk(tree):
        if isinstance(node, ast.Assert):
            if isinstance(node.test, ast.Constant) and node.test.value is True:
                trivial_asserts += 1
            else:
                real_asserts += 1
        elif isinstance(node, ast.Call):
            fn = node.func
            attr = fn.attr if isinstance(fn, ast.Attribute) else (fn.id if isinstance(fn, ast.Name) else "")
            if attr.startswith("assert"):
                real_asserts += 1
            elif attr in ("skip", "skipTest"):
                skips += 1
            elif isinstance(fn, ast.Attribute) and fn.attr in ("exit", "_exit"):
                if node.args and isinstance(node.args[0], ast.Constant) and node.args[0].value == 0:
                    forced_exits += 1
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            for dec in node.decorator_list:
                dec_src = ast.unparse(dec) if hasattr(ast, "unparse") else ""
                if any(tok in dec_src for tok in ("unittest.skip", "pytest.mark.skip", "mark.skip", "skipIf(True")):
                    skips += 1

    return {
        "realAsserts": real_asserts,
        "trivialAsserts": trivial_asserts,
        "skips": skips,
        "forcedExits": forced_exits,
    }


def _count_js_assertions(source: str) -> Dict[str, int]:
    real = len(re.findall(r"\b(?:expect|assert(?:\.[A-Za-z0-9_]+)?)\s*\(", source))
    trivial = len(re.findall(r"\bexpect\s*\(\s*true\s*\)\s*\.toBe\s*\(\s*true\s*\)", source))
    return {"realAsserts": max(0, real - trivial), "trivialAsserts": trivial}


def inspect_test_edit(path: str, before_text: Optional[str], after_text: str) -> List[Dict[str, Any]]:
    """Compare before/after content of a test file to catch reward hacking & test tampering (D04)."""
    if not is_test_file(path):
        return []
    findings: List[Dict[str, Any]] = []
    norm_path = path.replace("\\", "/")

    if norm_path.endswith(".py"):
        after_info = _count_python_assertions(after_text)
        before_info = _count_python_assertions(before_text) if before_text is not None else None
        if after_info is not None:
            if after_info["forcedExits"] > (before_info["forcedExits"] if before_info else 0):
                findings.append({
                    "class": "D04",
                    "code": "TEST_FORCED_EXIT_ZERO",
                    "severity": "DENY",
                    "file": norm_path,
                    "detail": "Newly added sys.exit(0) / os._exit(0) inside test file.",
                })
            if after_info["skips"] > (before_info["skips"] if before_info else 0):
                findings.append({
                    "class": "D04",
                    "code": "TEST_SKIP_INJECTED",
                    "severity": "DENY",
                    "file": norm_path,
                    "detail": "Newly added @skip / pytest.skip inside test file.",
                })
            if after_info["trivialAsserts"] > (before_info["trivialAsserts"] if before_info else 0):
                findings.append({
                    "class": "D04",
                    "code": "TRIVIAL_ASSERTION",
                    "severity": "ASK",
                    "file": norm_path,
                    "detail": "Newly introduced tautological `assert True` inside test file.",
                })
            if before_info is not None and after_info["realAsserts"] < before_info["realAsserts"]:
                delta = before_info["realAsserts"] - after_info["realAsserts"]
                findings.append({
                    "class": "D04",
                    "code": "TEST_ASSERTIONS_REDUCED",
                    "severity": "ASK",
                    "file": norm_path,
                    "detail": f"Test assertion count dropped by {delta} ({before_info['realAsserts']} -> {after_info['realAsserts']}).",
                })
        elif _PY_RUNNER_TAMPER_RE.search(after_text):
            findings.append({
                "class": "D04",
                "code": "TEST_FORCED_EXIT_ZERO",
                "severity": "DENY",
                "file": norm_path,
                "detail": "Forced exit(0) detected in test file.",
            })
    else:
        before_s = before_text or ""
        for pat, code, msg in _JS_ESCAPE_PATTERNS:
            if len(pat.findall(after_text)) > len(pat.findall(before_s)):
                findings.append({
                    "class": "D04",
                    "code": code,
                    "severity": "DENY" if code != "TRIVIAL_ASSERTION" else "ASK",
                    "file": norm_path,
                    "detail": msg,
                })
        if before_text is not None:
            b_js = _count_js_assertions(before_text)
            a_js = _count_js_assertions(after_text)
            if a_js["realAsserts"] < b_js["realAsserts"]:
                findings.append({
                    "class": "D04",
                    "code": "TEST_ASSERTIONS_REDUCED",
                    "severity": "ASK",
                    "file": norm_path,
                    "detail": f"Test assertion count dropped ({b_js['realAsserts']} -> {a_js['realAsserts']}).",
                })

    return findings


def inspect_production_theater(path: str, source: str) -> List[Dict[str, Any]]:
    """Scan non-test production code for synthetic green theater and error-swallowing fakes (D07)."""
    if is_test_file(path):
        return []
    findings: List[Dict[str, Any]] = []
    norm_path = path.replace("\\", "/")

    for pat, code, msg in _THEATER_LINE_PATTERNS:
        if pat.search(source):
            findings.append({
                "class": "D07",
                "code": code,
                "severity": "WARN",
                "file": norm_path,
                "detail": msg,
            })

    if norm_path.endswith(".py"):
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return findings
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler):
                for stmt in node.body:
                    if isinstance(stmt, ast.Return) and stmt.value is not None:
                        val = stmt.value
                        if isinstance(val, ast.Constant) and val.value is True:
                            findings.append({
                                "class": "D07",
                                "code": "ERROR_SWALLOW_FAKE_GREEN",
                                "severity": "WARN",
                                "file": norm_path,
                                "line": getattr(stmt, "lineno", None),
                                "detail": "Exception handler swallows error by returning literal True.",
                            })
                        elif isinstance(val, ast.Dict):
                            keys = [k.value for k in val.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)]
                            vals = [v.value for v in val.values if isinstance(v, ast.Constant)]
                            if ("ok" in keys and True in vals) or ("status" in keys and any(s in ("ok", "healthy", "green", "pass") for s in vals if isinstance(s, str))):
                                findings.append({
                                    "class": "D07",
                                    "code": "ERROR_SWALLOW_FAKE_GREEN",
                                    "severity": "WARN",
                                    "file": norm_path,
                                    "line": getattr(stmt, "lineno", None),
                                    "detail": "Exception handler swallows error by returning a synthetic ok/healthy dict.",
                                })
    return findings


def inspect_unified_diff(diff_text: str) -> List[Dict[str, Any]]:
    """Scan a unified git diff for D04 test-tampering and D07 synthetic-theater regressions."""
    findings: List[Dict[str, Any]] = []
    current_file: Optional[str] = None
    added_lines: List[str] = []
    removed_lines: List[str] = []

    def _flush() -> None:
        if not current_file:
            return
        added_blob = "\n".join(added_lines)
        removed_blob = "\n".join(removed_lines)
        if is_test_file(current_file):
            if _PY_RUNNER_TAMPER_RE.search(added_blob) and not _PY_RUNNER_TAMPER_RE.search(removed_blob):
                findings.append({
                    "class": "D04",
                    "code": "TEST_FORCED_EXIT_ZERO",
                    "severity": "DENY",
                    "file": current_file,
                    "detail": "Diff adds forced exit(0) inside a test file.",
                })
            if re.search(r"@(?:unittest|pytest\.mark)\.skip|pytest\.skip\s*\(", added_blob) and not re.search(
                r"@(?:unittest|pytest\.mark)\.skip|pytest\.skip\s*\(", removed_blob
            ):
                findings.append({
                    "class": "D04",
                    "code": "TEST_SKIP_INJECTED",
                    "severity": "DENY",
                    "file": current_file,
                    "detail": "Diff introduces test skip decorator/call.",
                })
            for pat, code, msg in _JS_ESCAPE_PATTERNS:
                if len(pat.findall(added_blob)) > len(pat.findall(removed_blob)):
                    findings.append({"class": "D04", "code": code, "severity": "DENY", "file": current_file, "detail": msg})
            added_asserts = len(re.findall(r"\b(?:assert\b|assert[A-Z][A-Za-z0-9_]*\(|expect\()", added_blob))
            removed_asserts = len(re.findall(r"\b(?:assert\b|assert[A-Z][A-Za-z0-9_]*\(|expect\()", removed_blob))
            if removed_asserts > added_asserts:
                findings.append({
                    "class": "D04",
                    "code": "TEST_ASSERTIONS_REDUCED",
                    "severity": "ASK",
                    "file": current_file,
                    "detail": f"Diff removes {removed_asserts - added_asserts} more assertion(s) than it adds.",
                })
        else:
            for pat, code, msg in _THEATER_LINE_PATTERNS:
                if pat.search(added_blob) and not pat.search(removed_blob):
                    findings.append({"class": "D07", "code": code, "severity": "WARN", "file": current_file, "detail": msg})

    for line in (diff_text or "").splitlines():
        if line.startswith("+++ b/"):
            _flush()
            current_file = line[6:].strip()
            added_lines = []
            removed_lines = []
        elif line.startswith("+") and not line.startswith("+++"):
            added_lines.append(line[1:])
        elif line.startswith("-") and not line.startswith("---"):
            removed_lines.append(line[1:])
    _flush()
    return findings
