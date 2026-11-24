"""Drift, spin watchdog, scope envelope, test-freeze toggle, and slopsquatting guard (D09, D11)."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from .baseline import _atomic_write_json, detective_dir
from .outcomes import is_test_file

# Well-known high-value package targets frequently mimicked by slopsquatting attacks
POPULAR_PACKAGES = frozenset({
    "requests", "urllib3", "numpy", "pandas", "pytest", "pydantic", "fastapi", "flask", "django",
    "cryptography", "httpx", "aiohttp", "sqlalchemy", "boto3", "pyyaml", "pillow", "scipy",
    "scikit-learn", "torch", "transformers", "openai", "anthropic", "mcp", "websockets", "uvicorn",
    "react", "next", "typescript", "vitest", "eslint", "tailwindcss", "zod", "axios", "express",
    "lodash", "prisma", "drizzle-orm", "playwright", "puppeteer", "supabase", "lucide-react",
})

_INSTALL_CMD_RE = re.compile(
    r"\b(?:pip3?|uv\s+pip|npm|pnpm|yarn)\s+(?:install|add)\s+(.+)$",
    re.IGNORECASE,
)


def config_path() -> str:
    return os.path.join(detective_dir(), "config.json")


def load_detective_config() -> Dict[str, Any]:
    defaults: Dict[str, Any] = {
        "schema": "aegis.detective.config.v1",
        "mode": "passive",  # off | passive | strict
        "freezeTests": False,
        "spinReadThreshold": 25,
        "scopeRoots": [],
    }
    try:
        with open(config_path(), "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            defaults.update({k: v for k, v in data.items() if k in defaults})
    except (FileNotFoundError, OSError, ValueError):
        pass
    env_mode = os.environ.get("AEGIS_DETECTIVE_MODE", "").strip().lower()
    if env_mode in ("off", "passive", "strict"):
        defaults["mode"] = env_mode
    return defaults


def save_detective_config(updates: Dict[str, Any]) -> Dict[str, Any]:
    cfg = load_detective_config()
    if "mode" in updates:
        m = str(updates["mode"]).strip().lower()
        if m not in ("off", "passive", "strict"):
            raise ValueError("mode must be 'off', 'passive', or 'strict'")
        cfg["mode"] = m
    if "freezeTests" in updates:
        cfg["freezeTests"] = bool(updates["freezeTests"])
    if "spinReadThreshold" in updates:
        n = int(updates["spinReadThreshold"])
        if n < 3 or n > 500:
            raise ValueError("spinReadThreshold must be between 3 and 500")
        cfg["spinReadThreshold"] = n
    if "scopeRoots" in updates:
        roots = updates["scopeRoots"]
        if not isinstance(roots, list) or not all(isinstance(r, str) for r in roots):
            raise ValueError("scopeRoots must be a list of path strings")
        cfg["scopeRoots"] = [r.strip() for r in roots if r.strip()]
    _atomic_write_json(config_path(), cfg)
    return cfg


def set_freeze_tests(enabled: bool) -> Dict[str, Any]:
    return save_detective_config({"freezeTests": bool(enabled)})


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i]
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr.append(min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost))
        prev = curr
    return prev[-1]


def check_install_slopsquatting(command: str, workspace: Optional[str] = None) -> List[Dict[str, Any]]:
    """Flag potential hallucinated or typosquatted packages in pip/npm install commands (D09)."""
    m = _INSTALL_CMD_RE.search(command or "")
    if not m:
        return []
    tail = m.group(1)
    # Collect declared dependencies from local lockfiles/manifests if available
    known_local = set()
    if workspace and os.path.isdir(workspace):
        for fname in ("pyproject.toml", "requirements.txt", "package.json"):
            fpath = Path(workspace) / fname
            if fpath.is_file():
                try:
                    known_local.update(re.findall(r"[a-z0-9][a-z0-9._-]{1,60}", fpath.read_text(encoding="utf-8", errors="ignore").lower()))
                except OSError:
                    pass

    findings: List[Dict[str, Any]] = []
    for raw_tok in tail.split():
        if raw_tok.startswith("-") or raw_tok in (".", "..", "&&", "||", ";") or "://" in raw_tok or "/" in raw_tok or "\\" in raw_tok:
            if raw_tok in ("&&", "||", ";"):
                break
            continue
        pkg = re.split(r"[=<>!~@\[,]", raw_tok, maxsplit=1)[0].strip().lower()
        if not pkg or len(pkg) < 2 or pkg in POPULAR_PACKAGES or pkg in known_local:
            continue
        close = [pop for pop in POPULAR_PACKAGES if 0 < _levenshtein(pkg, pop) <= 2 and abs(len(pkg) - len(pop)) <= 2]
        if close:
            findings.append({
                "class": "D09",
                "code": "SLOPSQUATTING_SUSPECT",
                "severity": "ASK",
                "package": pkg,
                "similarTo": sorted(close)[:3],
                "detail": f"Package '{pkg}' is not in local manifests and resembles popular package(s) {sorted(close)[:3]} (possible hallucination/slopsquat).",
            })
    return findings


def check_write_drift(
    target_path: str,
    detective_state: Dict[str, Any],
    config: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Check pre-write Detective guards: Test-Freeze, Rashomon red->test-edit, and Scope Envelope."""
    cfg = config or load_detective_config()
    findings: List[Dict[str, Any]] = []
    norm = (target_path or "").replace("\\", "/")

    if cfg.get("freezeTests") and is_test_file(norm):
        findings.append({
            "class": "D04",
            "code": "TESTS_FROZEN_BY_OWNER",
            "severity": "DENY",
            "file": norm,
            "detail": "Test files are frozen by `aegis detective freeze-tests`. Fix production code or unfreeze tests explicitly.",
        })

    if detective_state.get("testFailureArmed") and is_test_file(norm):
        if int(detective_state.get("prodEditsSinceLastFail") or 0) == 0:
            findings.append({
                "class": "D04",
                "code": "RASHOMON_TEST_EDIT_AFTER_FAIL",
                "severity": "ASK",
                "file": norm,
                "detail": "Test failed and the next edit targets a test file with zero intervening production code edits.",
            })

    scope_roots: Sequence[str] = cfg.get("scopeRoots") or []
    if scope_roots and target_path:
        abs_target = os.path.abspath(target_path)
        in_scope = any(
            abs_target == os.path.abspath(r) or abs_target.startswith(os.path.abspath(r) + os.sep)
            for r in scope_roots
        )
        if not in_scope:
            findings.append({
                "class": "D11",
                "code": "SCOPE_DRIFT",
                "severity": "WARN",
                "file": norm,
                "detail": f"Edit target '{norm}' lies outside declared Detective scope roots.",
            })
    return findings


def check_spin_budget(detective_state: Dict[str, Any], config: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    """Flag excessive read/search calls with zero progress (D11)."""
    cfg = config or load_detective_config()
    threshold = int(cfg.get("spinReadThreshold") or 25)
    reads = int(detective_state.get("readCallsSinceLastWrite") or 0)
    if reads >= threshold:
        return {
            "class": "D11",
            "code": "SPIN_WATCHDOG_EXCEEDED",
            "severity": "WARN",
            "readsSinceLastWrite": reads,
            "threshold": threshold,
            "detail": f"{reads} read/search calls executed since last file write (threshold: {threshold}). Pause and check for goal drift.",
        }
    return None
