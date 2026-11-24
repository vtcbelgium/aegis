"""Deterministic claim extraction from draft AI replies (zero LLM tokens).

Extracts falsifiable assertions:
    - Verification / pass claims ("all tests pass", "N passed", "exit 0", "0 failed", "build succeeded")
    - Cited file paths and line ranges (file:///...#L10-L20, `path/to/file.py:42`)
    - Cited git commit SHAs (7-40 hex chars in commit contexts)
    - Structured Truth Box fields (direct edits, Forge edits, winning chamber, failed chambers)
    - Blanket impossibility claims ("rollback is impossible", "cannot be recovered")
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

_HONEST_NEGATION_RE = re.compile(
    r"\b(?:did\s+not\s+run|not\s+run|unverified|blocked|failed\s+with|could\s+not\s+verify|"
    r"tests?\s+failed|exited?\s+(?:with\s+)?code\s+[1-9])\b",
    re.IGNORECASE,
)

_PASS_CLAIM_RE = re.compile(
    r"\b(?:all\s+(?:\d+\s+)?tests?\s+pass(?:ed|ing)?|tests?\s+(?:passed|are\s+green|OK)|"
    r"build\s+succeeded|exit(?:ed)?\s+(?:with\s+)?code\s+0|0\s+failed|0\s+errors|"
    r"100%\s+(?:green|pass(?:ing|ed)?)|verified\s+live)\b",
    re.IGNORECASE,
)

_DEPLOYMENT_CLAIM_RE = re.compile(
    r"\b(?:successfully\s+deployed|deployed\s+(?:live|and\s+operational|to\s+(?:production|prod|t590|cloudflare|vercel))|"
    r"operational\s+on\s+[A-Za-z0-9._-]+|live\s+in\s+production|production\s+(?:deploy|deployment|cutover)\s+(?:complete|succeeded|operational)|"
    r"service\s+(?:is\s+)?active\s+in\s+production|rolled\s+out\s+to\s+production)\b",
    re.IGNORECASE,
)

_COUNT_PASSED_RE = re.compile(r"\b(\d+)\s+(?:/\s*\d+\s+)?(?:tests?\s+)?passed\b", re.IGNORECASE)
_FILE_URI_RE = re.compile(r"file:///([A-Za-z]:/[^\s)#]+|/[^\s)#]+)(?:#L(\d+)(?:-L?(\d+))?)?")
_BACKTICK_FILE_RE = re.compile(
    r"`([A-Za-z0-9_./\\-]+\.(?:py|ts|tsx|js|jsx|json|md|yml|yaml|sql|sh|ps1|html|css|toml))(?::(\d+)(?:-(\d+))?)?`"
)
_COMMIT_SHA_RE = re.compile(r"\b(?:commit|sha|rev|at)\s+`?([0-9a-f]{7,40})`?\b", re.IGNORECASE)
_IMPOSSIBILITY_RE = re.compile(
    r"\b(?:rollback\s+is\s+impossible|cannot\s+be\s+recovered|impossible\s+to\s+(?:undo|recover|restore|rollback)|"
    r"no\s+backups?\s+exist|permanently\s+lost\s+with\s+no\s+way\s+back)\b",
    re.IGNORECASE,
)

_TRUTH_BOX_KEYS = {
    "directEdits": re.compile(r"^Antigravity direct file edits:\s*(.+)$", re.MULTILINE),
    "forgeEdits": re.compile(r"^Forge file edits:\s*(.+)$", re.MULTILINE),
    "winningChamber": re.compile(r"^Actual winning chamber/model:\s*(.+)$", re.MULTILINE),
    "failedChambers": re.compile(r"^Failed chambers before completion:\s*(.+)$", re.MULTILINE),
}


def extract_claims(reply_text: str) -> Dict[str, Any]:
    """Extract structured, verifiable claims from a draft reply."""
    text = reply_text or ""
    pass_matches = [m.group(0) for m in _PASS_CLAIM_RE.finditer(text)]
    deploy_matches = [m.group(0) for m in _DEPLOYMENT_CLAIM_RE.finditer(text)]
    # Ignore a pass/deployment claim only if the reply is strictly reporting failure/blocked without claiming pass
    claims_passing = bool(pass_matches)
    claims_deployment = bool(deploy_matches)
    honest_block = bool(_HONEST_NEGATION_RE.search(text)) and not claims_passing and not claims_deployment

    claimed_counts: List[int] = []
    for m in _COUNT_PASSED_RE.finditer(text):
        try:
            claimed_counts.append(int(m.group(1)))
        except ValueError:
            pass

    file_refs: List[Dict[str, Any]] = []
    seen_refs = set()
    for m in _FILE_URI_RE.finditer(text):
        raw_path = m.group(1)
        start_line = int(m.group(2)) if m.group(2) else None
        end_line = int(m.group(3)) if m.group(3) else start_line
        key = (raw_path, start_line, end_line)
        if key not in seen_refs:
            seen_refs.add(key)
            file_refs.append({"path": raw_path, "startLine": start_line, "endLine": end_line, "kind": "uri"})
    for m in _BACKTICK_FILE_RE.finditer(text):
        raw_path = m.group(1)
        start_line = int(m.group(2)) if m.group(2) else None
        end_line = int(m.group(3)) if m.group(3) else start_line
        key = (raw_path, start_line, end_line)
        if key not in seen_refs:
            seen_refs.add(key)
            file_refs.append({"path": raw_path, "startLine": start_line, "endLine": end_line, "kind": "backtick"})

    commit_shas = sorted(set(m.group(1).lower() for m in _COMMIT_SHA_RE.finditer(text)))
    impossibility_claims = [m.group(0) for m in _IMPOSSIBILITY_RE.finditer(text)]

    truth_box: Dict[str, Optional[str]] = {}
    for field, pat in _TRUTH_BOX_KEYS.items():
        m = pat.search(text)
        if m:
            truth_box[field] = m.group(1).strip()

    return {
        "claimsPassing": claims_passing,
        "claimsDeployment": claims_deployment,
        "honestBlock": honest_block,
        "passPhrases": pass_matches[:10],
        "deploymentPhrases": deploy_matches[:10],
        "claimedPassedCounts": claimed_counts,
        "fileRefs": file_refs[:50],
        "commitShas": commit_shas[:20],
        "impossibilityClaims": impossibility_claims,
        "truthBox": truth_box if truth_box else None,
    }
