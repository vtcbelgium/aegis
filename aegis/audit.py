"""OWASP code audit: static checks on code an agent writes or on a repository.

Ported from the OTHRYS Aegis (`agents/aegis.py`). This is the "A0x" rule engine: it scans
text for OWASP Web Top 10 (2021), API Top 10 (2023) and LLM Top 10 (2025) smells. It is
advisory by default (WARN), so an agent writing weak code is flagged in the ledger without
blocking the edit; set policy.code_audit to "off" to skip it, or callers may treat findings
as they wish.

Unlike the clans, this looks at *content*, not at where a file goes, so it never locks a
session on its own. It is used two ways:
    - `aegis audit <path>`  : scan a file or repository on demand (any CI, any agent).
    - write_file / edit_block content is scanned at WARN when policy.code_audit == "warn".
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional

from .core import DecisionLevel, Verdict

NAME = "AegisAudit"
L = DecisionLevel


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    level: DecisionLevel
    pattern: "re.Pattern[str]"
    message: str


def _r(id, name, level, pattern, message, flags=re.IGNORECASE):
    return Rule(id, name, level, re.compile(pattern, flags), message)


# Decisions follow the OTHRYS engine: advisory findings are WARN; the strongest smells
# (hardcoded live secrets, metadata SSRF) are RESTRICT. Nothing here LOCKs by itself.
RULES: List[Rule] = [
    # A01 Broken Access Control
    _r("A01", "Broken Access Control", L.WARN, r"(?:\.\./){2,}|(?:\.\.\\){2,}",
       "Path traversal sequence in code"),
    _r("A01", "Broken Access Control", L.WARN, r"\bunlock_token\s*==\s*['\"][A-Za-z0-9_-]{6,}['\"]",
       "Hardcoded bypass/override token"),
    # A02 Cryptographic Failures
    _r("A02", "Cryptographic Failures", L.RESTRICT,
       r"(?:api[_-]?key|secret|password|passwd|bearer|auth[_-]?token|client[_-]?secret)\s*[:=]\s*['\"][A-Za-z0-9+/=_\-]{16,}['\"]",
       "Hardcoded secret in source"),
    _r("A02", "Cryptographic Failures", L.WARN, r"\bhashlib\.(?:md5|sha1)\s*\(",
       "Weak hash (MD5/SHA-1) for security use"),
    _r("A02", "Cryptographic Failures", L.WARN, r"\bssl[._].*?CERT_NONE|verify\s*=\s*False",
       "TLS certificate verification disabled"),
    # A03 Injection
    _r("A03", "Injection", L.WARN,
       r"(?:execute|cursor\.execute|query)\s*\(\s*f['\"][^'\"]*(?:SELECT|INSERT|UPDATE|DELETE)[^'\"]*\{",
       "SQL built with an f-string (injection)"),
    _r("A03", "Injection", L.WARN, r"subprocess\.(?:Popen|run|call|check_output)\s*\([^)]*shell\s*=\s*True",
       "subprocess with shell=True"),
    _r("A03", "Injection", L.WARN, r"\b(?:os\.system|eval|exec)\s*\(",
       "Dynamic execution via os.system/eval/exec"),
    # A05 Security Misconfiguration
    _r("A05", "Security Misconfiguration", L.WARN, r"\b(?:DEBUG|FLASK_DEBUG)\s*=\s*True\b",
       "Debug mode enabled"),
    _r("A05", "Security Misconfiguration", L.WARN,
       r"Access-Control-Allow-Origin['\"]?\s*[:=]\s*['\"]\*['\"]|CORS\([^)]*origins\s*=\s*['\"]\*",
       "Wildcard CORS"),
    # A07 Identification & Authentication
    _r("A07", "Identification/Authentication", L.WARN,
       r"(?:password|token|secret|api_key)\s*==\s*(?:user_input|request\.|payload|body|data\[)",
       "Non-constant-time secret comparison (use hmac.compare_digest)"),
    # A10 SSRF
    _r("A10", "SSRF", L.RESTRICT, r"169\.254\.169\.254|metadata\.google\.internal",
       "Cloud instance-metadata endpoint referenced"),
    # LLM01 Prompt injection / guardrail override in source or data
    _r("LLM01", "Prompt Injection", L.WARN,
       r"ignore\s+(?:all\s+)?previous\s+instructions|disregard\s+(?:the\s+)?(?:guardrails|system\s+prompt)|bypass\s+aegis",
       "Prompt-injection / guardrail-override directive in text"),
    # LLM06 Excessive agency primitives
    _r("LLM06", "Excessive Agency", L.WARN,
       r"shutil\.rmtree\s*\(\s*['\"]/['\"]|os\.remove\s*\(\s*['\"](?:server|app|main)\.py['\"]",
       "Unbounded destructive file primitive"),
]

# Lines that are clearly examples/tests/placeholders should not raise a real finding.
_BENIGN = re.compile(r"\b(?:example|dummy|placeholder|your[-_]?key[-_]?here|xxx+|changeme|test[-_]?key|fixture|sample)\b",
                     re.IGNORECASE)


@dataclass
class Finding:
    rule_id: str
    name: str
    level: DecisionLevel
    message: str
    line: int
    excerpt: str

    def to_dict(self) -> dict:
        return {"rule": self.rule_id, "name": self.name, "level": self.level.name,
                "message": self.message, "line": self.line, "excerpt": self.excerpt}


def scan(content: str, filename: str = "") -> List[Finding]:
    """Return OWASP findings for a block of code/text."""
    if not content:
        return []
    findings: List[Finding] = []
    lines = content.splitlines()
    for rule in RULES:
        for m in rule.pattern.finditer(content):
            line_no = content.count("\n", 0, m.start()) + 1
            excerpt = (lines[line_no - 1] if 0 < line_no <= len(lines) else m.group(0)).strip()[:160]
            if _BENIGN.search(excerpt) and rule.level < L.RESTRICT:
                continue
            findings.append(Finding(rule.id, rule.name, rule.level, rule.message, line_no, excerpt))
    return findings


def audit_code(content: str, filename: str = "") -> Verdict:
    """One Verdict for a block of code (the worst finding), for the write path and the CLI."""
    findings = scan(content, filename)
    if not findings:
        return Verdict(L.PASS, ["No OWASP findings"], NAME)
    worst = max(f.level for f in findings)
    reasons = [f"{f.rule_id} {f.name}: {f.message} (line {f.line})"
               for f in sorted(findings, key=lambda f: (-int(f.level), f.line))[:8]]
    return Verdict(worst, reasons, NAME, metadata={"findings": [f.to_dict() for f in findings], "file": filename})
