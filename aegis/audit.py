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

# Lines or values that are clearly examples/tests/placeholders should not raise a real finding.
_BENIGN = re.compile(r"\b(?:example|dummy|placeholder|your[-_]?key[-_]?here|xxx+|changeme|test[-_]?key|fixture|sample)\b",
                     re.IGNORECASE)
_SYMBOLIC_ENUM_VALUE = re.compile(r"""[:=]\s*['"]([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)['"]""")
_COMMENT_LINE = re.compile(r"^\s*(?:#|//|/\*|\*)")

_SKIP_DIRS = frozenset({".git", "node_modules", ".venv", "venv", "__pycache__", ".next", "dist", "build"})
_AUDIT_EXTENSIONS = (
    ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rb", ".php", ".java",
    ".sh", ".yml", ".yaml", ".env", ".toml", ".cjs", ".mjs",
)


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
            matched_text = m.group(0)
            if _COMMENT_LINE.match(excerpt) and rule.id in ("A01", "A02", "A03", "A05", "A07", "A10"):
                continue
            if rule.id == "A02" and rule.level == L.RESTRICT:
                if _BENIGN.search(matched_text) or _SYMBOLIC_ENUM_VALUE.search(matched_text):
                    continue
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


def scan_path(target_path: str, *, max_files: int = 2000, max_file_bytes: int = 2 * 1024 * 1024) -> dict:
    """Scan a file or directory for live secrets and OWASP issues (shared by CLI and UI)."""
    import os
    from .clans import CustodyClan
    from .core import AegisGate
    from .ledger import redact

    abs_target = os.path.abspath(os.path.expanduser(target_path))
    if not os.path.exists(abs_target):
        raise FileNotFoundError(f"Target path does not exist: {target_path}")

    gate = AegisGate(base_dir=abs_target, max_violations_per_minute=10**9)
    files_to_check: List[str] = []
    truncated = False

    if os.path.isfile(abs_target):
        files_to_check = [abs_target]
    else:
        for root, dirs, files in os.walk(abs_target, followlinks=False):
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
            for name in sorted(files):
                files_to_check.append(os.path.join(root, name))
                if len(files_to_check) >= max_files:
                    truncated = True
                    break
            if truncated:
                break

    findings_out: List[dict] = []
    files_with_issues = 0

    for filepath in files_to_check:
        rel = os.path.relpath(filepath, abs_target) if os.path.isdir(abs_target) else os.path.basename(filepath)
        file_had_issue = False
        try:
            if os.path.getsize(filepath) > max_file_bytes:
                continue
            with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read()

            sec_verdict = CustodyClan.inspect_secrets(content)
            if not sec_verdict.passed:
                gate.record(sec_verdict)
                file_had_issue = True
                for reason in sec_verdict.reasons:
                    findings_out.append({
                        "file": rel,
                        "path": filepath,
                        "kind": "secret",
                        "rule": "CUSTODY",
                        "level": sec_verdict.level.name,
                        "message": redact(reason),
                        "line": None,
                    })

            if filepath.lower().endswith(_AUDIT_EXTENSIONS):
                code_verdict = audit_code(content, filepath)
                if code_verdict.level > L.PASS:
                    gate.record(code_verdict)
                    file_had_issue = True
                    for item in code_verdict.metadata.get("findings") or []:
                        findings_out.append({
                            "file": rel,
                            "path": filepath,
                            "kind": "owasp",
                            "rule": item["rule"],
                            "level": item["level"],
                            "message": f"{item['rule']} {item['name']}: {item['message']} (line {item['line']})",
                            "line": item["line"],
                            "excerpt": redact(item.get("excerpt", ""), 160),
                        })
        except Exception as exc:
            fail_v = Verdict(L.DENY, [f"Could not read file ({exc})"], NAME)
            gate.record(fail_v)
            file_had_issue = True
            findings_out.append({
                "file": rel,
                "path": filepath,
                "kind": "error",
                "rule": "FAIL_CLOSED",
                "level": "DENY",
                "message": f"Could not read ({exc})",
                "line": None,
            })

        if file_had_issue:
            files_with_issues += 1

    return {
        "target": abs_target,
        "filesScanned": len(files_to_check),
        "truncated": truncated,
        "filesWithIssues": files_with_issues,
        "findingCount": len(findings_out),
        "level": gate.current_level.name,
        "passed": len(findings_out) == 0,
        "findings": findings_out,
    }
