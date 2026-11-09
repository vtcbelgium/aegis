"""Tartarus Clan: Command Inspection, Destructive Operations & SQL Shield.

Command inspection is allowlist-based (see aegis/shell.py): every command line is parsed
with quote-aware tokenization, each segment's binary is looked up in an explicit table,
and its path / URL arguments are checked against the workspace and the network allowlist.
Unknown binaries are routed to the owner (ASK) instead of being silently allowed.

Invariants:
    1. Recursive deletion / wiping of roots, system or home directories -> LOCK.
    2. Credential stores referenced anywhere in a command -> LOCK.
    3. Paths outside the workspace, privilege escalation, pipes into interpreters -> DENY.
    4. Inline code, unknown binaries, non-allowlisted network egress -> ASK.
    5. Untrusted raw SQL injection patterns blocked (DENY).
"""

from __future__ import annotations

import re
from typing import Optional

from ..core import DecisionLevel, Verdict
from ..canonicalizer import normalize_text
from ..policy import AegisPolicy, SENSITIVE_PATH_PATTERNS  # noqa: F401  (re-exported)
from ..shell import analyze_command


# High-risk SQL injection signatures (distinguishes attacks from benign SQL comments)
SQL_INJECTION_PATTERNS = [
    r"'\s*OR\s*('1'\s*=\s*'1|1\s*=\s*1|'a'\s*=\s*'a')",
    r"\"\s*OR\s*(\"1\"\s*=\s*\"1|1\s*=\s*1|\"a\"\s*=\s*\"a\")",
    r"['\"]\s*;\s*--",                     # Quote termination followed by comment
    r"(?:admin|root)['\"]\s*--",           # Classic auth bypass comment
    r";\s*DROP\s+TABLE\b",
    r";\s*DELETE\s+FROM\b",
    r"UNION\s+ALL\s+SELECT\b",
    r"UNION\s+SELECT\b",
    r"/\*.*?\*/|/\*.*$",                   # Inline comment evasion
]


class TartarusClan:
    """Protects against A03 Injection and OWASP LLM06 Excessive Agency."""

    NAME = "Tartarus"

    @classmethod
    def inspect_command(
        cls,
        command_string: str,
        base_dir: Optional[str] = None,
        policy: Optional[AegisPolicy] = None,
        cwd: Optional[str] = None,
        windows: bool = False,
    ) -> Verdict:
        return analyze_command(command_string, base_dir=base_dir, cwd=cwd, policy=policy, windows=windows)

    @classmethod
    def inspect_sql(cls, query_string: str) -> Verdict:
        if not query_string:
            return Verdict(DecisionLevel.PASS, ["Empty SQL query"], cls.NAME)

        normalized = normalize_text(query_string)
        for pattern in SQL_INJECTION_PATTERNS:
            if re.search(pattern, normalized, re.IGNORECASE):
                return Verdict(
                    DecisionLevel.DENY,
                    [f"SQL injection heuristic triggered: {pattern}"],
                    cls.NAME,
                )

        return Verdict(DecisionLevel.PASS, ["SQL query clean"], cls.NAME)
