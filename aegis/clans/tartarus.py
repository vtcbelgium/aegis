"""Tartarus Clan: Command Injection, Destructive Operations & SQL Shield.

Invariants:
    1. Shell command injection sequences (; && || | ` $()) detected and contained.
    2. Destructive file operations (rm -rf /, format, mkfs, drop database) blocked.
    3. Untrusted raw SQL injection patterns quarantined.
"""

from __future__ import annotations

import re
import shlex
from typing import List
from ..core import DecisionLevel, Verdict
from ..canonicalizer import normalize_text


# Destructive operating system commands that autonomous agents must never run
DESTRUCTIVE_COMMANDS = {
    "rm -rf /",
    "rm -rf /*",
    ":(){ :|:& };:",   # Fork bomb
    "mkfs",
    "dd if=",
    "chmod -R 777 /",
    "chown -R",
    "format c:",
    "del /f /s /q c:\\",
}

# Suspicious command injection chains
SHELL_INJECTION_PATTERNS = [
    r";\s*(rm|del|shutdown|reboot|curl|wget|nc|bash|sh|powershell)\b",
    r"\|\s*(bash|sh|powershell|cmd)\b",
    r"`[^`]+`",                    # Backtick evaluation
    r"\$\([^)]+\)",                # Subshell execution $(...)
    r"&\s*(curl|wget|nc)\b",       # Background exfiltration
]

# High-risk SQL injection signatures
SQL_INJECTION_PATTERNS = [
    r"'\s*OR\s*'1'\s*=\s*'1",
    r"\"\s*OR\s*\"1\"\s*=\s*\"1",
    r"--\s*$",
    r";\s*DROP\s+TABLE",
    r";\s*DELETE\s+FROM",
    r"UNION\s+ALL\s+SELECT",
    r"UNION\s+SELECT",
]


class TartarusClan:
    """Protects against A03 Injection and OWASP LLM06 Excessive Agency."""

    NAME = "Tartarus"

    @classmethod
    def inspect_command(cls, command_string: str) -> Verdict:
        if not command_string:
            return Verdict(DecisionLevel.PASS, ["Empty command"], cls.NAME)

        normalized = normalize_text(command_string).strip()
        reasons: List[str] = []

        # 1. Catastrophic destruction check -> Immediate LOCK
        lower_cmd = normalized.lower()
        for destructive in DESTRUCTIVE_COMMANDS:
            if destructive in lower_cmd:
                return Verdict(
                    DecisionLevel.LOCK,
                    [f"Catastrophic destructive command blocked: {destructive}"],
                    cls.NAME,
                )

        # 2. Shell injection chaining patterns -> DENY
        for pattern in SHELL_INJECTION_PATTERNS:
            if re.search(pattern, normalized, re.IGNORECASE):
                reasons.append(f"Suspicious shell injection / chaining pattern: {pattern}")

        # 3. Token-based analysis with shlex
        try:
            tokens = shlex.split(normalized)
            if tokens and tokens[0] in {"sudo", "su", "pkexec"}:
                reasons.append("Unauthorized privilege escalation binary invocation")
        except Exception:
            # Malformed quoting is often an injection artifact
            reasons.append("Unbalanced shell quoting or parser evasion detected")

        if reasons:
            level = DecisionLevel.LOCK if "LOCK" in "".join(reasons) else DecisionLevel.DENY
            return Verdict(level, reasons, cls.NAME)

        return Verdict(DecisionLevel.PASS, ["Command passed Tartarus inspection"], cls.NAME)

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
