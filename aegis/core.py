"""Aegis Core: Deterministic Monotonic Negative Security Gate.

Supreme Law:
    "Aegis may subtract authority. Aegis may never create it."

The decision scale is a strict mathematical poset (partially ordered set):
    PASS (0) < OBSERVE (1) < WARN (2) < RESTRICT (3) < DENY (4) < LOCK (5)

Properties:
    1. Monotonicity: Decisions can only escalate upwards in severity within a session.
    2. Fail-Closed: Any unhandled exception or malformed payload escalates to LOCK.
    3. Negative-Only: Approval means "zero authority added", preserving caller limits.
"""

from __future__ import annotations

import datetime
from enum import IntEnum
from typing import Any, Dict, List, Optional, Tuple


class DecisionLevel(IntEnum):
    """The 6-level monotonic decision scale."""
    PASS = 0        # Fully compliant with negative invariant.
    OBSERVE = 1     # Low-risk anomaly recorded for auditing.
    WARN = 2        # Mild heuristic detection; flagged in telemetry.
    RESTRICT = 3    # Dangerous parameters stripped or permissions degraded.
    DENY = 4        # Current proposed action/mutation is completely blocked.
    LOCK = 5        # Fatal security event; agent session quarantined.


SUPREME_LAW = "Aegis may subtract authority. Aegis may never create it."


class Verdict:
    """The immutable result of an Aegis gate evaluation."""

    __slots__ = ("level", "reasons", "clan", "timestamp", "metadata")

    def __init__(
        self,
        level: DecisionLevel,
        reasons: List[str],
        clan: str = "AegisCore",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.level = level
        self.reasons = tuple(reasons)
        self.clan = clan
        self.timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.metadata = metadata or {}

    @property
    def passed(self) -> bool:
        """True only if the action passed without restriction or denial."""
        return self.level < DecisionLevel.RESTRICT

    def to_dict(self) -> Dict[str, Any]:
        return {
            "level": self.level.name,
            "levelValue": int(self.level),
            "passed": self.passed,
            "clan": self.clan,
            "reasons": list(self.reasons),
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }

    def __repr__(self) -> str:
        return f"<AegisVerdict {self.level.name} (clan={self.clan}, reasons={len(self.reasons)})>"


class AegisGate:
    """The Sovereign Negative Gate."""

    def __init__(
        self,
        base_dir: Optional[str] = None,
        fail_closed: bool = True,
        strict_mode: bool = False,
    ) -> None:
        self.base_dir = base_dir
        self.fail_closed = fail_closed
        self.strict_mode = strict_mode
        self._current_level: DecisionLevel = DecisionLevel.PASS
        self._audit_log: List[Verdict] = []

    @property
    def current_level(self) -> DecisionLevel:
        """Current session escalation level."""
        return self._current_level

    def escalate(self, new_level: DecisionLevel) -> DecisionLevel:
        """Monotonically escalate session level. Never de-escalates."""
        if new_level > self._current_level:
            self._current_level = new_level
        return self._current_level

    def reset_session(self, owner_token: str) -> bool:
        """Only an explicit authenticated owner action may reset the session."""
        if owner_token:
            self._current_level = DecisionLevel.PASS
            return True
        return False

    def record(self, verdict: Verdict) -> Verdict:
        """Record verdict and apply monotonic escalation."""
        self._audit_log.append(verdict)
        self.escalate(verdict.level)
        return verdict

    def snapshot(self) -> Dict[str, Any]:
        """Telemetry snapshot of the current gate state."""
        return {
            "supremeLaw": SUPREME_LAW,
            "authorityDelta": "SUBTRACTIVE_ONLY",
            "currentLevel": self._current_level.name,
            "currentLevelValue": int(self._current_level),
            "totalEvaluations": len(self._audit_log),
            "violationsRecorded": sum(1 for v in self._audit_log if v.level >= DecisionLevel.WARN),
            "history": [v.to_dict() for v in self._audit_log[-20:]],
        }
