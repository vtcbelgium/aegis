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

import collections
import datetime
import hashlib
import hmac
import os
import threading
import time
from enum import IntEnum
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple


class DecisionLevel(IntEnum):
    """The 7-level monotonic decision scale."""
    PASS = 0        # Fully compliant with negative invariant.
    OBSERVE = 1     # Low-risk anomaly recorded for auditing.
    WARN = 2        # Heuristic detection; flagged in telemetry.
    ASK = 3         # Suspicious or sensitive mutation requiring human owner approval (Tekton).
    RESTRICT = 4    # Dangerous parameters stripped or permissions degraded to read-only.
    DENY = 5        # Current proposed action/mutation is completely blocked.
    LOCK = 6        # Fatal security event; agent session quarantined.


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
        """True only if the action passed without requiring approval, restriction, or denial."""
        return self.level < DecisionLevel.ASK

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
    """The Sovereign Negative Gate.

    Escalation rules:
        - Only agent-initiated DENY and LOCK verdicts count toward the rapid-violation brake.
          ASK (waiting for the owner) and WARN never lock a session on their own.
        - Findings in tool *responses* (content the agent received, e.g. a web page that
          mentions prompt injection) are recorded with escalate=False: they are redacted,
          logged, and never raise the session level. Otherwise any website could lock an agent.
        - ASK verdicts go to approval_callback when one is configured. The callback runs
          outside the gate lock, so a slow human approval never blocks other evaluations.
    """

    MAX_AUDIT_LOG = 10_000
    MAX_PENDING = 200

    def __init__(
        self,
        base_dir: Optional[str] = None,
        fail_closed: bool = True,
        strict_mode: bool = False,
        owner_secret: Optional[str] = None,
        max_violations_per_minute: int = 3,
        violation_window_seconds: float = 60.0,
        approval_callback: Optional[Callable[[Verdict], bool]] = None,
        policy: Optional[Any] = None,
    ) -> None:
        from .policy import AegisPolicy

        if strict_mode and base_dir is None:
            self.base_dir = os.path.abspath(os.getcwd())
        else:
            self.base_dir = base_dir
        self.fail_closed = fail_closed
        self.strict_mode = strict_mode
        self.policy = policy or AegisPolicy(strict_tools=strict_mode)
        self.max_violations_per_minute = max_violations_per_minute
        self.violation_window_seconds = violation_window_seconds
        self.approval_callback = approval_callback
        self._current_level: DecisionLevel = DecisionLevel.PASS
        self._audit_log: Deque[Verdict] = collections.deque(maxlen=self.MAX_AUDIT_LOG)
        self._total_evaluations = 0
        self._violations_recorded = 0
        self._pending_approvals: Deque[Verdict] = collections.deque(maxlen=self.MAX_PENDING)
        self._violation_timestamps: Deque[float] = collections.deque()
        self._lock = threading.Lock()
        self._owner_token_hash = (
            hashlib.sha256(owner_secret.encode("utf-8")).hexdigest()
            if owner_secret
            else None
        )

    @property
    def current_level(self) -> DecisionLevel:
        """Current session escalation level."""
        with self._lock:
            return self._current_level

    def escalate(self, new_level: DecisionLevel) -> DecisionLevel:
        """Monotonically escalate session level. Never de-escalates."""
        with self._lock:
            if new_level > self._current_level:
                self._current_level = new_level
            return self._current_level

    def reset_session(self, owner_token: str) -> bool:
        """Only an explicit, verified owner secret may reset the session."""
        if not owner_token or not self._owner_token_hash:
            return False
        provided_hash = hashlib.sha256(owner_token.encode("utf-8")).hexdigest()
        if hmac.compare_digest(provided_hash, self._owner_token_hash):
            with self._lock:
                self._current_level = DecisionLevel.PASS
                self._violation_timestamps.clear()
                self._pending_approvals.clear()
            return True
        return False

    def get_pending_approvals(self) -> List[Dict[str, Any]]:
        """List sensitive actions currently awaiting human owner approval."""
        with self._lock:
            return [v.to_dict() for v in self._pending_approvals]

    def record(self, verdict: Verdict, escalate: bool = True) -> Verdict:
        """Record a verdict; route ASK to the approver; apply escalation rules (see class doc)."""
        # 1. Human-in-the-loop approval, outside the lock
        if escalate and verdict.level == DecisionLevel.ASK and self.approval_callback:
            try:
                approved = bool(self.approval_callback(verdict))
            except Exception:
                approved = False
            if approved:
                verdict = Verdict(
                    DecisionLevel.PASS,
                    [f"Approved by human owner: {'; '.join(verdict.reasons)}"],
                    verdict.clan,
                    metadata={**verdict.metadata, "approved": True},
                )

        with self._lock:
            self._audit_log.append(verdict)
            self._total_evaluations += 1
            if verdict.level >= DecisionLevel.WARN:
                self._violations_recorded += 1
            if not escalate:
                verdict.metadata.setdefault("escalated", False)
                return verdict
            if verdict.level == DecisionLevel.ASK:
                self._pending_approvals.append(verdict)
            if verdict.level >= DecisionLevel.DENY:
                now = time.time()
                self._violation_timestamps.append(now)
                while self._violation_timestamps and (now - self._violation_timestamps[0] > self.violation_window_seconds):
                    self._violation_timestamps.popleft()
                if len(self._violation_timestamps) >= self.max_violations_per_minute:
                    self._current_level = DecisionLevel.LOCK
            if verdict.level > self._current_level:
                self._current_level = verdict.level
        return verdict

    def snapshot(self) -> Dict[str, Any]:
        """Telemetry snapshot of the current gate state."""
        with self._lock:
            return {
                "supremeLaw": SUPREME_LAW,
                "authorityDelta": "SUBTRACTIVE_ONLY",
                "currentLevel": self._current_level.name,
                "currentLevelValue": int(self._current_level),
                "totalEvaluations": self._total_evaluations,
                "pendingApprovals": len(self._pending_approvals),
                "violationsRecorded": self._violations_recorded,
                "history": [v.to_dict() for v in list(self._audit_log)[-20:]],
            }
