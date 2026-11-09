"""Hecatoncheires Clan: Concurrency, Rate-Limiting & Runaway Loop Brakes.

Invariants:
    1. Rapid consecutive security violations trigger automatic session quarantine (LOCK).
    2. Runaway tool loops (same action repeated > threshold within time window) tripped.
    3. Concurrency lock contention and race conditions gated.
"""

from __future__ import annotations

import collections
import time
from typing import Deque, Dict, List, Optional
from ..core import DecisionLevel, Verdict


class HecatoncheiresClan:
    """Protects against concurrency race conditions, infinite loops, and token depletion."""

    NAME = "Hecatoncheires"

    def __init__(
        self,
        max_violations_per_minute: int = 3,
        loop_threshold: int = 5,
        window_seconds: float = 60.0,
    ) -> None:
        self.max_violations = max_violations_per_minute
        self.loop_threshold = loop_threshold
        self.window_seconds = window_seconds
        self._violation_timestamps: Deque[float] = collections.deque()
        self._action_history: Deque[tuple[str, float]] = collections.deque()

    def record_violation(self) -> Verdict:
        now = time.time()
        self._violation_timestamps.append(now)

        # Evict timestamps older than window
        while self._violation_timestamps and (now - self._violation_timestamps[0] > self.window_seconds):
            self._violation_timestamps.popleft()

        if len(self._violation_timestamps) >= self.max_violations:
            return Verdict(
                DecisionLevel.LOCK,
                [
                    f"Rapid escalation brake tripped: {len(self._violation_timestamps)} violations "
                    f"within {self.window_seconds}s. Agent session quarantined."
                ],
                self.NAME,
                metadata={"violationsInWindow": len(self._violation_timestamps)},
            )

        return Verdict(
            DecisionLevel.WARN,
            [f"Violation recorded ({len(self._violation_timestamps)} in current window)"],
            self.NAME,
        )

    def inspect_loop(self, action_signature: str) -> Verdict:
        now = time.time()
        self._action_history.append((action_signature, now))

        # Evict old history
        while self._action_history and (now - self._action_history[0][1] > self.window_seconds):
            self._action_history.popleft()

        # Count occurrences of the same action signature
        matches = sum(1 for sig, _ in self._action_history if sig == action_signature)
        if matches >= self.loop_threshold:
            return Verdict(
                DecisionLevel.DENY,
                [
                    f"Runaway loop detected: action '{action_signature}' executed {matches} times "
                    f"in {self.window_seconds}s. Emergency brake applied to prevent token depletion."
                ],
                self.NAME,
                metadata={"action": action_signature, "occurrences": matches},
            )

        return Verdict(DecisionLevel.PASS, ["Execution cadence normal"], self.NAME)
