"""Hecatoncheires Clan: Concurrency, Rate-Limiting & Runaway Loop Brakes.

Invariants:
    1. Rapid consecutive security violations trigger automatic session quarantine (LOCK).
    2. Runaway tool loops (same action repeated > threshold within time window) tripped.
    3. Concurrency lock contention and race conditions gated.
"""

from __future__ import annotations

import collections
import threading
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
        self._lock = threading.Lock()
        self._violation_timestamps: Deque[float] = collections.deque()
        self._action_history: Deque[tuple[str, float]] = collections.deque()

    def record_violation(self) -> Verdict:
        with self._lock:
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
        with self._lock:
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

    def export_state(self) -> Dict[str, object]:
        """Export bounded window state so hook subprocesses retain loop and violation history."""
        with self._lock:
            now = time.time()
            while self._violation_timestamps and (now - self._violation_timestamps[0] > self.window_seconds):
                self._violation_timestamps.popleft()
            while self._action_history and (now - self._action_history[0][1] > self.window_seconds):
                self._action_history.popleft()
            return {
                "violations": list(self._violation_timestamps)[-64:],
                "actions": [[sig, ts] for sig, ts in list(self._action_history)[-128:]],
            }

    def import_state(self, state: Optional[Dict[str, object]]) -> None:
        """Restore persisted loop and violation history (monotonically bounded to active window)."""
        if not isinstance(state, dict):
            return
        now = time.time()
        with self._lock:
            raw_v = state.get("violations")
            if isinstance(raw_v, list):
                valid_v = [float(t) for t in raw_v if isinstance(t, (int, float)) and (now - float(t) <= self.window_seconds)]
                self._violation_timestamps = collections.deque(valid_v[-64:])
            raw_a = state.get("actions")
            if isinstance(raw_a, list):
                valid_a = []
                for item in raw_a:
                    if isinstance(item, (list, tuple)) and len(item) == 2 and isinstance(item[0], str) and isinstance(item[1], (int, float)):
                        ts = float(item[1])
                        if now - ts <= self.window_seconds:
                            valid_a.append((item[0], ts))
                self._action_history = collections.deque(valid_a[-128:])
