"""Per-session state that survives across processes.

Hook-style integrations spawn a fresh process for every tool call, so the gate's in-memory
session (the monotonic level, Minotaur's memory of what was read) would be lost between
calls. This stores a session's state in ~/.aegis/sessions/<id>.json under a file lock, so a
LOCK stays locked and the data-leak guard still sees the whole session.

In-process integrations (the MCP proxy, the Python harness) keep one long-lived gate and do
not need this.
"""

from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Dict, Optional

from .core import DecisionLevel
from .ledger import _FileLock  # reuse the cross-process lock

_SAFE_ID = re.compile(r"[^A-Za-z0-9_.-]")
MAX_AGE_SECONDS = 24 * 3600


def sessions_dir() -> str:
    from .boundaries import aegis_home
    return os.path.join(aegis_home(), "sessions")


def _path(session_id: str) -> str:
    sid = _SAFE_ID.sub("_", session_id or "default")[:120]
    return os.path.join(sessions_dir(), f"{sid}.json")


def load(session_id: str) -> Dict[str, Any]:
    try:
        with open(_path(session_id), "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if time.time() - data.get("at", 0) > MAX_AGE_SECONDS:
            return {}
        return data
    except (OSError, ValueError):
        return {}


def save(session_id: str, level: DecisionLevel, minotaur_state: Optional[Dict[str, Any]]) -> None:
    path = _path(session_id)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with _FileLock(path):
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump({"at": time.time(), "level": int(level), "minotaur": minotaur_state or {}}, fh)
            os.replace(tmp, path)
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
    except OSError:
        pass


def apply_to_gate(gate, session_id: str) -> None:
    """Rehydrate a gate from the stored session (level + Minotaur memory)."""
    data = load(session_id)
    if not data:
        return
    try:
        gate.escalate(DecisionLevel(int(data.get("level", 0))))
    except (ValueError, TypeError):
        pass
    if gate.minotaur is not None and data.get("minotaur"):
        gate.minotaur.import_state(data["minotaur"])


def persist_from_gate(gate, session_id: str) -> None:
    minotaur_state = gate.minotaur.export_state() if gate.minotaur is not None else None
    save(session_id, gate.current_level, minotaur_state)
