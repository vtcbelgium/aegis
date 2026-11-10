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
import hashlib
import os
import re
import time
from typing import Any, Dict, Optional
from contextlib import contextmanager

from .core import DecisionLevel
from .ledger import _FileLock  # reuse the cross-process lock

_SAFE_ID = re.compile(r"[^A-Za-z0-9_.-]")
MAX_AGE_SECONDS = 24 * 3600


def sessions_dir() -> str:
    from .boundaries import aegis_home
    return os.path.join(aegis_home(), "sessions")


def _path(session_id: str, directory: Optional[str] = None) -> str:
    if not isinstance(session_id, str) or not session_id:
        raise ValueError("A nonempty session id is required")
    sid = hashlib.sha256(session_id.encode("utf-8")).hexdigest()
    return os.path.join(directory or sessions_dir(), f"{sid}.json")


def load(session_id: str, *, directory: Optional[str] = None) -> Dict[str, Any]:
    try:
        try:
            fh = open(_path(session_id, directory), "r", encoding="utf-8")
        except FileNotFoundError:
            # Preserve quarantines written by 1.0's original hook implementation.
            legacy = _SAFE_ID.sub("_", session_id)[:120]
            fh = open(os.path.join(directory or sessions_dir(), legacy + ".json"), "r", encoding="utf-8")
        with fh:
            data = json.load(fh)
        if not isinstance(data, dict) or type(data.get("level")) is not int:
            raise ValueError("Invalid Aegis session state")
        DecisionLevel(data["level"])
        if not isinstance(data.get("minotaur", {}), dict):
            raise ValueError("Invalid Minotaur state")
        return data
    except FileNotFoundError:
        return {}


def save(session_id: str, level: DecisionLevel, minotaur_state: Optional[Dict[str, Any]], *,
         directory: Optional[str] = None) -> None:
    path = _path(session_id, directory)
    import tempfile
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".session-", dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump({"at": time.time(), "level": int(level), "minotaur": minotaur_state or {}}, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


@contextmanager
def transaction(session_id: str, *, directory: Optional[str] = None):
    """Serialize the entire read/evaluate/write cycle, including post hooks."""
    with _FileLock(_path(session_id, directory)):
        yield


def apply_to_gate(gate, session_id: str, *, directory: Optional[str] = None) -> None:
    """Rehydrate a gate from the stored session (level + Minotaur memory)."""
    data = load(session_id, directory=directory)
    if not data:
        return
    gate.escalate(DecisionLevel(data["level"]))
    if gate.minotaur is not None and data.get("minotaur"):
        gate.minotaur.import_state(data["minotaur"])


def persist_from_gate(gate, session_id: str, *, directory: Optional[str] = None) -> None:
    minotaur_state = gate.minotaur.export_state() if gate.minotaur is not None else None
    save(session_id, gate.current_level, minotaur_state, directory=directory)
