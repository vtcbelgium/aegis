"""Tamper-protected turn baselines & surgical rollback checkpoints inside ~/.aegis/detective/."""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..boundaries import aegis_home


def detective_dir() -> str:
    d = os.path.join(aegis_home(), "detective")
    os.makedirs(d, mode=0o700, exist_ok=True)
    return d


def checkpoints_dir() -> str:
    d = os.path.join(detective_dir(), "checkpoints")
    os.makedirs(d, mode=0o700, exist_ok=True)
    return d


def _atomic_write_json(path: str, data: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path) or ".", mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".det-", dir=os.path.dirname(path) or ".")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
            fh.write("\n")
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except OSError:
                pass
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass


def _run_git(cwd: str, args: List[str], timeout: float = 5.0) -> Optional[str]:
    try:
        res = subprocess.run(
            ["git", "-C", cwd] + args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if res.returncode == 0:
            return res.stdout
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def _has_git_marker(cwd: str) -> bool:
    cur = os.path.abspath(cwd)
    while True:
        if os.path.exists(os.path.join(cur, ".git")):
            return True
        parent = os.path.dirname(cur)
        if parent == cur:
            return False
        cur = parent


def git_snapshot(cwd: str, *, allow_subprocess: bool = True) -> Dict[str, Any]:
    """Capture a lightweight, bounded snapshot of repository HEAD and porcelain status."""
    if not allow_subprocess or not _has_git_marker(cwd):
        return {"isGit": False, "root": os.path.abspath(cwd), "head": None, "dirty": {}, "treeDigest": None}
    root_out = _run_git(cwd, ["rev-parse", "--show-toplevel"])
    if not root_out:
        return {"isGit": False, "root": os.path.abspath(cwd), "head": None, "dirty": {}, "treeDigest": None}
    root = root_out.strip()
    head = (_run_git(root, ["rev-parse", "HEAD"]) or "").strip() or None
    porcelain = _run_git(root, ["status", "--porcelain=v1", "-uall"]) or ""
    dirty: Dict[str, str] = {}
    for line in porcelain.splitlines():
        if len(line) < 4:
            continue
        code = line[:2]
        rel = line[3:].strip()
        if " -> " in rel:
            rel = rel.split(" -> ", 1)[1].strip()
        rel = rel.strip('"')
        dirty[rel.replace("\\", "/")] = code.strip() or "?"
    tree_digest = hashlib.sha256(
        json.dumps({"head": head, "dirty": dirty}, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "isGit": True,
        "root": root,
        "head": head,
        "dirty": dirty,
        "treeDigest": tree_digest,
    }


def start_turn_baseline(cwd: str, *, session_id: str = "default", turn_id: Optional[str] = None) -> Dict[str, Any]:
    """Snapshot git state at turn start inside ~/.aegis/detective/ (protected from agents)."""
    tid = turn_id or (datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + secrets.token_hex(4))
    snap = git_snapshot(cwd)
    record = {
        "schema": "aegis.detective.baseline.v1",
        "turnId": tid,
        "sessionId": session_id,
        "startedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "cwd": os.path.abspath(cwd),
        "git": snap,
        "backedUpFiles": {},
    }
    path = os.path.join(checkpoints_dir(), f"{tid}.json")
    _atomic_write_json(path, record)
    return record


def load_turn_baseline(turn_id: str) -> Optional[Dict[str, Any]]:
    path = os.path.join(checkpoints_dir(), f"{turn_id}.json")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else None
    except (FileNotFoundError, OSError, ValueError):
        return None


def latest_turn_id(session_id: Optional[str] = None) -> Optional[str]:
    cdir = Path(checkpoints_dir())
    candidates = sorted(cdir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    for cand in candidates:
        try:
            data = json.loads(cand.read_text(encoding="utf-8"))
        except Exception:
            continue
        if session_id and data.get("sessionId") != session_id:
            continue
        tid = data.get("turnId")
        if isinstance(tid, str) and tid:
            return tid
    return None


def checkpoint_file_before_edit(turn_id: str, file_path: str, *, max_bytes: int = 2 * 1024 * 1024) -> bool:
    """Save the original pre-turn content of a file before its first mutation in this turn."""
    rec = load_turn_baseline(turn_id)
    if rec is None:
        return False
    abs_path = os.path.abspath(file_path)
    backed = rec.setdefault("backedUpFiles", {})
    if abs_path in backed:
        return True  # already captured original pre-turn state

    blob_dir = os.path.join(checkpoints_dir(), f"{turn_id}.blobs")
    os.makedirs(blob_dir, mode=0o700, exist_ok=True)
    if os.path.isfile(abs_path):
        try:
            size = os.path.getsize(abs_path)
            if size > max_bytes:
                backed[abs_path] = {"existed": True, "skipped": "too_large", "size": size}
            else:
                digest = hashlib.sha256(abs_path.encode("utf-8")).hexdigest()[:16]
                blob_path = os.path.join(blob_dir, f"{digest}.bak")
                shutil.copy2(abs_path, blob_path)
                backed[abs_path] = {"existed": True, "blob": blob_path, "size": size}
        except OSError:
            return False
    else:
        backed[abs_path] = {"existed": False, "blob": None}
    _atomic_write_json(os.path.join(checkpoints_dir(), f"{turn_id}.json"), rec)
    return True


def compute_dirty_delta(baseline: Optional[Dict[str, Any]], cwd: str, *, allow_subprocess: bool = True) -> Dict[str, Any]:
    """Compare live git status against the turn baseline to isolate files changed during this turn."""
    current = git_snapshot(cwd, allow_subprocess=allow_subprocess)
    base_dirty = ((baseline or {}).get("git") or {}).get("dirty") or {}
    cur_dirty = current.get("dirty") or {}
    newly_dirty = sorted(k for k, v in cur_dirty.items() if base_dirty.get(k) != v)
    reverted = sorted(k for k in base_dirty if k not in cur_dirty)
    return {
        "isGit": current["isGit"],
        "root": current["root"],
        "head": current["head"],
        "baselineHead": ((baseline or {}).get("git") or {}).get("head"),
        "newlyDirty": newly_dirty,
        "allDirty": sorted(cur_dirty.keys()),
        "revertedFromBaseline": reverted,
        "treeDigest": current["treeDigest"],
    }
