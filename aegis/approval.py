"""Exact destructive confirmations. A phrase is evidence, never an owner identity."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from typing import Any, Optional

from .core import DecisionLevel, Verdict

SCHEMA = "aegis.destructive-confirmation.v1"


def observe_git(directory: str) -> dict:
    """Read bounded Git metadata without executing Git or exposing its contents."""
    marker = os.path.join(directory, ".git")
    if not os.path.lexists(marker):
        return {"repository": directory, "state": "not-a-repository"}
    def read(path, limit=8 * 1024 * 1024):
        if os.path.islink(path):
            raise ValueError("Git metadata is a symlink")
        try:
            with open(path, "rb") as file:
                data = file.read(limit + 1)
        except FileNotFoundError:
            return None
        if len(data) > limit:
            raise ValueError("Git metadata exceeds review budget")
        return data
    if os.path.isfile(marker):
        pointer = read(marker, 4096).decode("utf-8").strip()
        if not pointer.startswith("gitdir: "):
            raise ValueError("Malformed Git worktree pointer")
        gitdir = os.path.realpath(os.path.join(directory, pointer[8:]))
    else:
        if os.path.islink(marker):
            raise ValueError("Git directory is a symlink")
        gitdir = marker
    if not os.path.isdir(gitdir):
        raise ValueError("Git metadata directory missing")
    common_pointer = read(os.path.join(gitdir, "commondir"), 4096)
    common = os.path.realpath(os.path.join(gitdir, common_pointer.decode().strip())) if common_pointer else gitdir
    head = read(os.path.join(gitdir, "HEAD"), 4096)
    if head is None:
        raise ValueError("Git HEAD missing")
    head_text = head.decode("utf-8").strip()
    paths = [os.path.join(gitdir, name) for name in ("HEAD", "index", "commondir", "config.worktree")]
    paths += [os.path.join(common, name) for name in ("config", "packed-refs")]
    ref = None
    if head_text.startswith("ref: "):
        ref = head_text[5:]
        if not re.fullmatch(r"refs/[A-Za-z0-9_./-]+", ref) or ".." in ref.split("/"):
            raise ValueError("Invalid Git HEAD reference")
        paths.append(os.path.join(common, *ref.split("/")))
    elif not re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", head_text):
        raise ValueError("Invalid detached HEAD")
    files = []
    for path in paths:
        data = read(path)
        files.append({"path": path, "digest": hashlib.sha256(data).hexdigest() if data is not None else None})
    return {"repository": directory, "head": ref or head_text, "files": files}


def bind_confirmation(verdict: Verdict, action: Any) -> Verdict:
    """Bind exact resolved targets and observed impact to the entire proposed action."""
    targets = verdict.metadata.get("destructive") or []
    if verdict.level != DecisionLevel.ASK or not targets:
        return verdict
    observations = verdict.metadata.get("destructive_state")
    if observations is None:
        observations = []
        try:
            for target in targets:
                if str(target.get("operation", "")).startswith("git-"):
                    observations.append(observe_git(target["target"]))
        except (OSError, ValueError, UnicodeError):
            return Verdict(DecisionLevel.DENY, ["Git state unavailable; destructive review cannot be bound safely"], verdict.clan)
        verdict.metadata["destructive_state"] = observations
    unique = []
    for target in targets:
        op, path = target.get("operation"), target.get("target")
        if (not isinstance(op, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", op)
                or not isinstance(path, str) or not path or any(c in path for c in "\r\n\x00*?[]")):
            return Verdict(DecisionLevel.DENY, ["Destructive approval requires exact, unambiguous targets"], verdict.clan)
        item = {"operation": op, "target": path}
        if item not in unique:
            unique.append(item)
    phrase = "\n".join(f"APPROVE DESTRUCTIVE: {t['operation']} :: {t['target']}" for t in unique)
    if len(unique) > 16 or len(phrase) > 8192:
        return Verdict(DecisionLevel.DENY, ["Destructive review is too large; split the action"], verdict.clan)
    body = {"schema": SCHEMA, "targets": unique, "impact": verdict.metadata.get("impact", []),
            "observations": observations, "action": action}
    digest = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    challenge = {"schema": SCHEMA, "phrase": phrase, "digest": digest,
                 "targets": unique, "impact": body["impact"]}
    if len(json.dumps(challenge, ensure_ascii=False).encode("utf-8")) > 12000:
        return Verdict(DecisionLevel.DENY, ["Destructive review is too large; split the action"], verdict.clan)
    verdict.metadata["confirmation"] = challenge
    return verdict


def confirms(verdict: Verdict, phrase: Any, digest: Optional[str] = None) -> bool:
    challenge = verdict.metadata.get("confirmation")
    if not challenge or not isinstance(phrase, str):
        return False
    if digest is not None and not hmac.compare_digest(str(challenge["digest"]), digest):
        return False
    return hmac.compare_digest(challenge["phrase"].encode("utf-8"), phrase.encode("utf-8"))
