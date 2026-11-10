"""Exact destructive confirmations. A phrase is evidence, never an owner identity."""
from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Any, Optional

from .core import DecisionLevel, Verdict

SCHEMA = "aegis.destructive-confirmation.v1"


def bind_confirmation(verdict: Verdict, action: Any) -> Verdict:
    """Bind exact resolved targets and observed impact to the entire proposed action."""
    targets = verdict.metadata.get("destructive") or []
    if verdict.level != DecisionLevel.ASK or not targets:
        return verdict
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
    body = {"schema": SCHEMA, "targets": unique, "impact": verdict.metadata.get("impact", []), "action": action}
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
