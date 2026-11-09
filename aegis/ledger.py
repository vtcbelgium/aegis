"""Aegis decision ledger: append-only, hash-chained and free of secrets.

Every decision becomes one JSON line. Each line carries the digest of the line before it,
so removing, reordering or editing a line breaks the chain and `verify` finds where:

    {"schema": "aegis.decision.v1", "seq": 42, "at": "...", "tool": "start_process",
     "level": "ASK", "clan": "Tartarus", "reasons": [...], "summary": "curl -d @.env ...",
     "argsDigest": "...", "previousDigest": "<line 41>", "eventDigest": "<this line>"}

Rules from the OTHRYS security model:
    - Telemetry is secret-minimised: live credentials are masked before anything is written,
      and the full arguments are stored only as a digest.
    - The ledger is a security log. Changing it is a SECURITY_LOGGING_DISABLE hard boundary
      (hosts list its path in policy.log_paths).
    - Several processes may append at once (one hook process per tool call); a file lock
      keeps the chain linear.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import re
import threading
from dataclasses import dataclass
from typing import Any, Dict, Iterator, List, Optional

from .core import DecisionLevel, Verdict

SCHEMA = "aegis.decision.v1"
ZERO_DIGEST = "0" * 64
MAX_SUMMARY = 240
MAX_REASON = 300

_GENERIC_TOKEN = re.compile(r"[A-Za-z0-9_\-+/=]{32,}")


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def body_digest(body: Dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()


def redact(text: Any, limit: int = MAX_SUMMARY) -> str:
    """Mask credentials and long opaque tokens; never let a raw secret reach the ledger."""
    from .clans.custody import CRITICAL_SECRET_SIGNATURES, MILD_SECRET_SIGNATURES
    s = str(text if text is not None else "")
    s = re.sub(r"-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----.*?"
               r"-----END (?:[A-Z0-9_-]+ )?PRIVATE KEY-----", "[PRIVATE KEY]", s, flags=re.S)
    for pattern, _label in CRITICAL_SECRET_SIGNATURES + MILD_SECRET_SIGNATURES:
        s = re.sub(pattern, "[SECRET]", s)
    s = _GENERIC_TOKEN.sub(lambda m: m.group(0)[:4] + "…[" + str(len(m.group(0))) + "]", s)
    return s if len(s) <= limit else s[:limit] + "…"


def summarize_arguments(tool: str, arguments: Any) -> str:
    """One human line for the ledger: the command, the path, or the argument names."""
    if isinstance(arguments, dict):
        for key in ("command", "cmd", "input", "path", "file_path", "source", "url", "query"):
            val = arguments.get(key)
            if isinstance(val, str) and val:
                extra = ""
                if key == "source" and isinstance(arguments.get("destination"), str):
                    extra = " -> " + arguments["destination"]
                return redact(val + extra)
        if isinstance(arguments.get("paths"), list):
            return redact(", ".join(str(p) for p in arguments["paths"][:5]))
        return redact(f"{tool}({', '.join(sorted(map(str, arguments.keys())))})")
    return redact(f"{tool}(...)")


class _FileLock:
    """Cross-process lock on <ledger>.lock (fcntl on POSIX, msvcrt on Windows)."""

    def __init__(self, path: str) -> None:
        self.path = path + ".lock"
        self._fh = None

    def __enter__(self) -> "_FileLock":
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        self._fh = open(self.path, "a+b")
        try:
            if os.name == "nt":
                import msvcrt
                self._fh.seek(0)
                msvcrt.locking(self._fh.fileno(), msvcrt.LK_LOCK, 1)
            else:
                import fcntl
                fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX)
        except Exception:
            self._fh.close()
            raise
        return self

    def __exit__(self, *exc: Any) -> None:
        try:
            if os.name == "nt":
                import msvcrt
                self._fh.seek(0)
                msvcrt.locking(self._fh.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
        except Exception:
            pass
        self._fh.close()


def _last_line(path: str) -> Optional[str]:
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            end = fh.tell()
            if end == 0:
                return None
            chunk = 4096
            pos = end
            data = b""
            while pos > 0:
                step = min(chunk, pos)
                pos -= step
                fh.seek(pos)
                data = fh.read(step) + data
                lines = data.rstrip(b"\n").split(b"\n")
                if len(lines) > 1 or pos == 0:
                    return lines[-1].decode("utf-8", "replace")
    except FileNotFoundError:
        return None
    return None


@dataclass
class VerifyResult:
    ok: bool
    count: int
    problem: Optional[str] = None
    line: Optional[int] = None
    tip: str = ZERO_DIGEST


class DecisionLedger:
    """Append-only, hash-chained record of Aegis decisions."""

    def __init__(self, path: str, *, min_level: DecisionLevel = DecisionLevel.PASS,
                 max_bytes: int = 20 * 1024 * 1024, session: Optional[str] = None) -> None:
        self.path = os.path.abspath(os.path.expanduser(path))
        self.min_level = min_level
        self.max_bytes = max_bytes
        self.session = session
        self._lock = threading.Lock()

    # -- writing -------------------------------------------------------------

    def _tip(self) -> tuple:
        line = _last_line(self.path)
        if not line:
            return ZERO_DIGEST, 0
        try:
            ev = json.loads(line)
            return str(ev["eventDigest"]), int(ev.get("seq", 0))
        except Exception:
            # A damaged tip is evidence: keep it and start a new file that points back at it.
            return "DAMAGED:" + hashlib.sha256(line.encode("utf-8", "replace")).hexdigest(), 0

    def _rotate_if_needed(self) -> Optional[str]:
        try:
            if os.path.getsize(self.path) < self.max_bytes:
                return None
        except OSError:
            return None
        import uuid
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + "-" + uuid.uuid4().hex
        root, ext = os.path.splitext(self.path)
        rotated = f"{root}.{stamp}{ext or '.jsonl'}"
        os.replace(self.path, rotated)
        return os.path.basename(rotated)

    def append(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock, _FileLock(self.path):
            previous, seq = self._tip()
            continues = self._rotate_if_needed()
            body: Dict[str, Any] = {
                "schema": SCHEMA,
                "seq": seq + 1,
                "at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds"),
            }
            body.update({k: v for k, v in entry.items() if v is not None})
            if self.session and "session" not in body:
                body["session"] = self.session
            if continues:
                body["continues"] = continues
            body["previousDigest"] = previous
            body["eventDigest"] = body_digest(body)
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(canonical_json(body) + "\n")
                fh.flush()
            return body

    def record(self, verdict: Verdict, *, tool: Optional[str] = None, arguments: Any = None,
               approved: bool = False, source: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Write a verdict. Logging failures must stop an enforcing caller."""
        try:
            if verdict.level < self.min_level and not approved:
                return None
            meta = verdict.metadata or {}
            entry: Dict[str, Any] = {
                "tool": tool,
                "level": verdict.level.name,
                "clan": verdict.clan,
                "reasons": [redact(r, MAX_REASON) for r in verdict.reasons[:5]],
                "boundary": meta.get("boundary"),
                "effects": meta.get("effects") or None,
                "impact": meta.get("impact") or None,
                "approved": True if approved or meta.get("approved") else None,
                "source": source or meta.get("source"),
            }
            if arguments is not None:
                entry["summary"] = summarize_arguments(tool or "", arguments)
                entry["argsDigest"] = hashlib.sha256(canonical_json(arguments).encode("utf-8")).hexdigest()
                binary = _binary_of(arguments)
                if binary:
                    entry["binary"] = binary
            def scrub(value):
                if isinstance(value, str):
                    return redact(value, 4096)
                if isinstance(value, dict):
                    return {redact(k): scrub(v) for k, v in value.items()}
                if isinstance(value, (list, tuple)):
                    return [scrub(v) for v in value]
                return value
            entry = {key: (value if key == "argsDigest" else scrub(value)) for key, value in entry.items()}
            return self.append(entry)
        except Exception as exc:
            raise OSError("Aegis decision could not be recorded") from exc

    # -- reading -------------------------------------------------------------

    def entries(self) -> Iterator[Dict[str, Any]]:
        return iter_entries(self.path)

    def tail(self, n: int = 20) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for ev in self.entries():
            out.append(ev)
            if len(out) > n:
                out.pop(0)
        return out

    def verify(self, *, expected_tip: Optional[str] = None) -> VerifyResult:
        return verify(self.path, expected_tip=expected_tip)


def _binary_of(arguments: Any) -> Optional[str]:
    if isinstance(arguments, dict) and isinstance(arguments.get("command"), str):
        first = arguments["command"].strip().split()
        if first:
            return os.path.basename(first[0]).lower()[:40]
    return None


def iter_entries(path: str) -> Iterator[Dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        yield {"_unparseable": line[:200]}
    except FileNotFoundError:
        return


def verify(path: str, expect_previous: Optional[str] = None, *, expected_tip: Optional[str] = None) -> VerifyResult:
    """Check that every line's digest is right and points at the line before it.

    A rotated-in file starts from the previous file's tip; pass that as expect_previous to
    check the link, or leave it out to accept whatever the first line claims.
    """
    previous = expect_previous
    count = 0
    for count, ev in enumerate(iter_entries(path), start=1):
        if not isinstance(ev, dict):
            return VerifyResult(False, count, "line is not an event object", count)
        if "_unparseable" in ev:
            return VerifyResult(False, count, "line is not valid JSON", count)
        claimed = ev.get("eventDigest")
        body = {k: v for k, v in ev.items() if k != "eventDigest"}
        if body_digest(body) != claimed:
            return VerifyResult(False, count, "line was changed after it was written", count)
        if previous is None and count == 1 and not ev.get("continues"):
            if ev.get("seq") != 1 or ev.get("previousDigest") != ZERO_DIGEST:
                return VerifyResult(False, count, "lines are missing at the start of the ledger", count)
        if previous is not None and ev.get("previousDigest") != previous:
            return VerifyResult(False, count, "chain broken: a line before this one was removed, added or reordered", count)
        previous = claimed
    tip = previous or ZERO_DIGEST
    if expected_tip is not None and tip != expected_tip:
        return VerifyResult(False, count, "tip does not match trusted checkpoint (possible tail truncation)", count, tip)
    return VerifyResult(True, count, None, None, tip)


def default_ledger_path() -> str:
    from .boundaries import aegis_home
    return os.path.join(aegis_home(), "ledger.jsonl")
