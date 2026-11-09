"""Minotaur: the sensor in the Labyrinth. Stateful behaviour, never an authority.

From the OTHRYS Book of Aegis: "Minotaur — future stateful behavioral/anomaly correlation;
a sensor, never an authority-granting oracle." And Pack 03: "Detection is probabilistic
evidence; authorization remains deterministic." So Minotaur may only raise a verdict's
severity (ASK, DENY, LOCK). It can never make one milder.

Three jobs, all AI-agnostic (they watch the tool calls, not which model made them):

1. Tripwires. Decoy files and fake "canary" credentials planted where a thief would look
   but ordinary work never goes. Touching a decoy path, or any appearance of a canary value
   in an argument or in tool output, is an instant LOCK. You and your own programs never go
   through Aegis, so only an agent can trip one — almost always a sign of prompt injection.

2. The data-leak guard (the "lethal trifecta"). A session leaks when three things combine:
   it read private data, it took in untrusted content, and it can send data out. Minotaur
   remembers the first two per session; when egress appears with both already set, it asks
   (or denies). You don't have to spot the hidden instruction — you stop the combination.

3. Credential hunting. Many distinct sensitive locations probed in a short window looks like
   an agent sweeping for secrets, not doing a task; Minotaur escalates.

The registry of decoys and canaries is itself protected (aegis/boundaries.py makes it
unreadable to agents), so an agent cannot list the tripwires in order to avoid them.
"""

from __future__ import annotations

import collections
import hashlib
import json
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Deque, Dict, FrozenSet, Iterable, List, Optional, Tuple

from ..core import DecisionLevel, Verdict

NAME = "Minotaur"
L = DecisionLevel
REGISTRY_SCHEMA = "aegis.minotaur.v1"
TRIPWIRE = "MINOTAUR_TRIPWIRE"
LEAK = "MINOTAUR_DATA_LEAK"
HUNT = "MINOTAUR_CREDENTIAL_HUNT"


def _norm(path: str) -> str:
    return (path or "").replace("\\", "/").rstrip("/").lower() or "/"


# ---------------------------------------------------------------------------
# Tripwires: decoy paths + canary tokens
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Tripwires:
    """Loaded decoy paths and canary token values. Held on the policy; read by every clan."""

    decoy_paths: FrozenSet[str] = frozenset()      # resolved, normalised absolute paths
    canaries: Tuple[str, ...] = ()                  # literal fake-secret values to match
    _canary_min: int = 12

    def match_path(self, abs_path: str) -> bool:
        if not abs_path or not self.decoy_paths:
            return False
        p = _norm(abs_path)
        return p in self.decoy_paths or any(p.startswith(d + "/") for d in self.decoy_paths)

    def match_text(self, text: str) -> Optional[str]:
        """Return the canary found in text (or None). Exact substring, case-sensitive."""
        if not text or not self.canaries:
            return None
        for c in self.canaries:
            if len(c) >= self._canary_min and c in text:
                return c
        return None

    @property
    def active(self) -> bool:
        return bool(self.decoy_paths or self.canaries)

    # -- persistence --------------------------------------------------------

    @classmethod
    def load(cls, path: Optional[str] = None) -> "Tripwires":
        from ..boundaries import minotaur_registry_path
        path = path or minotaur_registry_path()
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return cls()
        decoys = frozenset(_norm(d["path"]) for d in data.get("decoys", []) if d.get("path"))
        canaries = tuple(c for c in data.get("canaries", []) if isinstance(c, str))
        return cls(decoy_paths=decoys, canaries=canaries)


# Fake, non-functional credential shapes. They look real so an agent cannot tell a decoy
# from the real thing, but the random body authenticates nowhere.
def _mint_canary(kind: str) -> str:
    body = secrets.token_hex(20)
    b62 = re.sub(r"[^A-Za-z0-9]", "", secrets.token_urlsafe(40))
    return {
        "aws": "AKIA" + secrets.token_hex(8).upper()[:16],
        "github": "ghp_" + b62[:36],
        "openai": "sk-" + b62[:44],
        "stripe": "sk_live_" + b62[:24],
        "generic": "AG-CANARY-" + body,
    }.get(kind, "AG-CANARY-" + body)


DEFAULT_DECOYS = (
    ("{home}/passwords.txt", "generic"),
    ("{home}/Desktop/credentials.txt", "aws"),
    ("{home}/Documents/api_keys_backup.txt", "openai"),
    ("{workspace}/.env.production.bak", "stripe"),
    ("{workspace}/secrets.backup.json", "github"),
)


def plant(workspace: Optional[str] = None, home: Optional[str] = None,
          registry_path: Optional[str] = None, specs: Optional[Iterable[Tuple[str, str]]] = None) -> Dict:
    """Write decoy files with canary tokens and save the registry. Returns a summary.

    Idempotent per path: an existing decoy keeps its canary. Never overwrites a file Aegis
    did not plant (it checks for the registry marker line).
    """
    from ..boundaries import minotaur_registry_path
    home = os.path.abspath(os.path.expanduser(home or "~"))
    workspace = os.path.abspath(os.path.expanduser(workspace or os.getcwd()))
    registry_path = registry_path or minotaur_registry_path()
    marker = "# aegis-minotaur decoy — do not edit; a security tripwire watches this file"

    existing = {}
    try:
        with open(registry_path, "r", encoding="utf-8") as fh:
            for d in json.load(fh).get("decoys", []):
                existing[_norm(d["path"])] = d
    except (OSError, ValueError):
        pass

    decoys: List[Dict] = []
    canaries: List[str] = []
    planted, kept = [], []
    for template, kind in (specs or DEFAULT_DECOYS):
        path = os.path.abspath(template.format(home=home, workspace=workspace))
        prior = existing.get(_norm(path))
        if prior and os.path.exists(path):
            decoys.append(prior)
            canaries.append(prior["canary"])
            kept.append(path)
            continue
        canary = _mint_canary(kind)
        content = f"{marker}\n{_decoy_body(kind, canary)}\n"
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(content)
            os.utime(path, (time.time() - 86400 * 30, time.time() - 86400 * 30))  # look old
        except OSError:
            continue
        decoys.append({"path": path, "canary": canary, "kind": kind})
        canaries.append(canary)
        planted.append(path)

    os.makedirs(os.path.dirname(registry_path), exist_ok=True)
    tmp = registry_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump({"schema": REGISTRY_SCHEMA, "decoys": decoys, "canaries": canaries}, fh, indent=1)
    os.replace(tmp, registry_path)
    try:
        os.chmod(registry_path, 0o600)
    except OSError:
        pass
    return {"planted": planted, "kept": kept, "registry": registry_path, "count": len(decoys)}


def _decoy_body(kind: str, canary: str) -> str:
    if kind == "aws":
        return f"[default]\naws_access_key_id = {canary}\naws_secret_access_key = {secrets.token_hex(20)}"
    if kind == "github":
        return f"GITHUB_TOKEN={canary}\nGH_USER=release-bot"
    if kind == "openai":
        return f"OPENAI_API_KEY={canary}\nORG=org-prod"
    if kind == "stripe":
        return f"STRIPE_SECRET_KEY={canary}\nSTRIPE_WEBHOOK=whsec_{secrets.token_hex(16)}"
    return f"admin_password={canary}\ndb_root={secrets.token_hex(12)}"


# ---------------------------------------------------------------------------
# The stateful sensor
# ---------------------------------------------------------------------------

class MinotaurClan:
    """Per-session behaviour sensor. Subtractive only: it raises severity, never lowers it."""

    def __init__(self, tripwires: Optional[Tripwires] = None, leak_guard: str = "ask",
                 probe_threshold: int = 4, memory_seconds: float = 1800.0,
                 hunt_window_seconds: float = 120.0) -> None:
        self.tripwires = tripwires or Tripwires()
        self.leak_guard = leak_guard            # "ask", "deny" or "off"
        self.probe_threshold = probe_threshold
        self.memory_seconds = memory_seconds
        self.hunt_window = hunt_window_seconds
        self._lock = threading.Lock()
        self._read_private_at: Optional[float] = None
        self._read_untrusted_at: Optional[float] = None
        self._probes: Deque[Tuple[str, float]] = collections.deque()
        self._tripped = False

    def _fresh(self, at: Optional[float], now: float) -> bool:
        return at is not None and (now - at) <= self.memory_seconds

    def inspect_effects(self, effects: Iterable[str], *, sensitive_target: Optional[str] = None) -> Verdict:
        """Fold one tool call's effects into the session and return any escalation.

        effects come from the clans' verdict metadata: "read_private", "fetch" (untrusted
        content ingested) and "egress" (data can leave).
        """
        effects = set(effects or ())
        now = time.time()
        with self._lock:
            if "read_private" in effects:
                self._read_private_at = now
            if "fetch" in effects:
                self._read_untrusted_at = now
            if sensitive_target:
                self._probes.append((_norm(sensitive_target), now))
                while self._probes and now - self._probes[0][1] > self.hunt_window:
                    self._probes.popleft()
                distinct = len({p for p, _ in self._probes})
                if distinct >= self.probe_threshold:
                    return Verdict(L.ASK, [f"Credential hunt: {distinct} different sensitive locations probed "
                                           f"in {int(self.hunt_window)}s"], NAME, metadata={"boundary": HUNT})
            if "egress" in effects and self.leak_guard != "off":
                priv = self._fresh(self._read_private_at, now)
                unt = self._fresh(self._read_untrusted_at, now)
                if priv and unt:
                    level = L.DENY if self.leak_guard == "deny" else L.ASK
                    return Verdict(level, ["Data-leak guard: this session read private data and untrusted "
                                           "content, and is now sending data out (possible exfiltration)"],
                                   NAME, metadata={"boundary": LEAK, "effects": sorted(effects)})
        return Verdict(L.PASS, ["Session behaviour normal"], NAME)

    def inspect_content(self, text: str) -> Optional[Verdict]:
        """Scan any text (an argument, or tool output) for a canary token. LOCK on a hit."""
        hit = self.tripwires.match_text(text)
        if hit:
            with self._lock:
                self._tripped = True
            return Verdict(L.LOCK, ["Minotaur tripwire: a decoy credential appeared in a tool call or its output"],
                           NAME, metadata={"boundary": TRIPWIRE})
        return None

    def snapshot(self) -> Dict:
        now = time.time()
        with self._lock:
            return {
                "tripwiresActive": self.tripwires.active,
                "decoys": len(self.tripwires.decoy_paths),
                "canaries": len(self.tripwires.canaries),
                "readPrivate": self._fresh(self._read_private_at, now),
                "readUntrusted": self._fresh(self._read_untrusted_at, now),
                "leakGuard": self.leak_guard,
                "tripped": self._tripped,
            }
