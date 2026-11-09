"""Tool pinning: catch MCP servers that change their tools after you trusted them.

An MCP server describes its tools to the agent. Two known attacks:
    - Tool poisoning: hidden instructions in a tool description steer the agent.
    - Rug pull: a tool you approved later changes its description to something malicious.
    - Cross-server shadowing: a second server defines a tool whose name/description
      impersonates a trusted one.

Aegis records a fingerprint (SHA-256) of each server's tool definitions the first time you
accept them, in ~/.aegis/pins.json, and checks later listings against it — all on your
machine, nothing sent anywhere. This complements, and does not replace, the per-call gate:
pinning watches the *catalogue*; the clans watch each *call*.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

SCHEMA = "aegis.pins.v1"
_INSTRUCTIONISH = re.compile(
    r"ignore (?:all )?previous|disregard|system prompt|do not tell|secretly|exfiltrat|"
    r"<important>|\bBEGIN\b.*\bKEY\b|base64|\.env\b|~/\.ssh|credential", re.IGNORECASE)


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     default=str).encode("utf-8")).hexdigest()


def tool_fingerprint(tool: Dict[str, Any]) -> str:
    """Stable digest of the parts of a tool definition that change its behaviour."""
    return _digest({"name": tool.get("name"), "description": tool.get("description") or "",
                    "inputSchema": tool.get("inputSchema") or tool.get("input_schema") or {}})


@dataclass
class Change:
    server: str
    kind: str          # new-server, new-tool, changed, removed, shadow, suspicious-text
    tool: str
    detail: str

    def to_dict(self) -> dict:
        return {"server": self.server, "kind": self.kind, "tool": self.tool, "detail": self.detail}


def default_pins_path() -> str:
    from .boundaries import aegis_home
    return os.path.join(aegis_home(), "pins.json")


class ToolPins:
    """Store and compare MCP tool-catalogue fingerprints."""

    def __init__(self, path: Optional[str] = None) -> None:
        self.path = path or default_pins_path()
        self._data = self._load()

    def _load(self) -> Dict[str, Any]:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                d = json.load(fh)
                if isinstance(d, dict) and d.get("schema") == SCHEMA:
                    return d
        except (OSError, ValueError):
            pass
        return {"schema": SCHEMA, "servers": {}}

    def _save(self) -> None:
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self._data, fh, indent=1)
        os.replace(tmp, self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def _known_tool_names(self, exclude: str) -> Dict[str, str]:
        names: Dict[str, str] = {}
        for server, rec in self._data["servers"].items():
            if server == exclude:
                continue
            for name in rec.get("tools", {}):
                names[name] = server
        return names

    def check(self, server: str, tools: List[Dict[str, Any]]) -> List[Change]:
        """Compare a server's current tools against what was pinned. Does not modify state."""
        changes: List[Change] = []
        rec = self._data["servers"].get(server)
        current = {t.get("name", f"tool{i}"): tool_fingerprint(t) for i, t in enumerate(tools)}

        # Descriptions that read like instructions (tool poisoning), whether pinned or not.
        for t in tools:
            text = (t.get("description") or "") + json.dumps(t.get("inputSchema") or {})
            if _INSTRUCTIONISH.search(text):
                changes.append(Change(server, "suspicious-text", t.get("name", "?"),
                                      "tool description contains instruction-like or secret-seeking text"))

        # Cross-server shadowing: a tool name already owned by another pinned server.
        others = self._known_tool_names(exclude=server)
        for name in current:
            if name in others:
                changes.append(Change(server, "shadow", name, f"name also provided by '{others[name]}'"))

        if rec is None:
            changes.append(Change(server, "new-server", "*", f"{len(tools)} tools not seen before"))
            return changes

        pinned = rec.get("tools", {})
        for name, fp in current.items():
            if name not in pinned:
                changes.append(Change(server, "new-tool", name, "tool added since you approved this server"))
            elif pinned[name] != fp:
                changes.append(Change(server, "changed", name, "tool definition changed since you approved it"))
        for name in pinned:
            if name not in current:
                changes.append(Change(server, "removed", name, "previously pinned tool is gone"))
        return changes

    def pin(self, server: str, tools: List[Dict[str, Any]]) -> None:
        """Accept a server's current tools as trusted (first run, or after you reviewed a change)."""
        self._data["servers"][server] = {
            "tools": {t.get("name", f"tool{i}"): tool_fingerprint(t) for i, t in enumerate(tools)},
            "pinnedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        self._save()

    def pin_if_new(self, server: str, tools: List[Dict[str, Any]]) -> List[Change]:
        """Check, and pin automatically only when the server is brand new. Returns changes."""
        changes = self.check(server, tools)
        if server not in self._data["servers"]:
            self.pin(server, tools)
        return changes
