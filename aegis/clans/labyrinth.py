"""Labyrinth Clan: Filesystem Containment & Traversal Defense.

Invariants:
    1. Zero access outside approved base_dir (after expanding ~, $HOME, ${HOME},
       %USERPROFILE%, $env:USERPROFILE and resolving symlinks).
    2. Null bytes -> LOCK. Credential stores (~/.ssh, ~/.aws, /etc/shadow ...) -> DENY.
    3. Startup/persistence files (.bashrc, autostart, cron) -> DENY.
    4. Secret-bearing project files (.env, credentials.json) -> ASK the owner.
    5. Paths with variables Aegis cannot resolve -> ASK the owner.
"""

from __future__ import annotations

from typing import Iterable, List, Optional

from .. import boundaries
from ..core import DecisionLevel, Verdict
from ..canonicalizer import detect_null_bytes, is_inside, normalize_text, resolve_path, unquote_recursively
from ..policy import SENSITIVE_PATH_PATTERNS, classify_sensitive  # noqa: F401  (re-exported)


class LabyrinthClan:
    """Protects against A01 Broken Access Control & path traversal."""

    NAME = "Labyrinth"

    @classmethod
    def inspect_path(
        cls,
        path_input: str,
        base_dir: Optional[str] = None,
        cwd: Optional[str] = None,
        mode: str = "read",
        critical_level: DecisionLevel = DecisionLevel.DENY,
        extra_roots: Optional[Iterable[str]] = None,
        policy: Optional[object] = None,
    ) -> Verdict:
        """Evaluate one path argument.

        mode is "read", "write", "delete", "exec", "cd" or "upload" and only changes
        how secret-bearing files are treated (reading asks, uploading denies).
        """
        if not path_input:
            return Verdict(DecisionLevel.PASS, ["Empty path input"], cls.NAME)

        # 1. Null-byte truncation -> LOCK
        if detect_null_bytes(path_input):
            return Verdict(DecisionLevel.LOCK, ["Critical null-byte path truncation attempt detected"], cls.NAME)

        normalized = normalize_text(path_input)
        lower = normalized.lower()

        # 2. Windows Alternate Data Streams / trailing-dot tricks
        if "::$data" in lower or path_input.endswith("....") or path_input.endswith("   "):
            return Verdict(DecisionLevel.DENY, ["Windows Alternate Data Stream or trailing normalization bypass detected"], cls.NAME)

        # 3. Resolve exactly once with the shared normalizer
        abs_path, confined, unresolved = resolve_path(path_input, base_dir=base_dir, cwd=cwd)
        if confined is False and extra_roots and any(is_inside(abs_path, r) for r in extra_roots):
            confined = True
        decoded, multi_encoded = unquote_recursively(normalized)

        # 4. Minotaur decoys and the hard boundaries (Aegis's own state, logs, backups)
        if not unresolved:
            trip = getattr(policy, "tripwires", None)
            if trip is not None and trip.match_path(abs_path):
                return Verdict(DecisionLevel.LOCK, [f"Minotaur tripwire: a decoy file was touched ({path_input})"],
                               "Minotaur", metadata={"boundary": "MINOTAUR_TRIPWIRE", "resolved": abs_path})
            hit = boundaries.check_path(abs_path, mode, policy)
            if hit:
                boundary, level, reason = hit
                return Verdict(DecisionLevel[level], [reason], cls.NAME,
                               metadata={"boundary": boundary, "resolved": abs_path})

        # 5. Sensitive locations (checked on raw, decoded and resolved spellings)
        sensitivity = classify_sensitive(normalized, decoded, abs_path)
        if sensitivity == "critical":
            return Verdict(critical_level, [f"Target is a credential or system store: {path_input}"], cls.NAME,
                           metadata={"target": path_input, "resolved": abs_path, "boundary": boundaries.MASTER_SECRET})
        if sensitivity == "startup" and mode != "read":
            return Verdict(DecisionLevel.DENY, [f"Target is a startup/persistence location: {path_input}"], cls.NAME,
                           metadata={"target": path_input, "resolved": abs_path})

        # 5. Containment
        if base_dir:
            if unresolved:
                return Verdict(DecisionLevel.ASK, [f"Path contains a variable Aegis cannot resolve: {path_input}"], cls.NAME,
                               metadata={"target": path_input})
            if not confined:
                return Verdict(DecisionLevel.DENY, [f"Target path escapes base directory: {base_dir}"], cls.NAME,
                               metadata={"target": path_input, "resolved": abs_path, "baseDir": base_dir})
        else:
            # Without a workspace there is nothing to verify '..' against: refuse it.
            if ".." in decoded.replace("\\", "/").split("/"):
                return Verdict(DecisionLevel.DENY, ["Relative path traversal (..) with no base directory to verify against"],
                               cls.NAME, metadata={"target": path_input})
            if unresolved:
                return Verdict(DecisionLevel.ASK, [f"Path contains a variable Aegis cannot resolve: {path_input}"], cls.NAME)

        if sensitivity == "startup":
            return Verdict(DecisionLevel.ASK, [f"Reading a shell startup/history file: {path_input}"], cls.NAME)
        if sensitivity == "secret":
            if mode == "upload":
                return Verdict(DecisionLevel.DENY, [f"Uploading a secret-bearing file: {path_input}"], cls.NAME)
            if mode in ("read", "exec"):
                return Verdict(DecisionLevel.ASK, [f"Reading a secret-bearing file requires owner approval: {path_input}"], cls.NAME,
                               metadata={"effects": ["read_private"]})

        if sensitivity == "autoexec" and mode != "read":
            return Verdict(DecisionLevel.ASK, [f"Writes a file that runs code automatically later (hook/.envrc): {path_input}"], cls.NAME)

        reasons: List[str] = ["Path is within sovereign boundaries"]
        level = DecisionLevel.PASS
        if multi_encoded:
            level, reasons = DecisionLevel.WARN, ["Multi-level URL encoding in path (resolved safely)"]
        return Verdict(level, reasons, cls.NAME, metadata={"resolved": abs_path})
