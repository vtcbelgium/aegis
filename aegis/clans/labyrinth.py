"""Labyrinth Clan: Filesystem Containment & Traversal Defense.

Invariants:
    1. Zero access outside approved base_dir.
    2. Null bytes or multi-encoded traversal (%252e) immediately DENIED.
    3. Traversal dots (..) resolved and verified against commonpath.
"""

from __future__ import annotations

import os
from typing import List, Optional
from ..core import DecisionLevel, Verdict
from ..canonicalizer import canonicalize_path, detect_null_bytes, unquote_recursively, normalize_text


class LabyrinthClan:
    """Protects against A01 Broken Access Control & path traversal."""

    NAME = "Labyrinth"

    @classmethod
    def inspect_path(cls, path_input: str, base_dir: Optional[str] = None) -> Verdict:
        reasons: List[str] = []

        if not path_input:
            return Verdict(DecisionLevel.PASS, ["Empty path input"], cls.NAME)

        # 1. Null-byte truncation check
        if detect_null_bytes(path_input):
            return Verdict(
                DecisionLevel.LOCK,
                ["Critical null-byte path truncation attempt detected"],
                cls.NAME,
            )

        # 2. Multi-level URL encoding evasion check
        _, evasion = unquote_recursively(path_input)
        if evasion:
            reasons.append("Multi-level URL encoding evasion detected in path")

        # 3. Path traversal relative indicators
        normalized = normalize_text(path_input)
        if ".." in normalized or "..\\" in normalized or "../" in normalized:
            reasons.append("Relative path traversal sequence (..) detected")

        # 4. Strict base_dir boundary containment
        if base_dir:
            resolved, is_confined = canonicalize_path(base_dir, path_input)
            if not is_confined:
                reasons.append(f"Target path escapes base directory: {base_dir}")
                return Verdict(
                    DecisionLevel.DENY,
                    reasons,
                    cls.NAME,
                    metadata={"target": path_input, "baseDir": base_dir},
                )

        if reasons:
            level = DecisionLevel.WARN if len(reasons) == 1 and not base_dir else DecisionLevel.DENY
            return Verdict(level, reasons, cls.NAME)

        return Verdict(DecisionLevel.PASS, ["Path is within sovereign boundaries"], cls.NAME)
