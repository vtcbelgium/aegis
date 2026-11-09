"""Blast radius: how much a delete would actually remove, measured before it runs.

From the OTHRYS Destructive Action Constitution: "Enforce bounded blast radius; the default
destructive review threshold is 100 filesystem entries or 500 MiB, whichever is reached first.
Exceeding it stops for separate review."

Measuring never follows symlinks and stops as soon as the limit is passed, so even a huge
tree costs at most `max_entries` directory reads.
"""

from __future__ import annotations

import glob
import os
from dataclasses import asdict, dataclass
from typing import List

GLOB_CHARS = set("*?[")
MAX_GLOB_MATCHES = 1000


@dataclass
class Impact:
    target: str
    entries: int
    bytes: int
    exceeded: bool
    complete: bool          # False when the walk stopped early (limit passed or unreadable parts)

    def to_dict(self) -> dict:
        return asdict(self)


def human_bytes(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} B"


def describe(impact: Impact) -> str:
    plus = "+" if not impact.complete else ""
    noun = "item" if impact.entries == 1 else "items"
    return f"{impact.entries:,}{plus} {noun}, {human_bytes(impact.bytes)}{plus}"


def measure(target: str, max_entries: int = 100, max_bytes: int = 500 * 1024 * 1024,
            recursive: bool = True) -> Impact:
    """Count entries and bytes under target (itself included). Stops once a limit is passed."""
    entries = 0
    size = 0
    complete = True
    try:
        st = os.lstat(target)
    except OSError:
        return Impact(target, 0, 0, False, True)
    entries = 1
    if not os.path.isdir(target) or os.path.islink(target) or not recursive:
        size = st.st_size if not os.path.isdir(target) else 0
        return Impact(target, entries, size, entries > max_entries or size > max_bytes, True)
    stack = [target]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                for de in it:
                    entries += 1
                    try:
                        if de.is_dir(follow_symlinks=False):
                            stack.append(de.path)
                        else:
                            size += de.stat(follow_symlinks=False).st_size
                    except OSError:
                        complete = False
                    if entries > max_entries or size > max_bytes:
                        return Impact(target, entries, size, True, False)
        except OSError:
            complete = False
    return Impact(target, entries, size, False, complete)


def expand(target: str) -> List[str]:
    """Glob-expand the last component the way a shell would (capped)."""
    if not (GLOB_CHARS & set(os.path.basename(target))):
        return [target]
    return sorted(glob.glob(target))[:MAX_GLOB_MATCHES]


def measure_delete(target: str, recursive: bool, max_entries: int, max_bytes: int) -> Impact:
    """Measure what `rm [-r] target` would remove, globs included."""
    paths = expand(target)
    entries = 0
    size = 0
    complete = True
    for p in paths:
        imp = measure(p, max_entries - entries, max_bytes - size, recursive=recursive)
        entries += imp.entries
        size += imp.bytes
        complete = complete and imp.complete
        if imp.exceeded or entries > max_entries or size > max_bytes:
            return Impact(target, entries, size, True, False)
    return Impact(target, entries, size, entries > max_entries or size > max_bytes, complete)
