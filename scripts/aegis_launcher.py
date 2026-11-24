"""Standalone desktop entrypoint for Aegis Control Center (PyInstaller-friendly).

Launches Aegis on 127.0.0.1 (port 9999, or the next available loopback port if busy)
and opens the offline Control Center in the user's default browser.
"""

from __future__ import annotations

import os
import sys

from aegis.desktop import launch_desktop


def main() -> None:
    if sys.platform == "win32":
        try:
            if hasattr(sys.stdout, "reconfigure"):
                sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    base_dir = os.environ.get("AEGIS_WORKSPACE") or os.getcwd()
    port = int(os.environ.get("AEGIS_PORT") or "9999")
    raise SystemExit(launch_desktop(port=port, base_dir=base_dir, no_open=False))


if __name__ == "__main__":
    main()
