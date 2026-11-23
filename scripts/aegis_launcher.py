"""Standalone desktop entrypoint for Aegis Control Center (PyInstaller-friendly).

Launches Aegis on 127.0.0.1 (port 9999, or the next available loopback port if busy)
and opens the offline Control Center in the user's default browser.
"""

from __future__ import annotations

import os
import socket
import sys

from aegis.server import run_server


def _pick_port(preferred: int = 9999) -> int:
    for port in (preferred, 9998, 9997, 0):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(("127.0.0.1", port))
                return sock.getsockname()[1]
            except OSError:
                continue
    return 0


def main() -> None:
    if sys.platform == "win32":
        try:
            if hasattr(sys.stdout, "reconfigure"):
                sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    base_dir = os.environ.get("AEGIS_WORKSPACE") or os.getcwd()
    port = int(os.environ.get("AEGIS_PORT") or _pick_port(9999))
    run_server(port=port, base_dir=base_dir, open_browser=True)


if __name__ == "__main__":
    main()
