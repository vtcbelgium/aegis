"""Standalone desktop app launcher for Aegis Control Center.

Single-instance, Smart-App-Control-safe on Windows 11 when launched via signed
``pythonw.exe -m aegis desktop``:
    - If Aegis Control Center is already listening on 127.0.0.1:<port>, opens
      the running instance in a clean chromeless desktop app window (Edge/Chrome
      ``--app=`` mode, falling back to the default browser) without spawning a
      duplicate server.
    - Otherwise binds 127.0.0.1:<port> (falling back to the next free loopback
      port), opens the desktop app window, and serves until terminated.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import threading
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path
from typing import List, Optional

from .server import create_server


def _is_aegis_server_alive(port: int, timeout: float = 0.75) -> bool:
    url = f"http://127.0.0.1:{port}/status"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            if resp.status != 200:
                return False
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
            return isinstance(data, dict) and "currentLevel" in data
    except (OSError, ValueError, urllib.error.URLError):
        return False


def _pick_free_port(preferred: int = 9999) -> int:
    for port in (preferred, 9998, 9997, 0):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(("127.0.0.1", port))
                return int(sock.getsockname()[1])
            except OSError:
                continue
    return 0


def _find_chromium_app_browser() -> Optional[str]:
    if sys.platform == "win32":
        pf86 = os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)")
        pf = os.environ.get("PROGRAMFILES", r"C:\Program Files")
        local = os.environ.get("LOCALAPPDATA", "")
        candidates = [
            os.path.join(pf86, "Microsoft", "Edge", "Application", "msedge.exe"),
            os.path.join(pf, "Microsoft", "Edge", "Application", "msedge.exe"),
            os.path.join(pf, "Google", "Chrome", "Application", "chrome.exe"),
            os.path.join(pf86, "Google", "Chrome", "Application", "chrome.exe"),
            os.path.join(local, "Google", "Chrome", "Application", "chrome.exe") if local else "",
        ]
        for cand in candidates:
            if cand and os.path.isfile(cand):
                return cand
        return None

    for name in ("google-chrome", "chromium", "chromium-browser", "microsoft-edge"):
        found = shutil.which(name)
        if found:
            return found
    return None


def open_desktop_window(url: str) -> bool:
    """Open Aegis Control Center in a dedicated chromeless app window when available."""
    browser = _find_chromium_app_browser()
    if browser:
        profile_dir = Path(os.environ.get("LOCALAPPDATA") or str(Path.home() / ".local" / "share")) / "Aegis" / "app-profile"
        try:
            profile_dir.mkdir(parents=True, exist_ok=True)
            argv = [
                browser,
                f"--app={url}",
                f"--user-data-dir={profile_dir}",
                "--window-size=1120,760",
                "--no-first-run",
                "--no-default-browser-check",
            ]
            kwargs = {
                "stdin": subprocess.DEVNULL,
                "stdout": subprocess.DEVNULL,
                "stderr": subprocess.DEVNULL,
                "close_fds": True,
            }
            if sys.platform == "win32":
                kwargs["creationflags"] = (
                    getattr(subprocess, "DETACHED_PROCESS", 0)
                    | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                )
            else:
                kwargs["start_new_session"] = True
            subprocess.Popen(argv, **kwargs)
            return True
        except OSError:
            pass
    try:
        return bool(webbrowser.open(url))
    except Exception:
        return False


def build_ico_from_pngs(png_paths: List[Path], out_path: Path) -> Path:
    """Create a valid multi-resolution PNG-in-ICO file using Python stdlib only."""
    images: List[tuple[int, int, bytes]] = []
    for p in png_paths:
        raw = p.read_bytes()
        if raw[:8] != b"\x89PNG\r\n\x1a\n":
            raise ValueError(f"Not a PNG file: {p}")
        w, h = struct.unpack(">II", raw[16:24])
        images.append((w, h, raw))

    out_path.parent.mkdir(parents=True, exist_ok=True)
    header = struct.pack("<HHH", 0, 1, len(images))
    entries = bytearray()
    payload = bytearray()
    offset = 6 + 16 * len(images)
    for w, h, raw in images:
        bw = 0 if w >= 256 else w
        bh = 0 if h >= 256 else h
        entries.extend(struct.pack("<BBBBHHII", bw, bh, 0, 0, 1, 32, len(raw), offset))
        payload.extend(raw)
        offset += len(raw)
    out_path.write_bytes(header + bytes(entries) + bytes(payload))
    return out_path


def launch_desktop(
    *,
    port: int = 9999,
    base_dir: Optional[str] = None,
    owner_secret: Optional[str] = None,
    no_open: bool = False,
) -> int:
    """Launch Aegis Desktop Control Center (single-instance on loopback)."""
    if _is_aegis_server_alive(port):
        if not no_open:
            open_desktop_window(f"http://127.0.0.1:{port}")
        return 0

    ws = base_dir or os.environ.get("AEGIS_WORKSPACE") or os.getcwd()
    actual_bind = _pick_free_port(port)
    server, _state = create_server(port=actual_bind, base_dir=ws, owner_secret=owner_secret)
    actual_port = server.server_address[1]
    url = f"http://127.0.0.1:{actual_port}"
    if not no_open:
        threading.Timer(0.35, lambda: open_desktop_window(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0
