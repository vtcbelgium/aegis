"""Optional local Tekton runtime bridge for Aegis Control Center.

Zero proprietary Tekton code or secrets live in Aegis. When a local ``tekton``
CLI is installed on the host, this bridge queries its public CLI JSON surfaces
(``doctor``, ``relay-status``, ``approvals``) and forwards explicit owner
actions (launch Tekton GUI, sync monotonic policy floor, workspace allow-list,
approval decisions, pairing, and unlock) with ``shell=False``.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from .config import default_policy_path, load_policy_file, save_policy_file

_CREATE_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0
_DETACHED_FLAGS = (
    (getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | _CREATE_NO_WINDOW)
    if sys.platform == "win32"
    else 0
)


def find_tekton_binary() -> Optional[str]:
    """Return the path to a locally installed Tekton CLI binary, or None."""
    env_override = os.environ.get("AEGIS_TEKTON_BIN", "").strip()
    if env_override and os.path.isfile(env_override):
        return os.path.abspath(env_override)

    home = Path.home()
    candidates: List[Path] = []
    if sys.platform == "win32":
        candidates.extend([
            home / ".local" / "bin" / "tekton.cmd",
            home / ".local" / "bin" / "tekton.exe",
        ])
    else:
        candidates.append(home / ".local" / "bin" / "tekton")

    for cand in candidates:
        if cand.is_file():
            return str(cand)

    for name in ("tekton", "tekton.cmd", "tekton.exe"):
        found = shutil.which(name)
        if found:
            return found
    return None


def _resolve_tekton_argv(binary: str, args: List[str], *, windowed: bool = False) -> List[str]:
    """Prefer invoking the wrapped venv python directly when `tekton.cmd` is a shim.

    Calling `python.exe` / `pythonw.exe` directly avoids `cmd.exe` quoting quirks
    and eliminates Windows console window flashes.
    """
    if sys.platform == "win32" and binary.lower().endswith(".cmd"):
        try:
            text = Path(binary).read_text(encoding="utf-8", errors="ignore")
            for line in text.splitlines():
                line = line.strip()
                if "-m tekton" in line and ".exe" in line.lower():
                    first = line.split('"')[1] if line.startswith('"') and line.count('"') >= 2 else line.split()[0]
                    if os.path.isfile(first):
                        if windowed and first.lower().endswith("python.exe"):
                            pyw = first[:-10] + "pythonw.exe"
                            if os.path.isfile(pyw):
                                first = pyw
                        return [first, "-m", "tekton", *args]
        except OSError:
            pass
    return [binary, *args]


def _run_tekton(
    args: List[str],
    *,
    binary: Optional[str] = None,
    timeout: float = 8.0,
) -> Dict[str, Any]:
    exe = binary or find_tekton_binary()
    if not exe:
        return {"ok": False, "returncode": -1, "error": "Tekton runtime is not installed on this host."}
    argv = _resolve_tekton_argv(exe, args, windowed=False)
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            creationflags=_CREATE_NO_WINDOW,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "returncode": -2, "error": f"Tekton command timed out: {' '.join(args)}"}
    except OSError as exc:
        return {"ok": False, "returncode": -3, "error": str(exc)}

    stdout = (proc.stdout or "").strip()
    stderr = (proc.stderr or "").strip()
    parsed: Any = None
    if stdout:
        try:
            parsed = json.loads(stdout)
        except ValueError:
            parsed = None
    return {
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "json": parsed,
        "error": None if proc.returncode == 0 else (stderr or stdout or f"Exited with code {proc.returncode}"),
    }


def get_tekton_status(*, include_relay: bool = True, binary: Optional[str] = None) -> Dict[str, Any]:
    """Return live Tekton diagnostics, fleet relay status, and pending local approvals."""
    exe = binary or find_tekton_binary()
    if not exe:
        return {
            "installed": False,
            "binary": None,
            "doctor": None,
            "relay": None,
            "approvals": [],
            "aegisPolicyPath": default_policy_path(),
        }

    doc_res = _run_tekton(["doctor", "--json"], binary=exe, timeout=8.0)
    doctor = doc_res["json"] if isinstance(doc_res.get("json"), dict) else None

    appr_res = _run_tekton(["approvals", "--json"], binary=exe, timeout=6.0)
    approvals = appr_res["json"] if isinstance(appr_res.get("json"), list) else []

    relay: Optional[Dict[str, Any]] = None
    relay_error: Optional[str] = None
    if include_relay:
        rel_res = _run_tekton(["relay-status", "--json"], binary=exe, timeout=8.0)
        if isinstance(rel_res.get("json"), dict):
            relay = rel_res["json"]
        elif not rel_res["ok"]:
            relay_error = rel_res.get("error")

    devices = relay.get("devices") if isinstance(relay, dict) and isinstance(relay.get("devices"), list) else []
    online_count = sum(1 for d in devices if isinstance(d, dict) and d.get("online"))
    pending_pairs = relay.get("pending_pairs") if isinstance(relay, dict) and isinstance(relay.get("pending_pairs"), list) else []

    return {
        "installed": True,
        "binary": exe,
        "doctor": doctor,
        "doctorError": None if doctor is not None else doc_res.get("error"),
        "relay": relay,
        "relayError": relay_error,
        "fleetSummary": {
            "online": online_count,
            "total": len(devices),
            "pendingPairs": len(pending_pairs),
        },
        "approvals": approvals,
        "pendingApprovalCount": len(approvals),
        "aegisPolicyPath": default_policy_path(),
    }


def launch_tekton_gui(*, binary: Optional[str] = None) -> Dict[str, Any]:
    """Launch the native Tekton Control Center GUI detached from Aegis."""
    exe = binary or find_tekton_binary()
    if not exe:
        return {"ok": False, "error": "Tekton runtime is not installed on this host."}
    argv = _resolve_tekton_argv(exe, ["gui"], windowed=True)
    try:
        kwargs: Dict[str, Any] = {
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
            "close_fds": True,
        }
        if sys.platform == "win32":
            kwargs["creationflags"] = _DETACHED_FLAGS
        else:
            kwargs["start_new_session"] = True
        proc = subprocess.Popen(argv, **kwargs)
        return {"ok": True, "pid": proc.pid, "command": argv[0]}
    except OSError as exc:
        return {"ok": False, "error": str(exc)}


def sync_policy_floor(*, binary: Optional[str] = None) -> Dict[str, Any]:
    """Sync ~/.aegis/policy.json into Tekton's monotonic Aegis policy floor path."""
    exe = binary or find_tekton_binary()
    if not exe:
        return {"ok": False, "error": "Tekton runtime is not installed on this host."}
    doc_res = _run_tekton(["doctor", "--json"], binary=exe, timeout=8.0)
    doctor = doc_res["json"] if isinstance(doc_res.get("json"), dict) else None
    if not doctor:
        return {"ok": False, "error": doc_res.get("error") or "Could not query Tekton doctor"}

    pf = doctor.get("policy_floor") if isinstance(doctor.get("policy_floor"), dict) else {}
    target_path = str(pf.get("path") or "").strip()
    if not target_path:
        data_dir = str(doctor.get("data_dir") or "").strip()
        if not data_dir:
            return {"ok": False, "error": "Tekton did not report a policy_floor path (requires Tekton >= 1.5.0)."}
        target_path = os.path.join(data_dir, "aegis", "policy.json")

    current_policy = load_policy_file()
    saved = save_policy_file(current_policy, path=target_path)
    return {
        "ok": True,
        "source": default_policy_path(),
        "target": target_path,
        "config": saved,
    }


def allow_workspace_dir(path: str, *, binary: Optional[str] = None) -> Dict[str, Any]:
    cleaned = (path or "").strip()
    if not cleaned:
        return {"ok": False, "error": "Provide a workspace directory path."}
    if not os.path.isdir(cleaned):
        return {"ok": False, "error": f"Directory does not exist: {cleaned}"}
    res = _run_tekton(["allow-dir", os.path.abspath(cleaned)], binary=binary, timeout=8.0)
    return {"ok": res["ok"], "output": res.get("stdout") or "", "error": res.get("error")}


def remove_workspace_dir(path: str, *, binary: Optional[str] = None) -> Dict[str, Any]:
    cleaned = (path or "").strip()
    if not cleaned:
        return {"ok": False, "error": "Provide a workspace directory path to remove."}
    res = _run_tekton(["remove-dir", cleaned], binary=binary, timeout=8.0)
    return {"ok": res["ok"], "output": res.get("stdout") or "", "error": res.get("error")}


def decide_tekton_approval(approval_id: str, decision: str, *, binary: Optional[str] = None) -> Dict[str, Any]:
    aid = (approval_id or "").strip()
    if not aid:
        return {"ok": False, "error": "Missing approval id."}
    if decision not in ("approve", "deny"):
        return {"ok": False, "error": "decision must be 'approve' or 'deny'."}
    res = _run_tekton([decision, aid], binary=binary, timeout=8.0)
    return {"ok": res["ok"], "output": res.get("stdout") or "", "error": res.get("error")}


def approve_pair_request(pair_id: str, *, binary: Optional[str] = None) -> Dict[str, Any]:
    pid = (pair_id or "").strip()
    if not pid:
        return {"ok": False, "error": "Missing pair request UUID."}
    res = _run_tekton(["pair-approve", pid], binary=binary, timeout=10.0)
    return {"ok": res["ok"], "output": res.get("stdout") or "", "error": res.get("error")}


def unlock_tekton_session(*, binary: Optional[str] = None) -> Dict[str, Any]:
    res = _run_tekton(["unlock"], binary=binary, timeout=8.0)
    return {"ok": res["ok"], "output": res.get("stdout") or "", "error": res.get("error")}
