"""Offline unit tests for the Aegis <-> Tekton integration bridge & desktop launcher."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from pathlib import Path

from aegis import desktop, tekton_bridge
from aegis.server import create_server


def _http_json(url: str, *, method: str = "GET", body: dict | None = None, token: str = "") -> tuple[int, dict]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Aegis-Token"] = token
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def test_tekton_bridge_not_installed(monkeypatch):
    monkeypatch.setattr(tekton_bridge, "find_tekton_binary", lambda: None)
    status = tekton_bridge.get_tekton_status()
    assert status["installed"] is False
    assert status["doctor"] is None
    assert status["approvals"] == []


def test_tekton_bridge_status_and_sync_policy_floor(monkeypatch, tmp_path: Path):
    fake_bin = str(tmp_path / "tekton.cmd")
    Path(fake_bin).write_text("@echo off\r\n", encoding="utf-8")
    floor_path = tmp_path / "tekton-data" / "aegis" / "policy.json"

    def fake_run(args, *, binary=None, timeout=8.0):
        if args[:2] == ["doctor", "--json"]:
            return {
                "ok": True,
                "returncode": 0,
                "json": {
                    "ok": True,
                    "version": "1.5.0",
                    "aegis_gate_version": "1.1.1",
                    "aegis_mode": "enforce",
                    "policy_floor": {"active": floor_path.is_file(), "ok": True, "path": str(floor_path)},
                    "allowed_directories": [str(tmp_path)],
                    "node_id": "lattice-test-node",
                    "ledger": {"ok": True, "count": 42},
                },
                "error": None,
            }
        if args[:2] == ["relay-status", "--json"]:
            return {
                "ok": True,
                "returncode": 0,
                "json": {
                    "devices": [
                        {"node_id": "lattice-test-node", "display_name": "Workstation", "online": True, "heartbeat_age_seconds": 1},
                        {"node_id": "lattice-nas", "display_name": "NAS", "online": False, "heartbeat_age_seconds": 999},
                    ],
                    "pending_pairs": [],
                },
                "error": None,
            }
        if args[:2] == ["approvals", "--json"]:
            return {"ok": True, "returncode": 0, "json": [], "error": None}
        return {"ok": True, "returncode": 0, "stdout": "OK", "json": None, "error": None}

    monkeypatch.setattr(tekton_bridge, "_run_tekton", fake_run)
    monkeypatch.setattr(tekton_bridge, "find_tekton_binary", lambda: fake_bin)
    monkeypatch.setattr(tekton_bridge, "load_policy_file", lambda: {"unknown_binary": "deny", "secret_level": "lock"})

    st = tekton_bridge.get_tekton_status()
    assert st["installed"] is True
    assert st["doctor"]["version"] == "1.5.0"
    assert st["fleetSummary"] == {"online": 1, "total": 2, "pendingPairs": 0}

    sync = tekton_bridge.sync_policy_floor()
    assert sync["ok"] is True
    assert floor_path.is_file()
    saved = json.loads(floor_path.read_text(encoding="utf-8"))
    assert saved["unknown_binary"] == "deny"


def test_server_tekton_endpoints_and_ui_presence(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(tekton_bridge, "find_tekton_binary", lambda: "/fake/tekton")
    monkeypatch.setattr(
        tekton_bridge,
        "get_tekton_status",
        lambda include_relay=True: {
            "installed": True,
            "binary": "/fake/tekton",
            "doctor": {"version": "1.5.0", "aegis_gate_version": "1.1.1"},
            "relay": {"devices": [], "pending_pairs": []},
            "fleetSummary": {"online": 0, "total": 0, "pendingPairs": 0},
            "approvals": [],
            "pendingApprovalCount": 0,
        },
    )
    monkeypatch.setattr(tekton_bridge, "launch_tekton_gui", lambda: {"ok": True, "pid": 12345})

    server, state = create_server(port=0, base_dir=str(tmp_path), ledger_path=str(tmp_path / "ledger.jsonl"))
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        base = f"http://127.0.0.1:{port}"
        with urllib.request.urlopen(base + "/", timeout=5) as resp:
            html = resp.read().decode("utf-8")
        assert 'data-view="tekton"' in html
        assert "Tekton integration" in html
        assert "Open Tekton GUI" in html
        assert 'data-view="help"' in html
        assert "Help and quick manual" in html
        assert "Stop server" in html

        code, body = _http_json(base + "/api/tekton")
        assert code == 200
        assert body["installed"] is True
        assert body["doctor"]["version"] == "1.5.0"

        code_diag, diag = _http_json(base + "/api/diagnostics")
        assert code_diag == 200
        assert diag["baseDir"] == str(tmp_path)
        assert "owner_secret" not in json.dumps(diag)

        code_exp, exp = _http_json(base + "/api/ledger/export")
        assert code_exp == 200
        assert "verify" in exp and "entries" in exp

        # Mutating endpoints require valid X-Aegis-Token
        code_unauth, _ = _http_json(base + "/api/tekton/launch-gui", method="POST", body={})
        assert code_unauth == 403
        code_ws_unauth, _ = _http_json(base + "/api/workspace", method="POST", body={"path": str(tmp_path)})
        assert code_ws_unauth == 403
        code_sd_unauth, _ = _http_json(base + "/api/shutdown", method="POST", body={})
        assert code_sd_unauth == 403

        sub_ws = tmp_path / "other-project"
        sub_ws.mkdir()
        code_ws, ws_res = _http_json(base + "/api/workspace", method="POST", body={"path": str(sub_ws)}, token=state.owner_secret)
        assert code_ws == 200
        assert ws_res["baseDir"] == str(sub_ws)

        code_bad_ws, _ = _http_json(base + "/api/workspace", method="POST", body={"path": str(tmp_path / "missing")}, token=state.owner_secret)
        assert code_bad_ws == 400

        code_auth, res = _http_json(base + "/api/tekton/launch-gui", method="POST", body={}, token=state.owner_secret)
        assert code_auth == 200
        assert res["ok"] is True
        assert res["pid"] == 12345

        assert desktop._is_aegis_server_alive(port) is True
    finally:
        server.shutdown()
        server.server_close()


def test_build_ico_from_pngs(tmp_path: Path):
    repo_root = Path(__file__).resolve().parent.parent
    icons = [
        repo_root / "browser-extension" / "icons" / "icon16.png",
        repo_root / "browser-extension" / "icons" / "icon48.png",
        repo_root / "browser-extension" / "icons" / "icon128.png",
    ]
    out = desktop.build_ico_from_pngs(icons, tmp_path / "aegis.ico")
    raw = out.read_bytes()
    assert raw[:4] == b"\x00\x00\x01\x00"
    assert len(raw) > 2500
