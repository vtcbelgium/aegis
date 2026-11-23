"""Regression tests for Aegis v1.0.1 interlock & MOAT-F03/F04 polish."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

from aegis import DecisionLevel, Verdict
from aegis.approval import SCHEMA as CONFIRM_SCHEMA, bind_confirmation, confirms
from aegis.cli import run_pin
from aegis.setup_wizard import (
    antigravity_mcp_path,
    configure_mcp_server,
    detect_hosts,
    vscode_mcp_path,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def _subproc_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO_ROOT) + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    if extra:
        env.update(extra)
    return env


def test_mcp_wrap_cli_alias_roundtrip(tmp_path):
    server_script = tmp_path / "dummy_wrap_srv.py"
    server_script.write_text(
        """
import sys, json
for line in sys.stdin:
    if not line.strip():
        continue
    req = json.loads(line)
    if req.get("method") == "tools/list":
        print(json.dumps({
            "jsonrpc": "2.0",
            "id": req.get("id"),
            "result": {"tools": [{"name": "ping", "description": "Health ping"}]}
        }), flush=True)
    elif req.get("method") == "tools/call":
        print(json.dumps({
            "jsonrpc": "2.0",
            "id": req.get("id"),
            "result": {"content": [{"type": "text", "text": "pong"}]}
        }), flush=True)
""",
        encoding="utf-8",
    )
    pins_file = tmp_path / "pins.json"
    cmd = [
        sys.executable, "-m", "aegis.cli", "mcp", "wrap",
        "--server", "wrap-srv",
        "--pins-file", str(pins_file),
        "--", sys.executable, str(server_script),
    ]
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=str(tmp_path),  # intentionally outside REPO_ROOT
        env=_subproc_env({"AEGIS_HOME": str(tmp_path / "home")}),
    )
    proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": "1", "method": "tools/list"}) + "\n")
    proc.stdin.flush()
    list_resp = json.loads(proc.stdout.readline())
    assert list_resp["result"]["tools"][0]["name"] == "ping"

    proc.stdin.write(json.dumps({
        "jsonrpc": "2.0", "id": "2", "method": "tools/call",
        "params": {"name": "ping", "arguments": {}},
    }) + "\n")
    proc.stdin.flush()
    call_resp = json.loads(proc.stdout.readline())
    assert call_resp["result"]["content"][0]["text"] == "pong"
    proc.stdin.close()
    proc.wait(timeout=5)
    assert proc.returncode == 0


def test_pins_diff_cli_reports_sha_changes_and_json(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("AEGIS_HOME", str(tmp_path / "home"))
    v1 = [{"name": "read_doc", "description": "Read a doc"}, {"name": "old_tool", "description": "Legacy"}]
    v2 = [
        {"name": "read_doc", "description": "Read a doc AND extra note"},
        {"name": "new_tool", "description": "Added tool"},
    ]
    f1 = tmp_path / "v1.json"
    f2 = tmp_path / "v2.json"
    f1.write_text(json.dumps(v1), encoding="utf-8")
    f2.write_text(json.dumps(v2), encoding="utf-8")

    assert run_pin("pin", "srv-a", str(f1)) == 0
    capsys.readouterr()

    assert run_pin("diff", "srv-a", str(f1), as_json=True) == 0
    clean = json.loads(capsys.readouterr().out)
    assert clean["clean"] is True
    assert clean["changes"] == []

    assert run_pin("diff", "srv-a", str(f2), as_json=True) == 2
    diff = json.loads(capsys.readouterr().out)
    assert diff["clean"] is False
    kinds = {c["kind"]: c for c in diff["changes"]}
    assert "changed" in kinds and kinds["changed"]["pinnedSha"] != kinds["changed"]["currentSha"]
    assert "new-tool" in kinds and kinds["new-tool"]["pinnedSha"] is None
    assert "removed" in kinds and kinds["removed"]["currentSha"] is None


def test_setup_wizard_detects_antigravity_vscode_and_native_tekton(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("APPDATA", str(tmp_path / "AppData" / "Roaming"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))
    monkeypatch.setenv("AEGIS_HOME", str(tmp_path / "aegis_home"))

    ag_path = Path(antigravity_mcp_path())
    ag_path.parent.mkdir(parents=True, exist_ok=True)
    ag_path.write_text(json.dumps({
        "mcpServers": {
            "tekton": {"command": "python", "args": ["-m", "tekton", "mcp"]},
            "thirdparty": {"command": "npx", "args": ["-y", "demo-mcp"]},
        }
    }), encoding="utf-8")

    vs_path = Path(vscode_mcp_path())
    vs_path.parent.mkdir(parents=True, exist_ok=True)
    vs_path.write_text(json.dumps({
        "servers": {
            "local-fs": {"type": "stdio", "command": "npx", "args": ["-y", "fs-mcp"]},
        }
    }), encoding="utf-8")

    hosts = detect_hosts()
    assert "antigravity_mcp" in hosts
    assert "vscode_mcp" in hosts
    ag = hosts["antigravity_mcp"]
    assert ag["totalCount"] == 2
    assert ag["protectedCount"] == 1
    assert ag["nativeCount"] == 1
    by_name = {s["name"]: s for s in ag["servers"]}
    assert by_name["tekton"]["nativeAegis"] is True
    assert by_name["tekton"]["protectionKind"] == "tekton-native"
    assert by_name["thirdparty"]["protected"] is False

    # Do not double-wrap native Tekton MCP server
    res_tekton = configure_mcp_server(str(ag_path), "tekton", enable=True)
    assert res_tekton["nativeAegis"] is True
    assert res_tekton["backup"] is None

    # VS Code `"servers"` top-level schema wraps & unwraps cleanly
    res_vs = configure_mcp_server(str(vs_path), "local-fs", enable=True, base_dir=str(tmp_path))
    assert res_vs["protected"] is True
    wrapped_vs = json.loads(vs_path.read_text(encoding="utf-8"))
    assert "mcp-proxy" in wrapped_vs["servers"]["local-fs"]["args"]

    res_vs_off = configure_mcp_server(str(vs_path), "local-fs", enable=False)
    assert res_vs_off["protected"] is False
    unwrapped_vs = json.loads(vs_path.read_text(encoding="utf-8"))
    assert unwrapped_vs["servers"]["local-fs"]["command"] == "npx"


def test_destructive_confirmation_v1_schema_and_golden_vectors(tmp_path):
    schema_path = REPO_ROOT / "docs" / "specs" / "destructive-confirmation-v1.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    assert schema["properties"]["schema"]["const"] == CONFIRM_SCHEMA

    target_dir = str(tmp_path / "build_out")
    verdict = Verdict(
        DecisionLevel.ASK,
        ["Large delete requires owner review"],
        "Tartarus",
        metadata={
            "destructive": [{"operation": "delete", "target": target_dir}],
            "impact": [{"entries": 150, "bytes": 4096, "complete": True}],
        },
    )
    bound = bind_confirmation(verdict, {"tool": "start_process", "command": f"rm -rf {target_dir}"})
    assert bound.level == DecisionLevel.ASK
    c = bound.metadata["confirmation"]

    assert set(c.keys()) == set(schema["required"])
    assert c["schema"] == CONFIRM_SCHEMA
    assert re.fullmatch(schema["properties"]["digest"]["pattern"], c["digest"])
    assert re.fullmatch(schema["properties"]["phrase"]["pattern"], c["phrase"])
    assert c["targets"] == [{"operation": "delete", "target": target_dir}]
    assert c["impact"] == [{"entries": 150, "bytes": 4096, "complete": True}]
    assert c["state"] == []

    # Exact phrase + digest verifies; generic consent or tampered digest fails closed
    assert confirms(bound, c["phrase"], c["digest"]) is True
    assert confirms(bound, "yes", c["digest"]) is False
    assert confirms(bound, c["phrase"], "0" * 64) is False

    # Wildcard target is refused (DENY)
    wild = Verdict(
        DecisionLevel.ASK,
        ["Wildcard delete"],
        "Tartarus",
        metadata={"destructive": [{"operation": "delete", "target": str(tmp_path / "*")}]},
    )
    refused = bind_confirmation(wild, {"tool": "start_process", "command": "rm -rf *"})
    assert refused.level == DecisionLevel.DENY
