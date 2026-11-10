"""Exercise real bubblewrap containment when the host supports namespaces."""
import json
import os
import sys

import pytest

from aegis import sandbox


@pytest.fixture(scope="module")
def confinement():
    info = sandbox.probe()
    if not info["works"]:
        pytest.skip(info["error"])


def test_live_workspace_secrets_backup_environment_and_network(confinement, tmp_path, monkeypatch):
    ws = tmp_path / "work"; ws.mkdir()
    (ws / ".env").write_text("REAL_SECRET_FIXTURE")
    (ws / "backups").mkdir()
    backup = ws / "backups" / "restore.txt"; backup.write_text("restore")
    (ws / "backups" / ".env").write_text("BACKUP_SECRET_FIXTURE")
    outside = tmp_path / "outside.txt"; outside.write_text("HOST_ONLY")
    monkeypatch.setenv("AEGIS_LIVE_SECRET_FIXTURE", "MUST_NOT_INHERIT")
    code = '''import json, os, socket
from pathlib import Path
Path("output.txt").write_text("success")
blocked = False
try:
    Path("backups/restore.txt").write_text("destroyed")
except OSError:
    blocked = True
try:
    secret = Path(".env").read_text()
except PermissionError:
    secret = ""
try:
    backup_secret = Path("backups/.env").read_text()
except PermissionError:
    backup_secret = ""
print(json.dumps({"secret": secret, "backupBlocked": blocked,
                  "backupSecret": backup_secret,
                  "environment": os.environ.get("AEGIS_LIVE_SECRET_FIXTURE"),
                  "interfaces": [name for _, name in socket.if_nameindex()],
                  "outside": Path(os.sys.argv[1]).exists()}))
'''
    result = sandbox.run(sandbox.SandboxProfile(str(ws)), ["/usr/bin/python3", "-c", code, str(outside)],
                         capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data == {"secret": "", "backupSecret": "", "backupBlocked": True, "environment": None,
                    "interfaces": ["lo"], "outside": False}
    assert (ws / "output.txt").read_text() == "success"
    assert backup.read_text() == "restore"
    assert (ws / ".env").read_text() == "REAL_SECRET_FIXTURE"
