"""Hard boundaries: Aegis protects itself, the logs, the backups and the sentinel."""

import os

import pytest

from aegis import AegisGate, AegisHarness, DecisionLevel
from aegis.boundaries import (BACKUP_DESTRUCTION, LOGGING_DISABLE, MASTER_SECRET, POLICY_TAMPER,
                              SENTINEL_TAKEOVER, SYSTEM_DESTRUCTION, is_backup_path)
from aegis.policy import AegisPolicy
from aegis.shell import analyze_command

L = DecisionLevel


@pytest.fixture()
def ws(tmp_path, monkeypatch):
    home = tmp_path / "home"
    work = home / "project"
    (work / "src").mkdir(parents=True)
    (work / "backups").mkdir()
    (work / "src" / "backup_service.py").write_text("x = 1\n")
    (home / "OTHRYS-backups").mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("AEGIS_HOME", str(home / ".aegis"))
    return work


def cmd(c, ws, policy=None, windows=False):
    return analyze_command(c, base_dir=str(ws), policy=policy or AegisPolicy(), windows=windows)


def locked(v, boundary):
    return v.level == L.LOCK and v.metadata.get("boundary") == boundary


@pytest.mark.parametrize("c", [
    "export TEKTON_AEGIS_MODE=off",
    "TEKTON_AEGIS_MODE=off python3 run.py",
    "env AEGIS_HOME=/tmp/x python3 run.py",
    "unset TEKTON_AEGIS_MODE",
    "aegis minotaur reset",
    "python3 -m aegis ledger reset",
    "printf 'x' > ~/.aegis/minotaur.json",
    "rm -rf ~/.aegis",
])
def test_policy_tamper_posix(c, ws):
    assert locked(cmd(c, ws), POLICY_TAMPER), c


@pytest.mark.parametrize("c", [
    "setx TEKTON_AEGIS_MODE off",
    "$env:TEKTON_AEGIS_MODE = 'off'",
    "[Environment]::SetEnvironmentVariable('TEKTON_AEGIS_MODE', 'off', 'User')",
])
def test_policy_tamper_windows(c, ws):
    assert locked(cmd(c, ws, windows=True), POLICY_TAMPER), c


def test_declared_protected_paths(ws):
    dropin = ws.parent / ".config" / "systemd" / "user" / "tekton-relay.service.d" / "aegis.conf"
    pol = AegisPolicy(protected_paths=[str(dropin.parent)], extra_roots=[str(ws.parent)])
    v = cmd(f"printf '[Service]\\nEnvironment=TEKTON_AEGIS_MODE=off\\n' > {dropin}", ws, pol)
    assert locked(v, POLICY_TAMPER)


def test_registry_unreadable_ledger_readable(ws):
    pol = AegisPolicy(extra_roots=[str(ws.parent)], log_paths=[str(ws.parent / ".aegis" / "ledger.jsonl")])
    v = cmd("cat ~/.aegis/minotaur.json", ws, pol)
    assert v.level == L.DENY and v.metadata.get("boundary") is None or v.level == L.DENY
    assert cmd("cat ~/.aegis/ledger.jsonl", ws, pol).level == L.PASS
    assert locked(cmd("printf '' > ~/.aegis/ledger.jsonl", ws, pol), POLICY_TAMPER)


@pytest.mark.parametrize("c,windows", [
    ("systemctl --user stop tekton-relay", False),
    ("systemctl --user disable tekton-relay.service", False),
    ("systemctl --user mask tekton-relay", False),
    ("pkill -f tekton", False),
    ("killall Tekton", False),
    ("taskkill /f /im Tekton.exe", True),
    ("Stop-Process -Name Tekton -Force", True),
    ("schtasks /delete /tn TektonDesktopRelay /f", True),
    (r"reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v TektonDesktopRelay /f", True),
    (r"Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name TektonDesktopRelay", True),
    ("Stop-Service -Name aegis", True),
])
def test_sentinel_takeover(c, windows, ws):
    assert locked(cmd(c, ws, windows=windows), SENTINEL_TAKEOVER), c


def test_guard_service_reads_are_not_takeover(ws):
    for c in ("systemctl --user status tekton-relay", "pkill node", "taskkill /im notepad.exe"):
        v = cmd(c, ws, windows=c.startswith("taskkill"))
        assert v.level == L.ASK, (c, v)


@pytest.mark.parametrize("c,windows", [
    ("wevtutil cl Security", True),
    ("Clear-EventLog -LogName Security", True),
    ("journalctl --vacuum-time=1s", False),
    ("auditctl -D", False),
    ("systemctl stop auditd", False),
    ("rm -rf /var/log/journal", False),
    ("Set-MpPreference -DisableRealtimeMonitoring $true", True),
])
def test_logging_disable(c, windows, ws):
    assert locked(cmd(c, ws, windows=windows), LOGGING_DISABLE), c


@pytest.mark.parametrize("c,windows", [
    ("rm -rf backups", False),
    ("rm -rf ~/OTHRYS-backups", False),
    ("mv backups/db.sql /tmp/x", False),
    ("vssadmin delete shadows /all /quiet", True),
    ("wmic shadowcopy delete", True),
    ("tmutil deletelocalsnapshots /", False),
    ("bcdedit /set {default} recoveryenabled No", True),
    ("btrfs subvolume delete /.snapshots/1/snapshot", False),
])
def test_backup_destruction(c, windows, ws):
    pol = AegisPolicy(extra_roots=[str(ws.parent)])
    assert locked(cmd(c, ws, pol, windows=windows), BACKUP_DESTRUCTION), c


def test_backups_by_directory_not_by_file_name(ws):
    assert not is_backup_path(str(ws / "src" / "backup_service.py"))
    assert is_backup_path(str(ws / "backups" / "db.sql"))
    assert cmd("rm src/backup_service.py", ws).level == L.PASS
    assert cmd("cp src/backup_service.py backups/", ws).level == L.ASK


def test_master_secret_and_system_destruction_are_labelled(ws):
    assert locked(cmd("cat ~/.ssh/id_rsa", ws), MASTER_SECRET)
    assert locked(cmd("rm -rf /", ws), SYSTEM_DESTRUCTION)
    assert locked(cmd("mkfs.ext4 /dev/sda1", ws), SYSTEM_DESTRUCTION)


def test_file_tools_hit_the_same_boundaries(ws):
    def harness():   # a LOCK locks the session, so each check gets a fresh gate
        return AegisHarness(AegisGate(base_dir=str(ws), policy=AegisPolicy(extra_roots=[str(ws.parent)]),
                                      max_violations_per_minute=10**6))
    v = harness().evaluate_tool_call("write_file", {"path": str(ws.parent / ".aegis" / "policy.json"), "content": "{}"})
    assert v.level == L.LOCK and v.metadata["boundary"] == POLICY_TAMPER
    v = harness().evaluate_tool_call("move_file", {"source": str(ws / "backups"), "destination": str(ws / "old")})
    assert v.level == L.LOCK and v.metadata["boundary"] == BACKUP_DESTRUCTION
    assert harness().evaluate_tool_call("read_file", {"path": str(ws / "backups" / "db.sql")}).level == L.PASS


def test_backup_names():
    for name in ("backups", "OTHRYS-backups", "Backups.backupdb", "legion-recovery-2026-10-03",
                 "backup-2026-11-01", ".snapshots", "Recovery", "OTHRYS-Cold-Recovery"):
        assert is_backup_path(f"/home/u/{name}/x", is_dir=False), name
    for name in ("my_backup_scripts", "test_backups_by_directory", "recovery_tools_src", "snapshotting"):
        assert not is_backup_path(f"/home/u/{name}/x", is_dir=False), name


def test_everyday_work_is_unaffected(ws):
    for c in ("git status", "ls -la", "python3 -m pytest -q", "npm test", "rm -rf build",
              "git log --oneline -5", "cat src/backup_service.py", "mkdir -p backups/2026"):
        v = cmd(c, ws)
        assert v.level < L.DENY, (c, v)
