"""Tartarus confinement: the bwrap profile built from a policy, and fail-closed behaviour.

bubblewrap is not installed in CI, so these tests fake its presence to check the argv we
build, and verify we fail closed when it is genuinely unavailable. A live run is exercised
on the T590 (Linux, bwrap present).
"""

import os

import pytest

from aegis import sandbox
from aegis.policy import AegisPolicy
from aegis.sandbox import SandboxProfile, SandboxUnavailable


@pytest.fixture()
def fake_bwrap(tmp_path, monkeypatch):
    bw = tmp_path / "bwrap"; bw.write_text("#!/bin/sh\n"); bw.chmod(0o755)
    monkeypatch.setattr(sandbox, "bwrap_path", lambda: str(bw))
    monkeypatch.setattr(sandbox, "_user_namespaces_ok", lambda: True)
    monkeypatch.setattr(sandbox, "available", lambda: True)
    return str(bw)


def argv_for(tmp_path, **policy_kw):
    ws = tmp_path / "ws"; ws.mkdir(exist_ok=True)
    pol = AegisPolicy(**policy_kw)
    return sandbox.wrap_for_policy(pol, str(ws), "pytest -q"), str(ws)


def test_fails_closed_when_unavailable(tmp_path, monkeypatch):
    monkeypatch.setattr(sandbox, "bwrap_path", lambda: None)
    with pytest.raises(SandboxUnavailable):
        sandbox.wrap_for_policy(AegisPolicy(), str(tmp_path), "echo hi")
    assert sandbox.available() is False


def test_workspace_is_writable_system_is_readonly(fake_bwrap, tmp_path):
    argv, ws = argv_for(tmp_path)
    s = " ".join(argv)
    assert "--bind " + ws + " " + ws in s             # workspace read-write
    for root in sandbox.SYSTEM_RO:
        if os.path.exists(root):
            assert f"--ro-bind {root} {root}" in s
    assert "--chdir " + ws in s and "--clearenv" in s
    assert argv[-3:] == ["/bin/bash", "-c", "pytest -q"] or argv[-2] == "-c"


def test_network_off_by_default_on_when_asked(fake_bwrap, tmp_path):
    ws = tmp_path / "ws"; ws.mkdir()
    off = sandbox.wrap_for_policy(AegisPolicy(), str(ws), "x")
    assert "--unshare-net" in off
    on = sandbox.wrap_for_policy(AegisPolicy(), str(ws), "x", network=True)
    assert "--unshare-net" not in on


def test_extra_roots_are_bound(fake_bwrap, tmp_path):
    other = tmp_path / "shared"; other.mkdir()
    argv, ws = argv_for(tmp_path, extra_roots=[str(other)])
    s = " ".join(argv)
    assert f"--bind {str(other)} {str(other)}" in s


def test_credential_stores_are_hidden_under_an_allowed_root(fake_bwrap, tmp_path, monkeypatch):
    home = tmp_path / "home"; (home / ".ssh").mkdir(parents=True)
    (home / "project").mkdir()
    (home / ".aegis").mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    pol = AegisPolicy(extra_roots=[str(home)])        # whole home writable ...
    argv = sandbox.wrap_for_policy(pol, str(home / "project"), "x")
    s = " ".join(argv)
    assert f"--tmpfs {os.path.join(str(home), '.ssh')}" in s   # ... but .ssh masked
    assert f"--tmpfs {os.path.join(str(home), '.aegis')}" in s


def test_profile_from_policy():
    p = SandboxProfile.from_policy(AegisPolicy(extra_roots=["/a", "/b"]), "/ws", network=True)
    assert p.workspace == os.path.abspath("/ws")
    assert p.extra_roots == [os.path.abspath("/a"), os.path.abspath("/b")] and p.network is True


def test_probe_reports_unavailable_here():
    info = sandbox.probe()
    assert info["works"] or info["error"]


def test_masks_project_secret_files_and_preserves_backups(fake_bwrap, tmp_path):
    ws = tmp_path / "ws"; ws.mkdir()
    (ws / ".env").write_text("secret")
    (ws / "backups").mkdir()
    argv = sandbox.build_argv(SandboxProfile(str(ws)), ["true"])
    assert ["--ro-bind", "/dev/null", str(ws / ".env")] == argv[argv.index(str(ws / ".env")) - 2:argv.index(str(ws / ".env")) + 1]
    assert f"--ro-bind {ws / 'backups'} {ws / 'backups'}" in " ".join(argv)


def test_custom_state_is_masked_and_tmp_can_be_readonly(fake_bwrap, tmp_path, monkeypatch):
    (tmp_path / "state").mkdir()
    monkeypatch.setenv("AEGIS_HOME", str(tmp_path / "state"))
    argv = sandbox.build_argv(SandboxProfile(str(tmp_path), tmp_writable=False), ["true"])
    assert "--tmpfs " + str(tmp_path / "state") in " ".join(argv)
    assert "--remount-ro /tmp" in " ".join(argv)


def test_root_cannot_be_made_writable(fake_bwrap):
    with pytest.raises(SandboxUnavailable):
        sandbox.build_argv(SandboxProfile(os.path.abspath(os.sep)), ["true"])


def test_unreadable_scan_refuses_execution(fake_bwrap, tmp_path, monkeypatch):
    def unreadable(*args, **kwargs):
        if kwargs.get("onerror"):
            kwargs["onerror"](PermissionError("workspace cannot be inspected"))
        return iter(())
    monkeypatch.setattr(sandbox.os, "walk", unreadable)
    with pytest.raises(SandboxUnavailable, match="inspect"):
        sandbox.build_argv(SandboxProfile(str(tmp_path)), ["true"])


def test_nested_backup_secrets_get_masks(fake_bwrap, tmp_path):
    backup = tmp_path / "backups"; backup.mkdir()
    secret = backup / ".env"; secret.write_text("backup secret")
    argv = sandbox.build_argv(SandboxProfile(str(tmp_path)), ["true"])
    assert f"--ro-bind /dev/null {secret}" in " ".join(argv)
