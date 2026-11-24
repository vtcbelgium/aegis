"""Tartarus confinement: the bwrap profile built from a policy, and fail-closed behaviour."""

import os

import pytest

from aegis import sandbox
from aegis.policy import AegisPolicy
from aegis.sandbox import SandboxProfile, SandboxUnavailable


@pytest.fixture()
def fake_bwrap(tmp_path, monkeypatch):
    bw = tmp_path / "bwrap"
    bw.write_text("#!/bin/sh\n")
    bw.chmod(0o755)
    monkeypatch.setattr(sandbox, "bwrap_path", lambda: str(bw))
    monkeypatch.setattr(sandbox, "_user_namespaces_ok", lambda: True)
    monkeypatch.setattr(sandbox, "available", lambda: True)
    return str(bw)


def argv_for(tmp_path, **policy_kw):
    ws = tmp_path / "ws"
    ws.mkdir(exist_ok=True)
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
    assert "--bind " + ws + " " + ws in s
    for root in sandbox.SYSTEM_RO:
        if os.path.exists(root):
            assert f"--ro-bind {root} {root}" in s
    assert "--chdir " + ws in s and "--clearenv" in s
    assert argv[-3:] == ["/bin/bash", "-c", "pytest -q"] or argv[-2] == "-c"


def test_empty_and_readonly_workspace_profiles(fake_bwrap, tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / ".git" / "hooks").mkdir(parents=True)
    (ws / ".git" / "config").write_text("[core]\n")
    (ws / ".git" / "hooks" / "pre-commit").write_text("#!/bin/sh\n")

    # empty_workspace skips host workspace binding completely and chdirs to /tmp
    empty_argv = sandbox.wrap_for_policy(AegisPolicy(), str(ws), ["/usr/bin/uname", "-srm"], empty_workspace=True)
    empty_s = " ".join(empty_argv)
    assert "--bind " not in empty_s
    assert str(ws) not in empty_s
    assert "--chdir /tmp" in empty_s
    assert empty_argv[-2:] == ["/usr/bin/uname", "-srm"]

    # readonly_workspace mounts workspace --ro-bind and autoexec .git/config + hooks as --ro-bind (not /dev/null)
    ro_argv = sandbox.wrap_for_policy(AegisPolicy(), str(ws), ["/usr/bin/git", "status"], readonly_workspace=True)
    ro_s = " ".join(ro_argv)
    real_ws = os.path.realpath(str(ws))
    assert f"--ro-bind {real_ws} {real_ws}" in ro_s
    assert f"--ro-bind /dev/null {os.path.join(real_ws, '.git', 'config')}" not in ro_s
    assert f"--ro-bind {os.path.join(real_ws, '.git', 'config')} {os.path.join(real_ws, '.git', 'config')}" in ro_s


def test_network_off_by_default_on_when_asked(fake_bwrap, tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    off = sandbox.wrap_for_policy(AegisPolicy(), str(ws), "x")
    assert "--unshare-net" in off
    on = sandbox.wrap_for_policy(AegisPolicy(), str(ws), "x", network=True)
    assert "--unshare-net" not in on


def test_extra_roots_are_bound(fake_bwrap, tmp_path):
    other = tmp_path / "shared"
    other.mkdir()
    argv, _ = argv_for(tmp_path, extra_roots=[str(other)])
    s = " ".join(argv)
    assert f"--bind {os.path.realpath(str(other))} {os.path.realpath(str(other))}" in s


def test_credential_stores_are_hidden_under_an_allowed_root(fake_bwrap, tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    (home / "project").mkdir()
    (home / ".aegis").mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    pol = AegisPolicy(extra_roots=[str(home)])
    argv = sandbox.wrap_for_policy(pol, str(home / "project"), "x")
    s = " ".join(argv)
    assert f"--tmpfs {os.path.join(os.path.realpath(str(home)), '.ssh')}" in s
    assert f"--tmpfs {os.path.join(os.path.realpath(str(home)), '.aegis')}" in s


def test_profile_from_policy():
    p = SandboxProfile.from_policy(AegisPolicy(extra_roots=["/a", "/b"]), "/ws", network=True, readonly_workspace=True)
    assert p.workspace == os.path.abspath("/ws")
    assert p.extra_roots == [os.path.abspath("/a"), os.path.abspath("/b")]
    assert p.network is True and p.readonly_workspace is True


def test_probe_reports_unavailable_here():
    info = sandbox.probe()
    assert info["works"] or info["error"]


def test_masks_project_secret_files_and_preserves_backups(fake_bwrap, tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / ".env").write_text("secret")
    (ws / "backups").mkdir()
    argv = sandbox.build_argv(SandboxProfile(str(ws)), ["true"])
    real_env = os.path.realpath(str(ws / ".env"))
    real_bak = os.path.realpath(str(ws / "backups"))
    assert ["--ro-bind", "/dev/null", real_env] == argv[argv.index(real_env) - 2 : argv.index(real_env) + 1]
    assert f"--ro-bind {real_bak} {real_bak}" in " ".join(argv)


def test_custom_state_is_masked_and_tmp_can_be_readonly(fake_bwrap, tmp_path, monkeypatch):
    (tmp_path / "state").mkdir()
    monkeypatch.setenv("AEGIS_HOME", str(tmp_path / "state"))
    argv = sandbox.build_argv(SandboxProfile(str(tmp_path), tmp_writable=False), ["true"])
    assert "--tmpfs " + os.path.realpath(str(tmp_path / "state")) in " ".join(argv)
    assert "--remount-ro /tmp" in " ".join(argv)


def test_root_cannot_be_made_writable(fake_bwrap):
    with pytest.raises(SandboxUnavailable):
        sandbox.build_argv(SandboxProfile(os.path.abspath(os.sep)), ["true"])


def test_unreadable_non_lost_and_found_refuses_while_lost_and_found_masks(fake_bwrap, tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "lost+found").mkdir()

    def unreadable_other(*args, **kwargs):
        if kwargs.get("onerror"):
            kwargs["onerror"](PermissionError(13, "denied", str(ws / "secret_dir")))
        return iter(())

    monkeypatch.setattr(sandbox.os, "walk", unreadable_other)
    with pytest.raises(SandboxUnavailable, match="inspect"):
        sandbox.build_argv(SandboxProfile(str(ws)), ["true"])

    def unreadable_lost_found(*args, **kwargs):
        if kwargs.get("onerror"):
            kwargs["onerror"](PermissionError(13, "denied", str(ws / "lost+found")))
        return iter(())

    monkeypatch.setattr(sandbox.os, "walk", unreadable_lost_found)
    argv = sandbox.build_argv(SandboxProfile(str(ws)), ["true"])
    assert f"--tmpfs {os.path.realpath(str(ws / 'lost+found'))}" in " ".join(argv)


def test_walk_skips_heavy_caches_and_git_objects(fake_bwrap, tmp_path):
    ws = tmp_path / "ws"
    (ws / "node_modules" / "pkg").mkdir(parents=True)
    (ws / ".git" / "objects" / "aa").mkdir(parents=True)
    (ws / ".git" / "config").write_text("[core]\n")
    (ws / ".env").write_text("SECRET=1\n")
    argv = sandbox.build_argv(SandboxProfile(str(ws)), ["true"])
    s = " ".join(argv)
    assert f"--ro-bind /dev/null {os.path.realpath(str(ws / '.env'))}" in s
    assert f"--ro-bind {os.path.realpath(str(ws / '.git' / 'config'))}" in s
