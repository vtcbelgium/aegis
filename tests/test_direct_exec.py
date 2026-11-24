"""Tests for strict No-Shell PASS (`aegis.direct_exec`) and end-to-end invariant checks."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from aegis import AegisGate, AegisHarness, DecisionLevel as L
from aegis.direct_exec import parse_direct_command, resolve_trusted_executable
from aegis.policy import AegisPolicy
from aegis.shell import analyze_command


def test_direct_exec_allows_strict_readonly_diagnostics_and_workspace_reads(tmp_path):
    ws = tmp_path / "ws"
    (ws / "src").mkdir(parents=True)
    (ws / "src" / "app.py").write_text("print('hi')\n", encoding="utf-8")
    (ws / "a.txt").write_text("1\n", encoding="utf-8")
    (ws / "b.txt").write_text("2\n", encoding="utf-8")

    # Zero-path system diagnostics -> needs_workspace=False
    for cmd in (
        "hostname",
        "whoami",
        "pwd",
        "systeminfo",
        "uname -srm",
        "lscpu",
        "lspci",
        "ipconfig /all",
        "ipconfig /displaydns",
        "tasklist /nh",
        "tasklist /fo csv",
        "netstat -an",
        "nvidia-smi -L",
        "python --version",
        "git --version",
        "node --version",
        "ollama list",
        "ollama ps",
        "echo hello world",
    ):
        dc, err = parse_direct_command(cmd, base_dir=str(ws), cwd=str(ws))
        assert dc is not None, (cmd, err)
        assert dc.needs_workspace is False
        v = analyze_command(cmd, base_dir=str(ws), cwd=str(ws))
        assert v.level == L.PASS and v.metadata.get("direct_exec") is True, (cmd, v)
        assert v.metadata["direct_argv"] == list(dc.argv)

    # Workspace read-only inspection -> needs_workspace=True
    for cmd in (
        "ls -la",
        "cat src/app.py",
        "head -n 10 src/app.py",
        "tail -n 5 src/app.py",
        "wc -l src/app.py",
        "stat src/app.py",
        "diff -u a.txt b.txt",
        "rg '^print' src/app.py",
        "git status --short",
        "git log --oneline -5",
        "git branch --show-current",
        "git rev-parse --short HEAD",
    ):
        dc, err = parse_direct_command(cmd, base_dir=str(ws), cwd=str(ws))
        assert dc is not None, (cmd, err)
        assert dc.needs_workspace is True
        v = analyze_command(cmd, base_dir=str(ws), cwd=str(ws))
        assert v.level == L.PASS and v.metadata.get("direct_exec") is True, (cmd, v)


def test_git_hardened_flags_injected_and_dangerous_git_rejected(tmp_path):
    ws = tmp_path / "ws"
    (ws / "src").mkdir(parents=True)
    dc, err = parse_direct_command("git diff main -- src/", base_dir=str(ws), cwd=str(ws))
    assert dc is not None, err
    argv = list(dc.argv)
    assert "-c" in argv
    assert "core.pager=cat" in argv
    assert "core.fsmonitor=false" in argv
    assert "core.sshCommand=false" in argv
    assert "diff.external=" in argv
    assert "credential.helper=" in argv
    assert "--no-pager" in argv
    assert "--no-ext-diff" in argv
    assert "--no-textconv" in argv

    for bad_git in (
        "git -c core.fsmonitor=evil status",
        "git -C .git status",
        "git show HEAD:.env",
        "git branch -D old",
        "git tag v1.0.0",
        "git commit -m 'msg'",
        "git checkout -b feat",
        "git push origin main",
        "git remote add origin https://example.com/r.git",
        "git diff --output=out.txt",
        "git log --ext-diff",
    ):
        v = analyze_command(bad_git, base_dir=str(ws), cwd=str(ws))
        assert v.level >= L.ASK and not v.metadata.get("direct_exec"), (bad_git, v)


def test_shell_syntax_escapes_globs_braces_and_control_chars_never_pass(tmp_path):
    ws = tmp_path / "ws"
    (ws / ".git").mkdir(parents=True)
    (ws / ".git" / "config").write_text("[core]\n", encoding="utf-8")
    (ws / ".env").write_text("SECRET=1\n", encoding="utf-8")
    (ws / "notes.txt").write_text("ok\n", encoding="utf-8")

    # No shell syntax / bypass vector may ever return PASS
    vectors = (
        "",
        "   ",
        "echo a | cat",
        "echo a > notes.txt",
        "echo a; ls",
        "cd src && ls",
        "cat .gi?/config",
        "cat *.txt",
        "ls {a,b}",
        "sort -S 1K --compress-progra{m=./z.sh,m=./z.sh} notes.txt",
        "echo $(hostname)",
        "echo `hostname`",
        "echo $HOME",
        "echo %USERPROFILE%",
        "ls\npwd",
        "cat '.git/config'",
        "cat .env",
        "cat ../outside.txt",
        "./git status",
        "git.exe.bat status" if sys.platform == "win32" else "./notes.txt",
        "cmd.exe /c dir",
        "powershell -Command ls",
        "Get-ChildItem",
        "New-Item -ItemType File -Path x.txt",
        "sed -n 1,5p notes.txt",
        "awk '{print $1}' notes.txt",
        "tar -cf out.tar notes.txt",
        "python -c 'print(1)'",
        "python -m pytest",
        "rm notes.txt",
        "mv notes.txt x.txt",
        "rg --pre=evil foo notes.txt",
        "rg foo notes.txt extra'mixed'quote",
        "echo -n hello",
        "cat \"notes.txt\\x\"",
    )
    for cmd in vectors:
        v = analyze_command(cmd, base_dir=str(ws), cwd=str(ws), windows=(os.name == "nt"))
        assert v.level >= L.ASK, f"Expected non-PASS for {cmd!r}, got {v}"
        assert not v.metadata.get("direct_exec"), cmd


def test_harness_preserves_direct_exec_metadata_only_for_safe_commands(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    h = AegisHarness(AegisGate(base_dir=str(ws)), base_dir=str(ws))
    v_ok = h.evaluate_tool_call("start_process", {"command": "hostname"})
    assert v_ok.passed and v_ok.metadata.get("direct_exec") is True
    assert v_ok.metadata["direct_argv"] == ["hostname"]
    assert v_ok.metadata["needs_workspace"] is False

    v_ask = h.evaluate_tool_call("start_process", {"command": "echo hi | cat"})
    assert v_ask.level == L.ASK and not v_ask.metadata.get("direct_exec")


def test_resolve_trusted_executable_blocks_workspace_and_temp_shadowing(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    ws.mkdir()
    fake_ext = ".exe" if sys.platform == "win32" else ""
    fake_git = ws / f"git{fake_ext}"
    fake_git.write_text("evil", encoding="utf-8")
    if sys.platform != "win32":
        fake_git.chmod(0o755)
    # Put workspace FIRST on PATH + add a .bat shim
    if sys.platform == "win32":
        (ws / "git.bat").write_text("@echo off\r\necho pwned\r\n", encoding="utf-8")
    monkeypatch.setenv("PATH", str(ws) + os.pathsep + os.environ.get("PATH", ""))

    # Direct paths, scripts, and relative binaries are always refused
    assert resolve_trusted_executable("./git", workspace_roots=[str(ws)], cwd=str(ws)) is None
    assert resolve_trusted_executable("git.bat", workspace_roots=[str(ws)], cwd=str(ws)) is None
    assert resolve_trusted_executable("git.cmd", workspace_roots=[str(ws)], cwd=str(ws)) is None

    # Legitimate git resolves from system PATH, NEVER from workspace or temp dir
    resolved = resolve_trusted_executable("git", workspace_roots=[str(ws)], cwd=str(ws))
    if resolved is not None:
        assert Path(resolved).resolve() != fake_git.resolve()
        assert not str(Path(resolved).resolve()).lower().startswith(str(ws.resolve()).lower())
