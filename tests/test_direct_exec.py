"""Tests for strict No-Shell PASS (`aegis.direct_exec`) and end-to-end invariant checks."""

from __future__ import annotations

import os
import random
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from aegis import AegisGate, AegisHarness, DecisionLevel as L, Tripwires, boundaries
from aegis.canonicalizer import is_inside, resolve_path
from aegis.direct_exec import (
    _is_sensitive_control_component,
    parse_direct_command,
    resolve_trusted_executable,
)
from aegis.policy import AegisPolicy, classify_sensitive
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


def _make_dir_link(target: Path, link: Path) -> None:
    try:
        os.symlink(str(target), str(link), target_is_directory=True)
    except OSError:
        if os.name != "nt":
            raise
        import _winapi
        _winapi.CreateJunction(str(target), str(link))


def _run_git(repo: Path, *args: str, input_bytes: bytes | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args],
        cwd=str(repo),
        input=input_bytes,
        capture_output=True,
        check=True,
    )


def test_real_malicious_git_configs_never_pass_and_clean_repo_runs(tmp_path):
    # 1) Clean repo allows read-only inspection (incl. git blame --no-textconv, HEAD~1, git remote)
    clean = tmp_path / "clean_repo"
    clean.mkdir()
    _run_git(clean, "init")
    _run_git(clean, "config", "user.email", "t@example.com")
    _run_git(clean, "config", "user.name", "Tester")
    _run_git(clean, "remote", "add", "origin", "https://example.com/repo.git")
    (clean / "readme.txt").write_text("line1\n", encoding="utf-8")
    _run_git(clean, "add", "readme.txt")
    _run_git(clean, "commit", "-m", "c1")
    (clean / "readme.txt").write_text("line1\nline2\n", encoding="utf-8")
    _run_git(clean, "add", "readme.txt")
    _run_git(clean, "commit", "-m", "c2")

    for cmd in (
        "git status",
        "git diff",
        "git diff HEAD~1 HEAD",
        "git log -n 1",
        "git log --max-count 1",
        "git show HEAD",
        "git blame readme.txt",
        "git remote",
    ):
        v = analyze_command(cmd, base_dir=str(clean), cwd=str(clean), windows=(os.name == "nt"))
        assert v.level == L.PASS and v.metadata.get("direct_exec") is True, (cmd, v)
        res = subprocess.run(v.metadata["direct_argv"], cwd=str(clean), capture_output=True, text=True)
        assert res.returncode == 0, (cmd, res.stderr)

    blame_v = analyze_command("git blame readme.txt", base_dir=str(clean), cwd=str(clean))
    blame_argv = blame_v.metadata["direct_argv"]
    assert "--no-textconv" in blame_argv
    assert "--no-ext-diff" not in blame_argv

    log_v = analyze_command("git log -n 1", base_dir=str(clean), cwd=str(clean))
    log_argv = log_v.metadata["direct_argv"]
    assert "log.showSignature=false" in log_argv
    assert "gpg.program=false" in log_argv
    assert "core.hooksPath=" in log_argv
    assert "status.submoduleSummary=false" in log_argv

    for ask_git in (
        "git remote -v",
        "git remote --verbose",
        "git diff -n",
        "git log -n",
        "git log --max-count",
        "cat ~/readme.txt",
        "cat PROGRA~1",
    ):
        v = analyze_command(ask_git, base_dir=str(clean), cwd=str(clean), windows=(os.name == "nt"))
        assert v.level >= L.ASK and not v.metadata.get("direct_exec"), (ask_git, v)

    # 2) diff.<driver>.textconv RCE blocked
    repo_tc = tmp_path / "mal_textconv"
    repo_tc.mkdir()
    _run_git(repo_tc, "init")
    _run_git(repo_tc, "config", "user.email", "t@example.com")
    _run_git(repo_tc, "config", "user.name", "Tester")
    marker_tc = tmp_path / "PWN_TC"
    payload_tc = (tmp_path / "tc.py").as_posix()
    Path(payload_tc).write_text(f"open({str(marker_tc)!r}, 'w').write('PWN')\n", encoding="utf-8")
    _run_git(repo_tc, "config", "diff.evil.textconv", f'"{sys.executable.replace(os.sep, "/")}" "{payload_tc}"')
    (repo_tc / ".gitattributes").write_text("*.txt diff=evil\n", encoding="utf-8")
    (repo_tc / "readme.txt").write_text("hello\n", encoding="utf-8")
    _run_git(repo_tc, "add", ".gitattributes", "readme.txt")
    _run_git(repo_tc, "commit", "-m", "init")
    (repo_tc / "readme.txt").write_text("hello2\n", encoding="utf-8")
    _run_git(repo_tc, "add", "readme.txt")
    _run_git(repo_tc, "commit", "-m", "c2")
    marker_tc.unlink(missing_ok=True)
    for cmd in ("git blame readme.txt", "git diff HEAD~1 HEAD", "git log -p", "git show HEAD"):
        v = analyze_command(cmd, base_dir=str(repo_tc), cwd=str(repo_tc))
        assert v.level >= L.ASK and not v.metadata.get("direct_exec"), (cmd, v)
    assert not marker_tc.exists()

    # 3) filter.<driver>.clean RCE blocked
    repo_flt = tmp_path / "mal_filter"
    repo_flt.mkdir()
    _run_git(repo_flt, "init")
    _run_git(repo_flt, "config", "user.email", "t@example.com")
    _run_git(repo_flt, "config", "user.name", "Tester")
    marker_flt = tmp_path / "PWN_FILTER"
    payload_flt = (tmp_path / "flt.py").as_posix()
    Path(payload_flt).write_text(
        f"import sys; open({str(marker_flt)!r}, 'w').write('PWN'); sys.stdout.write(sys.stdin.read())\n",
        encoding="utf-8",
    )
    _run_git(repo_flt, "config", "filter.evil.clean", f'"{sys.executable.replace(os.sep, "/")}" "{payload_flt}"')
    _run_git(repo_flt, "config", "filter.evil.smudge", "cat")
    (repo_flt / ".gitattributes").write_text("*.txt filter=evil\n", encoding="utf-8")
    (repo_flt / "readme.txt").write_text("v1\n", encoding="utf-8")
    _run_git(repo_flt, "add", ".gitattributes", "readme.txt")
    _run_git(repo_flt, "commit", "-m", "init")
    marker_flt.unlink(missing_ok=True)
    (repo_flt / "readme.txt").write_text("v2_dirty\n", encoding="utf-8")
    for cmd in ("git status", "git diff", "git blame readme.txt"):
        v = analyze_command(cmd, base_dir=str(repo_flt), cwd=str(repo_flt))
        assert v.level >= L.ASK and not v.metadata.get("direct_exec"), (cmd, v)
    assert not marker_flt.exists()

    # 4) log.showSignature + gpg.program RCE blocked
    repo_gpg = tmp_path / "mal_gpg"
    repo_gpg.mkdir()
    _run_git(repo_gpg, "init")
    _run_git(repo_gpg, "config", "user.email", "t@example.com")
    _run_git(repo_gpg, "config", "user.name", "Tester")
    (repo_gpg / "a.txt").write_text("hi\n", encoding="utf-8")
    _run_git(repo_gpg, "add", "a.txt")
    tree = _run_git(repo_gpg, "write-tree").stdout.decode().strip()
    commit_body = (
        f"tree {tree}\n"
        "author Tester <t@example.com> 1700000000 +0000\n"
        "committer Tester <t@example.com> 1700000000 +0000\n"
        "gpgsig -----BEGIN PGP SIGNATURE-----\n"
        " fake\n"
        " -----END PGP SIGNATURE-----\n\n"
        "signed\n"
    ).encode("utf-8")
    sha = _run_git(repo_gpg, "hash-object", "-t", "commit", "-w", "--stdin", input_bytes=commit_body).stdout.decode().strip()
    _run_git(repo_gpg, "update-ref", "HEAD", sha)
    _run_git(repo_gpg, "config", "log.showSignature", "true")
    _run_git(repo_gpg, "config", "gpg.program", payload_tc)
    for cmd in ("git log -n 1", "git show HEAD"):
        v = analyze_command(cmd, base_dir=str(repo_gpg), cwd=str(repo_gpg))
        assert v.level >= L.ASK and not v.metadata.get("direct_exec"), (cmd, v)

    # 5) Worktree .git pointer -> commondir/config with [include] blocked
    wt_repo = tmp_path / "wt_repo"
    wt_repo.mkdir()
    common_dir = tmp_path / "common_git"
    common_dir.mkdir()
    (common_dir / "config").write_text("[core]\n\tbare = false\n[include]\n\tpath = evil.cfg\n", encoding="utf-8")
    wt_gitdir = common_dir / "worktrees" / "wt1"
    wt_gitdir.mkdir(parents=True)
    (wt_gitdir / "commondir").write_text("../..\n", encoding="utf-8")
    (wt_repo / ".git").write_text(f"gitdir: {wt_gitdir.as_posix()}\n", encoding="utf-8")
    v_wt = analyze_command("git status", base_dir=str(wt_repo), cwd=str(wt_repo))
    assert v_wt.level >= L.ASK and not v_wt.metadata.get("direct_exec"), v_wt


def test_diff_directories_rg_hidden_and_junction_control_dir_blocked(tmp_path):
    ws = tmp_path / "ws"
    (ws / "a").mkdir(parents=True)
    (ws / "b").mkdir(parents=True)
    (ws / "a" / ".env").write_text("SECRET=1\n", encoding="utf-8")
    (ws / "b" / ".env").write_text("SECRET=2\n", encoding="utf-8")
    (ws / "a.txt").write_text("one\n", encoding="utf-8")
    (ws / "b.txt").write_text("two\n", encoding="utf-8")

    # diff directory / recursive forms must ASK; regular two-file diff still PASSes
    for bad_diff in ("diff -ru a b", "diff -r a b", "diff a b"):
        v = analyze_command(bad_diff, base_dir=str(ws), cwd=str(ws))
        assert v.level >= L.ASK and not v.metadata.get("direct_exec"), (bad_diff, v)
    v_ok_diff = analyze_command("diff -u a.txt b.txt", base_dir=str(ws), cwd=str(ws))
    assert v_ok_diff.level == L.PASS and v_ok_diff.metadata.get("direct_exec") is True

    # rg --hidden / --no-ignore must ASK; safe rg injects fail-closed exclusions
    for bad_rg in (
        "rg --hidden SECRET .",
        "rg --no-ignore SECRET .",
        "rg --files --hidden",
        "rg --files --no-ignore",
    ):
        v = analyze_command(bad_rg, base_dir=str(ws), cwd=str(ws))
        assert v.level >= L.ASK and not v.metadata.get("direct_exec"), (bad_rg, v)

    (ws / ".git").mkdir()
    (ws / ".git" / "config").write_text("TOKEN_SENTINEL\n", encoding="utf-8")
    (ws / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (ws / ".env").write_text("TOKEN_SENTINEL\n", encoding="utf-8")
    (ws / "id_rsa").write_text("TOKEN_SENTINEL\n", encoding="utf-8")
    (ws / "credentials.json").write_text("TOKEN_SENTINEL\n", encoding="utf-8")
    (ws / "app.py").write_text("# TOKEN_SENTINEL TODO\n", encoding="utf-8")

    v_rg = analyze_command("rg TOKEN_SENTINEL .", base_dir=str(ws), cwd=str(ws))
    assert v_rg.level == L.PASS and v_rg.metadata.get("direct_exec") is True
    rg_argv = v_rg.metadata["direct_argv"]
    for expected in (
        "--no-follow",
        "--no-hidden",
        "--iglob=!.git/**",
        "--iglob=!.env",
        "--iglob=!.env.*",
        "--iglob=!id_rsa",
        "--iglob=!credentials.json",
        "--iglob=!*.pem",
        "--iglob=!*.key",
    ):
        assert expected in rg_argv, (expected, rg_argv)

    rg_bin = shutil.which("rg")
    if rg_bin:
        res = subprocess.run([rg_bin, *rg_argv[1:]], cwd=str(ws), capture_output=True, text=True)
        assert res.returncode == 0, res.stderr
        assert "app.py" in res.stdout
        for leak in (".env", "id_rsa", "credentials.json", ".git"):
            assert leak not in res.stdout, res.stdout

    # Junction/symlink to .git, outside folder, and Minotaur tripwire decoy
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("OUTSIDE\n", encoding="utf-8")
    _make_dir_link(ws / ".git", ws / "innocent")
    _make_dir_link(outside, ws / "jlink")

    decoy_dir = ws / "decoy_box"
    decoy_dir.mkdir()
    decoy_file = decoy_dir / "bait.txt"
    decoy_file.write_text("BAIT\n", encoding="utf-8")
    _make_dir_link(decoy_dir, ws / "alias_box")
    pol = AegisPolicy(tripwires=Tripwires(decoy_paths=frozenset({str(decoy_file).replace("\\", "/").lower()})))
    v_rg_decoy = analyze_command("rg BAIT .", base_dir=str(ws), cwd=str(ws), policy=pol)
    assert v_rg_decoy.level == L.PASS
    assert "--iglob=!decoy_box/bait.txt" in v_rg_decoy.metadata["direct_argv"]
    assert "--iglob=!bait.txt" in v_rg_decoy.metadata["direct_argv"]

    for bad_link_cmd in (
        "cat innocent/HEAD",
        "cat innocent/config",
        "cat innocent/missing.txt",
        "ls innocent",
        "cat jlink/secret.txt",
        "cat jlink/missing.txt",
        "cat alias_box/bait.txt",
    ):
        v = analyze_command(bad_link_cmd, base_dir=str(ws), cwd=str(ws), policy=pol, windows=(os.name == "nt"))
        assert v.level >= L.ASK and not v.metadata.get("direct_exec"), (bad_link_cmd, v)


def test_direct_exec_seeded_property_fuzz(tmp_path):
    ws = tmp_path / "fuzz_ws"
    (ws / "sub").mkdir(parents=True)
    (ws / "sub" / "ok.txt").write_text("safe\n", encoding="utf-8")
    (ws / "a.txt").write_text("1\n", encoding="utf-8")
    (ws / "b.txt").write_text("2\n", encoding="utf-8")
    (ws / ".git").mkdir()
    (ws / ".git" / "config").write_text("[core]\n\tbare = false\n", encoding="utf-8")
    (ws / ".env").write_text("SECRET=1\n", encoding="utf-8")
    outside = tmp_path / "outside_fuzz"
    outside.mkdir()
    (outside / "secret.txt").write_text("NO\n", encoding="utf-8")
    _make_dir_link(outside, ws / "jlink")
    _make_dir_link(ws / ".git", ws / "gitlink")

    path_bins = ("cat", "head", "tail", "wc", "stat", "ls", "diff", "sha256sum", "rg")
    tricky_paths = (
        "sub/ok.txt",
        '"sub/ok.txt"',
        "../outside_fuzz/secret.txt",
        "sub/../../outside_fuzz/secret.txt",
        "/etc/passwd",
        r"C:\Windows\win.ini",
        ".env",
        ".env.local",
        ".GIT/config",
        ".git.",
        ".git /HEAD",
        "~/.ssh/id_rsa",
        "readme.txt:stream",
        "::$DATA",
        "jlink/secret.txt",
        "gitlink/HEAD",
        "*.txt",
        "{a.txt,b.txt}",
        "$HOME/x",
        "%USERPROFILE%\\x",
        "a.txt\t;rm",
        "a.txt|cat",
    )
    git_forms = (
        "git status",
        "git diff",
        "git diff HEAD~1 HEAD",
        "git log --oneline -5",
        "git show HEAD",
        "git blame sub/ok.txt",
        "git remote",
        "git remote -v",
        "git -c core.pager=sh status",
        "git -c alias.x=!sh status",
        "git diff --output=out.txt",
        "git diff --ext-diff",
        "git show --textconv HEAD",
        "git blame --textconv sub/ok.txt",
        "git grep SECRET",
        "git cat-file -p HEAD",
        "git config --get user.email",
        "git diff --no-index a.txt b.txt",
        "git log --pretty=format:%x",
        "git status; whoami",
    )
    diag_forms = (
        "hostname",
        "whoami",
        "pwd",
        "uname -srm",
        "python --version",
        "node --version",
        "echo hello world",
        "echo /etc/passwd",
        "echo sk_live_12345678901234567890",
        "rg --hidden SECRET .",
        "rg --no-ignore SECRET .",
        "rg --pre=sh SECRET .",
        "diff -ru a.txt b.txt",
        "cat --version",
    )

    rng = random.Random(20261125)
    pol = AegisPolicy()
    real_ws = os.path.realpath(str(ws))
    samples: list[tuple[str, bool]] = []
    for _ in range(600):
        win = rng.choice((False, True))
        kind = rng.randrange(10)
        if kind < 6:
            b = rng.choice(path_bins)
            p1 = rng.choice(tricky_paths)
            if b == "diff":
                p2 = rng.choice(tricky_paths)
                cmd = f"{b} -u {p1} {p2}"
            elif b == "rg":
                flag = rng.choice(("", "-n ", "--hidden ", "--no-ignore ", "--files "))
                cmd = f"rg {flag}TODO {p1}" if "--files" not in flag else f"rg --files {p1}"
            else:
                cmd = f"{b} {p1}"
        elif kind < 8:
            cmd = rng.choice(git_forms)
        else:
            cmd = rng.choice(diag_forms)
        samples.append((cmd, win))

    pass_count = 0
    for cmd, win in samples:
        v = analyze_command(cmd, base_dir=str(ws), cwd=str(ws), policy=pol, windows=win)
        if v.level != L.PASS:
            assert not v.metadata.get("direct_exec"), (cmd, win, v)
            continue
        pass_count += 1
        assert v.metadata.get("direct_exec") is True, (cmd, win, v)
        argv = v.metadata.get("direct_argv")
        assert isinstance(argv, list) and argv, (cmd, win, v)
        for tok in argv:
            assert not any((ord(ch) < 0x20 and ch != "\t") or ord(ch) == 0x7F for ch in tok), (cmd, tok)
        dc, _ = parse_direct_command(cmd, base_dir=str(ws), cwd=str(ws), policy=pol, windows=win)
        assert dc is not None
        for raw_p in dc.path_args:
            assert not _is_sensitive_control_component(raw_p), (cmd, raw_p)
            abs_p, _, unres = resolve_path(raw_p, base_dir=str(ws), cwd=str(ws))
            assert not unres
            real_p = os.path.realpath(abs_p)
            assert is_inside(real_p, real_ws), (cmd, raw_p, real_p)
            rel_p = os.path.relpath(real_p, real_ws)
            assert rel_p == "." or not _is_sensitive_control_component(rel_p), (cmd, raw_p, rel_p)
            assert classify_sensitive(raw_p, abs_p, real_p, write_mode=False) is None, (cmd, raw_p)
            assert boundaries.check_path(abs_p, "read", pol) is None, (cmd, raw_p)
            assert boundaries.check_path(real_p, "read", pol) is None, (cmd, raw_p)
    assert pass_count > 0
