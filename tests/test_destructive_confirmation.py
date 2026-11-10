import pytest

from aegis import AegisGate, AegisHarness, DecisionLevel as L
from aegis.approval import confirms
from aegis.shell import analyze_command


@pytest.mark.parametrize("command", ["git reset --hard HEAD~1", "git clean -fd", "git branch -D old", "git push --force origin main"])
def test_destructive_git_requests_an_exact_phrase(tmp_path, command):
    verdict = analyze_command(command, base_dir=str(tmp_path))
    challenge = verdict.metadata["confirmation"]
    assert verdict.level == L.ASK
    assert challenge["phrase"].startswith("APPROVE DESTRUCTIVE: git-")
    assert str(tmp_path).replace("\\", "/").lower() in challenge["phrase"].replace("\\", "/").lower()
    assert confirms(verdict, challenge["phrase"], challenge["digest"])
    assert not confirms(verdict, "continue")
    assert not confirms(verdict, True)
    assert not confirms(verdict, challenge["phrase"] + " ")


def test_bool_approval_cannot_release_a_destructive_call(tmp_path):
    gate = AegisGate(base_dir=str(tmp_path), approval_callback=lambda v: True)
    assert AegisHarness(gate).evaluate_tool_call("start_process", {"command": "git reset --hard"}).level == L.ASK
    gate = AegisGate(base_dir=str(tmp_path), approval_callback=lambda v: v.metadata["confirmation"]["phrase"])
    assert AegisHarness(gate).evaluate_tool_call("start_process", {"command": "git reset --hard"}).passed


def test_changed_arguments_invalidate_confirmation(tmp_path):
    a = AegisHarness(AegisGate(base_dir=str(tmp_path))).evaluate_tool_call("start_process", {"command": "git reset --hard HEAD~1"})
    b = AegisHarness(AegisGate(base_dir=str(tmp_path))).evaluate_tool_call("start_process", {"command": "git reset --hard HEAD~2"})
    assert not confirms(b, a.metadata["confirmation"]["phrase"], a.metadata["confirmation"]["digest"])


def test_changed_delete_impact_invalidates_confirmation(tmp_path):
    folder = tmp_path / "large"; folder.mkdir()
    for i in range(103):
        (folder / str(i)).write_text("fixture")
    a = analyze_command("rm -rf large", base_dir=str(tmp_path))
    (folder / "0").write_text("a different size")
    b = analyze_command("rm -rf large", base_dir=str(tmp_path))
    assert not confirms(b, a.metadata["confirmation"]["phrase"], a.metadata["confirmation"]["digest"])


def test_wildcard_targets_are_never_exact_approvals(tmp_path):
    assert analyze_command("rm -rf *.txt", base_dir=str(tmp_path)).level == L.DENY


def test_changed_git_head_invalidates_the_same_command(tmp_path):
    git = tmp_path / ".git"; git.mkdir()
    (git / "HEAD").write_text("ref: refs/heads/main\n")
    (git / "refs" / "heads").mkdir(parents=True)
    ref = git / "refs" / "heads" / "main"; ref.write_text("a" * 40)
    a = analyze_command("git reset --hard", base_dir=str(tmp_path))
    ref.write_text("b" * 40)
    b = analyze_command("git reset --hard", base_dir=str(tmp_path))
    assert not confirms(b, a.metadata["confirmation"]["phrase"], a.metadata["confirmation"]["digest"])


def test_git_c_resolves_the_reviewed_repository(tmp_path):
    nested = tmp_path / "nested"; nested.mkdir()
    a = analyze_command("git -C nested reset --hard", base_dir=str(tmp_path))
    assert a.metadata["confirmation"]["targets"][0]["target"].replace("\\", "/").endswith("/nested")


def test_git_from_subdirectory_reviews_the_actual_repository(tmp_path):
    git = tmp_path / ".git"; git.mkdir(); (git / "HEAD").write_text("a" * 40)
    sub = tmp_path / "src"; sub.mkdir()
    a = analyze_command("git -C src reset --hard", base_dir=str(tmp_path))
    assert a.metadata["confirmation"]["targets"][0]["target"].replace("\\", "/") == str(tmp_path).replace("\\", "/")
    assert analyze_command("git reset --hard", base_dir=str(sub)).level == L.DENY
