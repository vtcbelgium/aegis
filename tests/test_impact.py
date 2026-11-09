"""Blast radius of deletes, and git commands that throw work away."""

import pytest

from aegis import DecisionLevel
from aegis.impact import describe, measure, measure_delete
from aegis.policy import AegisPolicy
from aegis.shell import analyze_command

L = DecisionLevel


@pytest.fixture()
def ws(tmp_path):
    big = tmp_path / "big"
    for i in range(130):
        (big / f"d{i % 5}").mkdir(parents=True, exist_ok=True)
        (big / f"d{i % 5}" / f"f{i}.txt").write_text("x" * 10)
    small = tmp_path / "small"
    small.mkdir()
    for i in range(3):
        (small / f"f{i}.log").write_text("y")
    (tmp_path / "logs").mkdir()
    for i in range(150):
        (tmp_path / "logs" / f"{i}.log").write_text("z")
    return tmp_path


def cmd(c, ws, policy=None):
    return analyze_command(c, base_dir=str(ws), policy=policy or AegisPolicy())


def test_measure_stops_early(ws):
    imp = measure(str(ws / "big"), max_entries=100)
    assert imp.exceeded and not imp.complete and imp.entries == 101
    small = measure(str(ws / "small"))
    assert not small.exceeded and small.complete and small.entries == 4
    assert describe(small) == "4 items, 3 B"


def test_large_recursive_delete_asks_with_the_numbers(ws):
    v = cmd("rm -rf big", ws)
    assert v.level == L.ASK and "101+ items" in v.reasons[0]
    assert v.metadata["impact"][0]["exceeded"] is True


def test_small_delete_passes_but_is_measured(ws):
    v = cmd("rm -rf small", ws)
    assert v.level == L.PASS
    assert v.metadata["impact"][0]["entries"] == 4


def test_glob_delete_counts_matches(ws):
    assert cmd("rm logs/*.log", ws).level == L.ASK
    assert cmd("rm small/*.log", ws).level == L.PASS
    assert measure_delete(str(ws / "logs" / "*.log"), False, 100, 10**9).exceeded


def test_limits_come_from_policy(ws):
    pol = AegisPolicy(blast_max_entries=2)
    assert cmd("rm -rf small", ws, pol).level == L.ASK


def test_powershell_and_find_deletes_are_measured(ws):
    v = analyze_command("Remove-Item -Recurse -Force big", base_dir=str(ws), windows=True)
    assert v.level == L.ASK and "items" in v.reasons[0]
    assert cmd("find big -delete", ws).level == L.ASK


@pytest.mark.parametrize("c", [
    "git reset --hard HEAD~3",
    "git clean -fdx",
    "git clean -f",
    "git checkout -- .",
    "git restore .",
    "git stash drop",
    "git stash clear",
    "git branch -D feature",
    "git push --force origin main",
    "git push -f",
    "git push origin --delete old",
    "git push origin :old",
    "git push origin +main",
    "git reflog expire --expire=now --all",
    "git gc --prune=now",
])
def test_git_that_discards_work_asks(c, ws):
    assert cmd(c, ws).level == L.ASK, c


@pytest.mark.parametrize("c", [
    "git status", "git checkout -b feature", "git checkout main", "git restore --staged src/a.py",
    "git restore src/a.py", "git stash", "git stash pop", "git branch -d merged", "git clean -n",
    "git clean -nd", "git push", "git push origin main", "git reset --soft HEAD~1", "git reset src/a.py",
    "git gc", "git commit -m 'x'",
])
def test_everyday_git_still_passes(c, ws):
    assert cmd(c, ws).level == L.PASS, (c, cmd(c, ws))
