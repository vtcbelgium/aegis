import subprocess
import pytest
from aegis.dojo import run_dojo


def test_all_six_packs_run_without_executing_attack_strings(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Dojo must not execute attack strings")
    monkeypatch.setattr(subprocess, "run", forbidden)
    report = run_dojo(mission="local regression")
    assert report["passed"], [r for r in report["cases"] if not r["passed"]]
    assert {r["pack"] for r in report["cases"]} == {"01", "02", "03", "04", "05", "06"}
    assert report["cleanup"] == "temporary fixtures removed"


def test_scope_and_mission_are_required():
    with pytest.raises(ValueError):
        run_dojo(mission="")
    with pytest.raises(ValueError):
        run_dojo(mission="test", scope="production")
