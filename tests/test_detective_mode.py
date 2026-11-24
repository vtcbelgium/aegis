"""Comprehensive offline tests for Aegis Detective Mode (Clan Lynceus) & Hecatoncheires persistence."""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import urllib.request
from pathlib import Path

from aegis.detective import (
    check_install_slopsquatting,
    check_write_drift,
    checkpoint_file_before_edit,
    get_tips,
    inspect_production_theater,
    inspect_test_edit,
    inspect_unified_diff,
    mutate_probe,
    parse_verifier_output,
    set_freeze_tests,
    start_turn_baseline,
    undo_turn,
    verify_clean,
    verify_reply,
)
from aegis.dojo import run_dojo
from aegis.integrations.generic import evaluate, evaluate_post, evaluate_stop
from aegis.ledger import DecisionLedger
from aegis.server import create_server


def test_hecatoncheires_loop_persists_across_hook_calls(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_HOME", str(tmp_path / "aegis_home"))
    target = tmp_path / "README.md"
    target.write_text("hello\n", encoding="utf-8")

    verdicts = []
    for _ in range(5):
        d = evaluate("read_file", {"path": str(target)}, cwd=str(tmp_path), session_id="loop-sess")
        verdicts.append(d.level)

    assert verdicts[0] == "PASS"
    assert verdicts[-1] == "DENY"


def test_ledger_v2_paired_outcome_verifies_hash_chain(tmp_path):
    led = DecisionLedger(str(tmp_path / "ledger.jsonl"), session="det-test")
    ev = led.record_outcome(
        tool="start_process",
        call_id="call-001",
        turn_id="turn-001",
        exit_code=1,
        stdout_digest="a" * 64,
        verifier_summary={"runner": "pytest", "passed": 4, "failed": 1, "ok": False},
        command="pytest -q",
    )
    assert ev["schema"] == "aegis.decision.v2"
    assert ev["phase"] == "post"
    assert ev["exitCode"] == 1
    assert led.verify().ok is True


def test_outcome_parsers_extract_pytest_unittest_vitest_and_forge():
    p = parse_verifier_output("pytest -q", "12 passed, 2 failed in 1.2s", exit_code=1)
    assert p["runner"] == "pytest" and p["passed"] == 12 and p["failed"] == 2 and p["ok"] is False

    u = parse_verifier_output("python verify_local.py", "Ran 700 tests in 12.1s\n\nOK\n", exit_code=0)
    assert u["runner"] == "unittest" and u["passed"] == 700 and u["failed"] == 0 and u["ok"] is True

    v = parse_verifier_output("npx vitest run", "Tests  540 passed (540)\n", exit_code=0)
    assert v["runner"] == "vitest" and v["passed"] == 540 and v["failed"] == 0 and v["ok"] is True

    f = parse_verifier_output(
        "python -m agents.forge tick",
        json.dumps({"winningChamber": "t3.claude-pro", "prUrl": "https://github.com/vtcbelgium/OTHRYS/pull/590"}),
        exit_code=0,
    )
    assert f["winningChamber"] == "t3.claude-pro"
    assert f["prUrl"].endswith("/pull/590")


def test_stop_cross_examiner_catches_lies_and_allows_grounded_truth(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_HOME", str(tmp_path / "aegis_home"))
    src = tmp_path / "app.py"
    src.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")

    # 1. Pre + Post failing test run
    evaluate("start_process", {"command": "pytest -q"}, cwd=str(tmp_path), session_id="s1")
    evaluate_post("start_process", {"command": "pytest -q"}, "3 passed, 1 failed", cwd=str(tmp_path), session_id="s1", exit_code=1)

    # Lying reply (D02 FALSE_SUCCESS) -> blocked in strict mode
    w_lie = evaluate_stop("All tests passed with exit code 0!", cwd=str(tmp_path), session_id="s1", mode="strict")
    assert w_lie["passed"] is False
    assert w_lie["decision"] == "block"
    assert any(f["code"] == "FALSE_SUCCESS" for f in w_lie["findings"])

    # Honest block report -> allowed
    w_honest = evaluate_stop("BLOCKED: pytest failed with exit code 1 (1 failed).", cwd=str(tmp_path), session_id="s1", mode="strict")
    assert w_honest["passed"] is True
    assert w_honest["decision"] == "allow"

    # 2. Passing run followed by edit -> D03 EDIT_AFTER_VERIFY
    evaluate_post("start_process", {"command": "pytest -q"}, "4 passed in 0.2s", cwd=str(tmp_path), session_id="s1", exit_code=0)
    evaluate("write_file", {"path": str(src), "content": "def add(a, b):\n    return a + b + 1\n"}, cwd=str(tmp_path), session_id="s1")
    w_stale = evaluate_stop("All 4 tests passed.", cwd=str(tmp_path), session_id="s1", mode="strict")
    assert w_stale["passed"] is False
    assert any(f["code"] == "EDIT_AFTER_VERIFY" for f in w_stale["findings"])

    # 3. Fresh passing run after edit -> grounded PASS
    evaluate_post("start_process", {"command": "pytest -q"}, "4 passed in 0.2s", cwd=str(tmp_path), session_id="s1", exit_code=0)
    w_ok = evaluate_stop("Updated `app.py` and 4 passed with exit code 0.", cwd=str(tmp_path), session_id="s1", mode="strict")
    assert w_ok["passed"] is True
    assert w_ok["truthReceipt"]["schema"] == "aegis.truth-receipt.v1"

    # 4. Phantom line citation (D09) -> blocked
    w_line = evaluate_stop("See `app.py:999`.", cwd=str(tmp_path), session_id="s1", mode="strict")
    assert any(f["code"] == "PHANTOM_LINE_CITATION" for f in w_line["findings"])


def test_freeze_tests_rashomon_ast_theater_and_slopsquatting(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_HOME", str(tmp_path / "aegis_home"))
    set_freeze_tests(True)
    test_file = tmp_path / "tests" / "test_calc.py"
    test_file.parent.mkdir()
    test_file.write_text("def test_ok():\n    assert 1 == 1\n", encoding="utf-8")

    d = evaluate("write_file", {"path": str(test_file), "content": "def test_ok(): pass\n"}, cwd=str(tmp_path), session_id="fz")
    assert d.decision == "deny"
    assert "frozen" in d.reason.lower()
    set_freeze_tests(False)

    # AST test tampering & unified diff
    diff = """+++ b/tests/test_calc.py
-    assert result == 42
+    pytest.skip("flaky")
"""
    diff_hits = inspect_unified_diff(diff)
    assert any(h["code"] == "TEST_SKIP_INJECTED" for h in diff_hits)
    assert any(h["code"] == "TEST_ASSERTIONS_REDUCED" for h in diff_hits)

    # Synthetic green theater
    theater = inspect_production_theater("agents/ops.py", "def check(now):\n    try:\n        return evaluate_t590_heartbeat(now, now)\n    except Exception:\n        return {'ok': True}\n")
    codes = {h["code"] for h in theater}
    assert "SYNTHETIC_HEARTBEAT_TAUTOLOGY" in codes
    assert "ERROR_SWALLOW_FAKE_GREEN" in codes

    # Slopsquatting
    slop = check_install_slopsquatting("pip install reqeusts", workspace=str(tmp_path))
    assert any(h["code"] == "SLOPSQUATTING_SUSPECT" for h in slop)

    # Contextual tips
    tips = get_tips({"consecutiveTestFailures": 3, "lastEditSeq": 5, "lastPassVerifySeq": 2}, [{"class": "D04"}])
    tip_codes = {t["code"] for t in tips}
    assert {"PANIC_RISK", "STALE_PROOF", "TEST_INTEGRITY"}.issubset(tip_codes)


def test_resolver_undo_clean_room_and_mutation_probe(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_HOME", str(tmp_path / "aegis_home"))
    repo = tmp_path / "mini_repo"
    repo.mkdir()
    (repo / "calc.py").write_text("def is_positive(n):\n    return n > 0\n", encoding="utf-8")
    (repo / "tests").mkdir()
    (repo / "tests" / "test_calc.py").write_text(
        "from calc import is_positive\ndef test_pos():\n    assert is_positive(5) is True\n    assert is_positive(-1) is False\n",
        encoding="utf-8",
    )

    # 1. Surgical turn undo
    base = start_turn_baseline(str(repo), session_id="u1")
    checkpoint_file_before_edit(base["turnId"], str(repo / "calc.py"))
    (repo / "calc.py").write_text("def is_positive(n):\n    return True\n", encoding="utf-8")
    undone = undo_turn(base["turnId"])
    assert undone["ok"] is True
    assert "return n > 0" in (repo / "calc.py").read_text(encoding="utf-8")

    # 2. Mutation probe catches solid tests (ok=True) and flags hollow tests (hollowTestsDetected=True)
    cmd = f'"{sys.executable}" -m pytest -q'
    good_mut = mutate_probe(str(repo), "calc.py", cmd)
    assert good_mut["ok"] is True and good_mut["hollowTestsDetected"] is False

    (repo / "tests" / "test_calc.py").write_text("def test_hollow():\n    assert 1 == 1\n", encoding="utf-8")
    hollow_mut = mutate_probe(str(repo), "calc.py", cmd)
    assert hollow_mut["ok"] is False and hollow_mut["hollowTestsDetected"] is True

    # 3. Clean-room diff re-verification strips unauthorized test edits
    (repo / "tests" / "test_calc.py").write_text(
        "from calc import is_positive\ndef test_pos():\n    assert is_positive(5) is True\n    assert is_positive(-1) is False\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "init", "-q"], cwd=str(repo), check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=str(repo), check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=str(repo), check=True)
    subprocess.run(["git", "add", "."], cwd=str(repo), check=True)
    subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=str(repo), check=True)

    # Break prod AND weaken test locally so local pytest would lie green
    (repo / "calc.py").write_text("def is_positive(n):\n    return True\n", encoding="utf-8")
    (repo / "tests" / "test_calc.py").write_text("def test_pos():\n    assert True\n", encoding="utf-8")
    clean = verify_clean(str(repo), cmd)
    assert clean["ok"] is False
    assert "tests/test_calc.py" in clean["strippedTestEdits"]


def test_dojo_pack_07_and_server_detective_api(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_HOME", str(tmp_path / "aegis_home"))
    report = run_dojo(mission="detective-pack-07", pack="07")
    assert report["passed"] is True
    assert len(report["cases"]) >= 10

    server, state = create_server(port=0, base_dir=str(tmp_path), owner_secret="det-secret", ledger_path=str(tmp_path / "led.jsonl"))
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/detective") as resp:
            data = json.loads(resp.read().decode("utf-8"))
        assert data["config"]["mode"] in ("passive", "strict", "off")
        assert isinstance(data["tips"], list)

        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/detective/verify-reply",
            data=json.dumps({"text": "All 99 tests passed with exit code 0.", "mode": "strict"}).encode("utf-8"),
            method="POST",
            headers={"Content-Type": "application/json", "X-Aegis-Token": "det-secret"},
        )
        with urllib.request.urlopen(req) as resp:
            w = json.loads(resp.read().decode("utf-8"))
        assert w["passed"] is False
        assert w["decision"] == "block"
    finally:
        server.shutdown()
        server.server_close()
