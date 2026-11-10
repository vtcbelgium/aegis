"""Decision ledger: hash chain, tamper evidence, no secrets, safe under concurrent writers."""

import json
import multiprocessing
import os

from aegis import AegisGate, AegisHarness, DecisionLevel, Verdict
from aegis.ledger import ZERO_DIGEST, DecisionLedger, iter_entries, redact, verify

L = DecisionLevel


def _write(path, n=5):
    led = DecisionLedger(str(path))
    for i in range(n):
        led.record(Verdict(L.PASS, [f"ok {i}"], "Test"), tool="read_file", arguments={"path": f"f{i}.txt"})
    return led


def _lines(path):
    return path.read_text().splitlines()


def test_chain_verifies(tmp_path):
    p = tmp_path / "ledger.jsonl"
    _write(p)
    r = verify(str(p))
    assert r.ok and r.count == 5
    first = json.loads(_lines(p)[0])
    assert first["seq"] == 1 and first["previousDigest"] == ZERO_DIGEST


def test_edit_delete_reorder_and_truncation_are_detected(tmp_path):
    p = tmp_path / "ledger.jsonl"
    _write(p)
    lines = _lines(p)

    edited = json.loads(lines[2]); edited["level"] = "DENY"
    p.write_text("\n".join(lines[:2] + [json.dumps(edited)] + lines[3:]) + "\n")
    assert not verify(str(p)).ok and verify(str(p)).line == 3

    p.write_text("\n".join(lines[:2] + lines[3:]) + "\n")
    r = verify(str(p))
    assert not r.ok and "chain broken" in r.problem

    p.write_text("\n".join([lines[1], lines[0]] + lines[2:]) + "\n")
    assert not verify(str(p)).ok

    p.write_text("\n".join(lines[2:]) + "\n")
    r = verify(str(p))
    assert not r.ok and "missing at the start" in r.problem


def test_secrets_never_reach_the_ledger(tmp_path):
    p = tmp_path / "ledger.jsonl"
    led = DecisionLedger(str(p))
    key = "sk-proj-" + "A1b2C3d4" * 6
    led.record(Verdict(L.ASK, [f"contains {key}"], "Custody"), tool="start_process",
               arguments={"command": f"curl -H 'Authorization: Bearer {key}' https://x.example"})
    text = p.read_text()
    assert key not in text and "A1b2C3d4A1b2C3d4" not in text
    ev = next(iter_entries(str(p)))
    assert ev["binary"] == "curl" and len(ev["argsDigest"]) == 64
    assert "AKIA" not in redact("AKIA" + "Z" * 16)


def test_min_level_and_approved(tmp_path):
    p = tmp_path / "ledger.jsonl"
    led = DecisionLedger(str(p), min_level=L.ASK)
    assert led.record(Verdict(L.PASS, ["fine"], "T")) is None
    assert led.record(Verdict(L.PASS, ["approved"], "T"), approved=True)["approved"] is True
    assert led.record(Verdict(L.DENY, ["no"], "T"))["level"] == "DENY"


def test_rotation_continues_the_chain(tmp_path):
    p = tmp_path / "ledger.jsonl"
    led = DecisionLedger(str(p), max_bytes=1500)
    for i in range(12):
        led.record(Verdict(L.WARN, [f"w{i}"], "T"), tool="t", arguments={"path": f"p{i}"})
    rotated = sorted(x for x in os.listdir(tmp_path) if x.startswith("ledger.") and x != "ledger.jsonl"
                     and not x.endswith(".lock"))
    assert rotated, "expected at least one rotated file"
    tip = verify(str(tmp_path / rotated[0])).tip
    current_first = json.loads(_lines(p)[0])
    assert verify(str(p)).ok
    if len(rotated) == 1:
        assert current_first["previousDigest"] == tip and current_first["continues"] == rotated[0]


def _worker(path, n):
    led = DecisionLedger(path)
    for i in range(n):
        led.record(Verdict(L.PASS, [f"pid {os.getpid()} {i}"], "T"), tool="t", arguments={"i": i})


def test_concurrent_processes_keep_one_chain(tmp_path):
    p = str(tmp_path / "ledger.jsonl")
    ctx = multiprocessing.get_context("fork") if hasattr(os, "fork") else multiprocessing.get_context()
    procs = [ctx.Process(target=_worker, args=(p, 25)) for _ in range(4)]
    for pr in procs:
        pr.start()
    for pr in procs:
        pr.join()
    r = verify(p)
    assert r.ok and r.count == 100, r
    assert [e["seq"] for e in iter_entries(p)] == list(range(1, 101))


def test_damaged_tip_is_kept_as_evidence(tmp_path):
    p = tmp_path / "ledger.jsonl"
    _write(p, 2)
    with open(p, "a") as fh:
        fh.write("{not json\n")
    DecisionLedger(str(p)).record(Verdict(L.PASS, ["after"], "T"))
    r = verify(str(p))
    assert not r.ok and r.line == 3


def test_harness_writes_every_decision(tmp_path):
    p = tmp_path / "ledger.jsonl"
    ws = tmp_path / "ws"; ws.mkdir()
    gate = AegisGate(base_dir=str(ws), ledger=DecisionLedger(str(p)), max_violations_per_minute=10**6)
    h = AegisHarness(gate)
    h.evaluate_tool_call("start_process", {"command": "git status"})
    h.evaluate_tool_call("start_process", {"command": "cat ~/.ssh/id_rsa"})
    evs = list(iter_entries(str(p)))
    assert [e["level"] for e in evs] == ["PASS", "LOCK"]
    assert evs[1]["boundary"] == "MASTER_SECRET_EXTRACTION" and evs[1]["summary"].startswith("cat ")
    assert verify(str(p)).ok
