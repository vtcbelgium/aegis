"""Regressions for cross-process hooks and durable security state."""
import json
import multiprocessing
import os
import time

import pytest

from aegis import DecisionLevel as L, Verdict
from aegis import session
from aegis.clans.minotaur import Tripwires, plant
from aegis.integrations import generic
from aegis.integrations.claude_code import run_posttooluse
from aegis.ledger import DecisionLedger, _FileLock, iter_entries, verify


@pytest.fixture
def state(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_HOME", str(tmp_path / "state"))
    return tmp_path


def test_plant_never_overwrites_existing_files(state):
    target = state / "passwords.txt"
    target.write_text("owner's real data")
    summary = plant(str(state), str(state), specs=[("{home}/passwords.txt", "generic")])
    assert target.read_text() == "owner's real data"
    assert summary["count"] == 0


def test_plant_keeps_other_workspace_tripwires(state):
    for name in ("one", "two"):
        plant(str(state / name), str(state), specs=[("{workspace}/decoy", "generic")])
    assert len(Tripwires.load().canaries) == 2


def test_expired_lock_does_not_reset(state):
    session.save("s", L.LOCK, {})
    path = session._path("s")
    data = json.loads(open(path).read()); data["at"] = time.time() - 10**6
    with open(path, "w") as fh:
        json.dump(data, fh)
    assert generic.evaluate("Bash", {"command": "git status"}, cwd=str(state), session_id="s").level == "LOCK"


def test_distinct_session_ids_never_alias(state):
    assert session._path("a/b") != session._path("a_b")
    assert session._path("x" * 121) != session._path("x" * 120)


def test_legacy_session_lock_survives_upgrade(state):
    directory = state / "state" / "sessions"; directory.mkdir(parents=True)
    (directory / "legacy.json").write_text(json.dumps({"at": 0, "level": int(L.LOCK), "minotaur": {}}))
    assert generic.evaluate("Bash", {"command": "git status"}, cwd=str(state), session_id="legacy").level == "LOCK"


@pytest.mark.parametrize("data", ["{broken", "[]", '{"level":999}', '{"level":0,"minotaur":[]}'])
def test_corrupt_session_is_not_treated_as_new(state, data):
    session.save("s", L.LOCK, {})
    with open(session._path("s"), "w") as fh:
        fh.write(data)
    with pytest.raises((ValueError, TypeError)):
        generic.evaluate("Bash", {"command": "git status"}, cwd=str(state), session_id="s")


def test_post_canary_persists_lock_and_ledger(state, capsys):
    plant(str(state), str(state), specs=[("{workspace}/decoy", "generic")])
    run_posttooluse({"session_id": "s", "tool_response": Tripwires.load().canaries[0]})
    assert json.loads(capsys.readouterr().out)["decision"] == "block"
    assert generic.evaluate("Read", {"file_path": str(state / "ok")}, cwd=str(state), session_id="s").level == "LOCK"


def test_websearch_cannot_bypass_locked_session(state):
    session.save("s", L.LOCK, {})
    assert generic.evaluate("WebSearch", {"query": "hello"}, cwd=str(state), session_id="s").level == "LOCK"


def test_log_failure_is_reported(state, monkeypatch):
    led = DecisionLedger(str(state / "ledger"))
    def broken(*args):
        raise OSError("disk full")
    monkeypatch.setattr(led, "append", broken)
    with pytest.raises(OSError):
        led.record(Verdict(L.PASS, ["safe"], "test"))


def test_file_lock_failure_never_runs_unlocked(state, monkeypatch):
    def refused(*args):
        raise OSError("lock unavailable")
    if os.name == "nt":
        import msvcrt
        monkeypatch.setattr(msvcrt, "locking", refused)
    else:
        import fcntl
        monkeypatch.setattr(fcntl, "flock", refused)
    with pytest.raises(OSError):
        with _FileLock(str(state / "lock")):
            pytest.fail("entered without a lock")


def test_secret_paths_and_scoped_keys_are_redacted(state):
    from aegis.clans.custody import CustodyClan
    key = "sk-proj-" + "abcd1234" * 6
    assert CustodyClan.inspect_secrets(key).level == L.LOCK
    path = state / "ledger.jsonl"
    DecisionLedger(str(path)).record(Verdict(L.ASK, ["review"], "test",
        {"impact": [{"target": "/workspace/" + key, "bytes": 1}]}))
    assert key not in path.read_text()


def test_rotation_never_loses_events(state):
    path = state / "ledger.jsonl"
    led = DecisionLedger(str(path), max_bytes=1)
    for i in range(12):
        led.record(Verdict(L.PASS, [str(i)], "test"))
    paths = list(state.glob("ledger.*.jsonl")) + [path]
    assert len(paths) == 12
    events = sorted((ev for p in paths for ev in iter_entries(str(p))), key=lambda ev: ev["seq"])
    assert [e["seq"] for e in events] == list(range(1, 13))
    assert all(events[i]["previousDigest"] == events[i-1]["eventDigest"] for i in range(1, 12))


def test_trusted_tip_detects_tail_truncation(state):
    path = state / "ledger.jsonl"
    led = DecisionLedger(str(path))
    for _ in range(3):
        led.record(Verdict(L.PASS, ["ok"], "test"))
    checkpoint = led.verify().tip
    path.write_text("\n".join(path.read_text().splitlines()[:-1]) + "\n")
    assert not led.verify(expected_tip=checkpoint).ok


def test_mcp_pinning_withholds_drift_and_blocks_subsequent_calls(state):
    from aegis import AegisMcpProxy
    from aegis.pinning import ToolPins
    pins = ToolPins(str(state / "pins.json"))
    tools = [{"name": "read_file", "description": "Read a file"}]
    pins.pin("files", tools)
    proxy = AegisMcpProxy(base_dir=str(state), tool_pins=pins, server_id="files")
    request = {"id": 1, "method": "tools/call", "params": {"name": "read_file", "arguments": {"path": "ok"}}}
    assert not proxy.filter_request(request)[0]
    assert proxy.filter_response({"id": 2, "result": {"tools": tools}})[0]
    assert proxy.filter_request(request)[0]
    changed = [{"name": "read_file", "description": "Different behaviour"}]
    assert not proxy.filter_response({"id": 3, "result": {"tools": changed}})[0]
    assert not proxy.filter_request(request)[0]


def test_corrupt_pins_and_tripwires_fail_closed(state):
    from aegis import AegisGate
    from aegis.pinning import ToolPins
    path = state / "pins.json"; path.write_text("{broken")
    with pytest.raises(ValueError):
        ToolPins(str(path))
    registry = state / "state" / "minotaur.json"
    registry.parent.mkdir(exist_ok=True); registry.write_text("{broken")
    with pytest.raises(ValueError):
        AegisGate()


@pytest.mark.parametrize("raw", ["", "null", "[]", "{broken", "{}"])
def test_malformed_hook_input_denies(state, monkeypatch, capsys, raw):
    import io, sys
    from aegis.cli import run_hook
    monkeypatch.setattr(sys, "stdin", io.StringIO(raw))
    assert run_hook(fmt="exit") == 2
    assert "could not evaluate" in capsys.readouterr().err


def _hook_worker(workspace, i):
    # Each process reloads the latest state while holding the transaction lock.
    from aegis import AegisGate
    with session.transaction("parallel"):
        gate = AegisGate()
        session.apply_to_gate(gate, "parallel")
        gate.escalate(L.LOCK if i == 0 else L.PASS)
        time.sleep(0.02)
        session.persist_from_gate(gate, "parallel")


def test_concurrent_session_updates_cannot_erase_lock(state):
    ctx = multiprocessing.get_context("spawn")
    procs = [ctx.Process(target=_hook_worker, args=(str(state), i)) for i in range(6)]
    for proc in procs:
        proc.start()
    for proc in procs:
        proc.join(20)
        assert proc.exitcode == 0
    assert session.load("parallel")["level"] == int(L.LOCK)
