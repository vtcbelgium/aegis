"""Native Windows links must not bypass workspace containment."""
import os

import pytest

from aegis import AegisGate, AegisHarness, DecisionLevel


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows path semantics")
def test_windows_directory_link_cannot_escape_workspace(tmp_path):
    workspace = tmp_path / "workspace"; workspace.mkdir()
    outside = tmp_path / "outside"; outside.mkdir()
    (outside / "notes.txt").write_text("owner data")
    try:
        os.symlink(str(outside), str(workspace / "link"), target_is_directory=True)
    except OSError:
        import _winapi
        _winapi.CreateJunction(str(outside), str(workspace / "link"))
    verdict = AegisHarness(AegisGate(base_dir=str(workspace))).evaluate_tool_call(
        "read_file", {"path": str(workspace / "link" / "notes.txt")})
    assert verdict.level >= DecisionLevel.DENY
