"""Deterministic Remediation Engine: Clean-Room Diff Re-Test, AST Mutation Probe, and Surgical Turn Undo."""

from __future__ import annotations

import ast
import os
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from .baseline import latest_turn_id, load_turn_baseline
from .outcomes import is_test_file, parse_verifier_output


def undo_turn(turn_id: Optional[str] = None, *, dry_run: bool = False) -> Dict[str, Any]:
    """Surgically restore every file backed up during a turn from ~/.aegis/detective/checkpoints/."""
    tid = turn_id or latest_turn_id()
    if not tid:
        return {"ok": False, "error": "No Detective turn checkpoint found."}
    rec = load_turn_baseline(tid)
    if rec is None:
        return {"ok": False, "error": f"Checkpoint '{tid}' not found."}

    backed = rec.get("backedUpFiles") or {}
    restored: List[str] = []
    removed: List[str] = []
    skipped: List[str] = []

    for abs_path, meta in backed.items():
        if not isinstance(meta, dict):
            continue
        if meta.get("skipped"):
            skipped.append(abs_path)
            continue
        if meta.get("existed"):
            blob = meta.get("blob")
            if not blob or not os.path.isfile(blob):
                skipped.append(abs_path)
                continue
            if not dry_run:
                os.makedirs(os.path.dirname(abs_path) or ".", exist_ok=True)
                shutil.copy2(blob, abs_path)
            restored.append(abs_path)
        else:
            if os.path.isfile(abs_path):
                if not dry_run:
                    os.unlink(abs_path)
                removed.append(abs_path)

    return {
        "ok": True,
        "turnId": tid,
        "dryRun": dry_run,
        "restored": restored,
        "removed": removed,
        "skipped": skipped,
    }


def _split_cmd(command: str) -> List[str]:
    tokens = shlex.split(command, posix=(os.name != "nt"))
    cleaned: List[str] = []
    for tok in tokens:
        if len(tok) >= 2 and ((tok[0] == '"' and tok[-1] == '"') or (tok[0] == "'" and tok[-1] == "'")):
            tok = tok[1:-1]
        cleaned.append(tok)
    return cleaned


def _env_for_cwd(work_dir: str) -> Dict[str, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = work_dir + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    return env


def verify_clean(repo_dir: str, test_command: str, *, timeout: int = 120) -> Dict[str, Any]:
    """Replay ONLY non-test production changes onto a clean HEAD checkout with untouched tests."""
    repo = os.path.abspath(repo_dir)
    if not os.path.isdir(repo):
        return {"ok": False, "error": f"Repository path not found: {repo}"}

    # Collect modified tracked files
    diff_names = subprocess.run(
        ["git", "-C", repo, "diff", "--name-only", "HEAD"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if diff_names.returncode != 0:
        return {"ok": False, "error": "Target directory is not a valid git repository with HEAD."}

    changed = [line.strip() for line in diff_names.stdout.splitlines() if line.strip()]
    prod_files = [f for f in changed if not is_test_file(f)]
    stripped_tests = [f for f in changed if is_test_file(f)]

    with tempfile.TemporaryDirectory(prefix="aegis-cleanroom-") as tmpdir:
        clean_dir = os.path.join(tmpdir, "repo")
        clone = subprocess.run(
            ["git", "clone", "--quiet", "--local", repo, clean_dir],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if clone.returncode != 0:
            return {"ok": False, "error": f"Clean-room clone failed: {clone.stderr.strip()[:200]}"}

        # Apply production-only patch if any production files changed
        if prod_files:
            patch = subprocess.run(
                ["git", "-C", repo, "diff", "HEAD", "--"] + prod_files,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            if patch.stdout.strip():
                apply_res = subprocess.run(
                    ["git", "-C", clean_dir, "apply", "--whitespace=nowarn", "-"],
                    input=patch.stdout,
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                )
                if apply_res.returncode != 0:
                    return {
                        "ok": False,
                        "error": f"Failed to apply production diff cleanly: {apply_res.stderr.strip()[:200]}",
                        "strippedTestEdits": stripped_tests,
                    }

        argv = _split_cmd(test_command)
        try:
            proc = subprocess.run(
                argv,
                cwd=clean_dir,
                env=_env_for_cwd(clean_dir),
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"ok": False, "error": f"Clean-room verifier failed to run: {exc}"}

        combined = (proc.stdout or "") + "\n" + (proc.stderr or "")
        summary = parse_verifier_output(test_command, combined, exit_code=proc.returncode)
        return {
            "ok": summary["ok"],
            "exitCode": proc.returncode,
            "productionFilesApplied": prod_files,
            "strippedTestEdits": stripped_tests,
            "verifier": summary,
            "verdict": "PASS" if summary["ok"] else "DENY",
        }


def _mutate_python_source(source: str) -> Optional[tuple[str, str]]:
    """Inject a single deterministic semantic mutation in Python source code."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None

    class _FirstFlip(ast.NodeTransformer):
        def __init__(self) -> None:
            self.mutated: Optional[str] = None

        def visit_Compare(self, node: ast.Compare):
            if self.mutated is None and len(node.ops) == 1:
                op = node.ops[0]
                flips = {
                    ast.Eq: (ast.NotEq(), "== -> !="),
                    ast.NotEq: (ast.Eq(), "!= -> =="),
                    ast.Lt: (ast.GtE(), "< -> >="),
                    ast.Gt: (ast.LtE(), "> -> <="),
                    ast.LtE: (ast.Gt(), "<= -> >"),
                    ast.GtE: (ast.Lt(), ">= -> <"),
                }
                for cls, (new_op, desc) in flips.items():
                    if isinstance(op, cls):
                        node.ops[0] = new_op
                        self.mutated = f"line {getattr(node, 'lineno', '?')}: {desc}"
                        return node
            return self.generic_visit(node)

        def visit_Return(self, node: ast.Return):
            if self.mutated is None and isinstance(node.value, ast.Constant) and isinstance(node.value.value, bool):
                old_v = node.value.value
                node.value = ast.Constant(value=not old_v)
                self.mutated = f"line {getattr(node, 'lineno', '?')}: return {old_v} -> return {not old_v}"
                return node
            return self.generic_visit(node)

    tf = _FirstFlip()
    new_tree = tf.visit(tree)
    if not tf.mutated:
        return None
    ast.fix_missing_locations(new_tree)
    return ast.unparse(new_tree) + "\n", tf.mutated


def mutate_probe(repo_dir: str, target_relpath: str, test_command: str, *, timeout: int = 120) -> Dict[str, Any]:
    """Copy workspace to a temp dir, inject 1 AST fault, and verify tests actually catch it."""
    repo = Path(repo_dir).resolve()
    target = (repo / target_relpath).resolve()
    if not target.is_file():
        return {"ok": False, "error": f"Target file not found: {target_relpath}"}
    source = target.read_text(encoding="utf-8")
    mutated = _mutate_python_source(source)
    if mutated is None:
        return {"ok": False, "error": "No mutable comparison or boolean return found in target file."}
    new_source, mutation_desc = mutated

    with tempfile.TemporaryDirectory(prefix="aegis-mutate-") as tmpdir:
        copy_dir = Path(tmpdir) / "repo"
        shutil.copytree(
            repo,
            copy_dir,
            ignore=shutil.ignore_patterns(".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build"),
        )
        rel = target.relative_to(repo)
        (copy_dir / rel).write_text(new_source, encoding="utf-8")
        argv = _split_cmd(test_command)
        try:
            proc = subprocess.run(
                argv,
                cwd=str(copy_dir),
                env=_env_for_cwd(str(copy_dir)),
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"ok": False, "error": f"Mutation probe failed to run: {exc}"}

        caught = proc.returncode != 0
        return {
            "ok": caught,
            "mutation": mutation_desc,
            "testExitCode": proc.returncode,
            "hollowTestsDetected": not caught,
            "verdict": "PASS" if caught else "DENY",
            "detail": (
                f"Tests caught injected fault ({mutation_desc})."
                if caught
                else f"HOLLOW_TESTS_DETECTED: tests still exited 0 after mutating {target_relpath} ({mutation_desc})!"
            ),
        }
