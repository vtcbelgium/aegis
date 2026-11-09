"""Aegis Harness Middleware: Interceptor for Agent Execution Harnesses.

Supports:
    - Custom Python tool-calling agents
    - LangChain / LlamaIndex Tool Callables
    - AutoGen / CrewAI / SWE-bench agent loops
    - OpenAI / Anthropic tool use interception
    - Tekton / OTHP tool schemas (move_file, edit_block, read_multiple_files)

Usage:
    gate = AegisGate(base_dir="/safe/workspace")
    harness = AegisHarness(gate)

    @harness.protect_tool
    def execute_bash(command: str):
        ...
"""

from __future__ import annotations

import functools
import hashlib
import inspect
import json
from typing import Any, Callable, Dict, List, Optional, Tuple
from .core import AegisGate, DecisionLevel, Verdict
from .clans import LabyrinthClan, TartarusClan, CustodyClan, HecatoncheiresClan


def walk_arguments(obj: Any, key_path: str = "") -> List[Tuple[str, str]]:
    """Recursively extracts all string values along with their dot/bracket key context path."""
    items: List[Tuple[str, str]] = []
    if isinstance(obj, str):
        items.append((key_path, obj))
    elif isinstance(obj, dict):
        for k, v in obj.items():
            sub_path = f"{key_path}.{k}" if key_path else str(k)
            items.extend(walk_arguments(v, sub_path))
    elif isinstance(obj, (list, tuple, set)):
        for idx, elem in enumerate(obj):
            sub_path = f"{key_path}[{idx}]"
            items.extend(walk_arguments(elem, sub_path))
    return items


def make_action_signature(tool_name: str, arguments: Any) -> str:
    """Create a deterministic hash of tool name and argument values to catch runaway loops."""
    try:
        serialized = json.dumps(arguments, sort_keys=True, default=str)
    except Exception:
        serialized = str(arguments)
    arg_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:16]
    return f"{tool_name}:{arg_hash}"


class AegisHarness:
    """Interceptor that gates tool execution in agent harnesses."""

    def __init__(self, gate: Optional[AegisGate] = None, base_dir: Optional[str] = None) -> None:
        self.gate = gate or AegisGate(base_dir=base_dir)
        self.base_dir = self.gate.base_dir
        self.hecatoncheires = HecatoncheiresClan()

    def evaluate_tool_call(self, tool_name: str, arguments: Any) -> Verdict:
        """Evaluate an arbitrary tool call before it executes with full recursive coverage."""
        try:
            # 1. Check if the session is locked
            if self.gate.current_level >= DecisionLevel.LOCK:
                return Verdict(
                    DecisionLevel.LOCK,
                    ["Session is LOCKED due to previous security violations"],
                    "HarnessGuard",
                )

            # Ensure arguments is walkable
            if not isinstance(arguments, dict):
                if isinstance(arguments, (list, tuple)):
                    arguments = {"__items__": list(arguments)}
                elif arguments is None:
                    arguments = {}
                else:
                    arguments = {"__arg__": arguments}

            # 2. Runaway loop detection: hashes argument VALUES rather than keys
            loop_sig = make_action_signature(tool_name, arguments)
            loop_verdict = self.hecatoncheires.inspect_loop(loop_sig)
            if not loop_verdict.passed:
                return self.gate.record(loop_verdict)

            # Recursively walk every argument in the structure
            extracted_items = walk_arguments(arguments)

            # Keys that explicitly carry file content, code, or documentation
            CONTENT_KEYS = (
                "content", "text", "body", "data", "patch", "new_string", "old_string",
                "code", "script_content", "prompt", "message", "diff", "doc", "readme",
                "replacement", "file_content", "description", "target_content"
            )

            for key_path, val in extracted_items:
                clean_key = key_path.lower()
                is_content_key = any(ck in clean_key for ck in CONTENT_KEYS)

                # 3. Path inspection (covers path, file_path, source, destination, paths[0], etc.)
                # Content fields (code, markdown, text) are strictly exempt from path inspection
                # to prevent relative imports ('../lib'), JS rest params ('...args'), and loading dots from false-positive locking.
                is_path_key = (
                    not is_content_key
                    and any(
                        k in clean_key
                        for k in ("path", "file_path", "filename", "filepath", "target", "dir", "source", "dest", "destination", "folder", "paths")
                    )
                )
                looks_like_path = (
                    not is_content_key
                    and "\n" not in val
                    and len(val) < 2048
                    and not any(c in val for c in (";", "{", "}", "(", ")", "="))
                    and (
                        val.startswith(("/", "\\", "~", "..", "."))
                        or (len(val) > 1 and val[1] == ":")
                    )
                )
                if is_path_key or looks_like_path:
                    path_verdict = LabyrinthClan.inspect_path(val, base_dir=self.base_dir)
                    if not path_verdict.passed:
                        return self.gate.record(path_verdict)

                # 4. Command inspection for bash/shell execution tools and interactive processes
                is_interactive_tool = any(
                    it in tool_name.lower()
                    for it in ("interact_with_process", "send_input", "write_process", "terminal", "stdin")
                )
                is_cmd_key = any(
                    k in clean_key
                    for k in ("command", "cmd", "script", "bash", "shell", "exec", "run", "input", "stdin", "interactive_input")
                )
                if is_cmd_key or (is_interactive_tool and not is_content_key):
                    cmd_verdict = TartarusClan.inspect_command(val, base_dir=self.base_dir)
                    if not cmd_verdict.passed:
                        return self.gate.record(cmd_verdict)

                # 5. SQL inspection for database queries
                if any(k in clean_key for k in ("query", "sql")):
                    sql_verdict = TartarusClan.inspect_sql(val)
                    if not sql_verdict.passed:
                        return self.gate.record(sql_verdict)

                # 6. URL inspection for HTTP/browse tools or string URLs
                is_url_key = any(k in clean_key for k in ("url", "uri", "endpoint", "host", "domain"))
                looks_like_url = val.startswith(("http://", "https://", "file://", "gopher://", "dict://"))
                if is_url_key or looks_like_url:
                    url_verdict = CustodyClan.inspect_url(val)
                    if not url_verdict.passed:
                        return self.gate.record(url_verdict)

                # 7. Secrets inspection in any text/content/string arguments
                sec_verdict = CustodyClan.inspect_secrets(val)
                if not sec_verdict.passed:
                    return self.gate.record(sec_verdict)

            # All clans passed -> Zero authority added
            return self.gate.record(Verdict(DecisionLevel.PASS, ["Tool call verified safe"], "AegisHarness"))

        except Exception as exc:
            # Fail closed on any malformed input or unhandled exception
            if self.gate.fail_closed:
                return self.gate.record(
                    Verdict(
                        DecisionLevel.LOCK,
                        [f"Aegis evaluation crashed (fail closed): {exc}"],
                        "FailClosedHandler",
                    )
                )
            raise

    def protect_tool(self, func: Callable[..., Any]) -> Callable[..., Any]:
        """Decorator for Python tool functions to enforce Aegis negative gating with positional binding."""
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            tool_name = func.__name__
            try:
                sig = inspect.signature(func)
                bound = sig.bind(*args, **kwargs)
                bound.apply_defaults()
                call_args = dict(bound.arguments)
            except Exception:
                # If signature binding fails, combine kwargs and args
                call_args = dict(kwargs)
                if args:
                    for i, a in enumerate(args):
                        call_args[f"arg_{i}"] = a

            verdict = self.evaluate_tool_call(tool_name, call_args)
            if not verdict.passed:
                raise PermissionError(
                    f"Aegis Gate {verdict.level.name}: {'; '.join(verdict.reasons)}"
                )
            return func(*args, **kwargs)
        return wrapper
