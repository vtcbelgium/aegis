"""Aegis Harness Middleware: Interceptor for Agent Execution Harnesses.

Supports:
    - Custom Python tool-calling agents
    - LangChain / LlamaIndex Tool Callables
    - AutoGen / CrewAI / SWE-bench agent loops
    - OpenAI / Anthropic tool use interception
    - Tekton / Desktop Commander tools via exact per-tool schemas

Argument classification:
    1. Known tools use an exact schema: each argument is declared as a path, command,
       URL, content, or plain value. Nothing is guessed.
    2. Other tools: the key is split into whole words (data_dir -> data, dir). Path, URL and
       command words win over content words, so "data_dir" is a path, never content.
       Substring matching is never used.
    3. Any string that *looks like* a path or URL is checked even under an unknown key;
       only declared/recognized content fields (file bodies, code, prose) are exempt from
       path checks. Every string is scanned for live credentials.

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
import os
import re
from typing import Any, Callable, Dict, List, Optional, Tuple

from .core import AegisGate, DecisionLevel, Verdict
from .canonicalizer import looks_windows_path
from .clans import CustodyClan, HecatoncheiresClan, LabyrinthClan, TartarusClan

# Argument roles
PATH_READ, PATH_WRITE, COMMAND, URL, CONTENT, VALUE, SQL, CONFIG = (
    "path_read", "path_write", "command", "url", "content", "value", "sql", "config")

# Exact schemas for Tekton / Desktop Commander style tools. Keys not listed fall back
# to word-based classification below.
TOOL_SCHEMAS: Dict[str, Dict[str, str]] = {
    "read_file": {"path": PATH_READ, "offset": VALUE, "length": VALUE, "isUrl": VALUE},
    "read_multiple_files": {"paths": PATH_READ},
    "write_file": {"path": PATH_WRITE, "content": CONTENT, "mode": VALUE},
    "write_pdf": {"path": PATH_WRITE, "content": CONTENT, "outputPath": PATH_WRITE, "options": VALUE},
    "edit_block": {"file_path": PATH_WRITE, "old_string": CONTENT, "new_string": CONTENT,
                   "expected_replacements": VALUE},
    "create_directory": {"path": PATH_WRITE},
    "list_directory": {"path": PATH_READ, "depth": VALUE},
    "move_file": {"source": PATH_WRITE, "destination": PATH_WRITE},
    "get_file_info": {"path": PATH_READ},
    "start_search": {"path": PATH_READ, "pattern": CONTENT, "searchType": VALUE, "filePattern": VALUE,
                     "ignoreCase": VALUE, "maxResults": VALUE, "includeHidden": VALUE,
                     "contextLines": VALUE, "timeout_ms": VALUE, "earlyTermination": VALUE,
                     "literalSearch": VALUE},
    "search": {"path": PATH_READ, "pattern": CONTENT, "query": CONTENT},
    "start_process": {"command": COMMAND, "timeout_ms": VALUE, "shell": VALUE, "verbose_timing": VALUE},
    "interact_with_process": {"pid": VALUE, "input": COMMAND, "timeout_ms": VALUE, "wait_for_prompt": VALUE,
                              "verbose_timing": VALUE},
    "read_process_output": {"pid": VALUE, "timeout_ms": VALUE, "offset": VALUE, "length": VALUE},
    "force_terminate": {"pid": VALUE},
    "list_processes": {}, "list_sessions": {}, "list_searches": {}, "get_config": {},
    "get_more_search_results": {"sessionId": VALUE, "offset": VALUE, "length": VALUE},
    "stop_search": {"sessionId": VALUE},
    "set_config_value": {"key": CONFIG, "value": CONFIG},
    # Tekton device management
    "tekton_list_devices": {}, "tekton_ping": {}, "tekton_profile": {}, "tekton_pair_status": {},
    "tekton_check_call": {},
    "tekton_pair_begin": {"access": CONFIG}, "tekton_unpair_device": {"device": CONFIG},
}
# Arguments every Tekton tool may carry
COMMON_KEYS = {"device": VALUE, "approval_id": VALUE}

PATH_WORDS = {"path", "paths", "file", "files", "filename", "filenames", "filepath", "dir", "dirs",
              "directory", "directories", "folder", "folders", "root", "cwd", "workdir", "src",
              "source", "sources", "dest", "dst", "destination", "target", "output", "outfile",
              "infile", "location", "basedir", "workspace", "home"}
URL_WORDS = {"url", "urls", "uri", "uris", "endpoint", "href", "link", "links", "host", "hostname",
             "domain", "webhook", "callback", "server", "origin", "address"}
COMMAND_WORDS = {"command", "commands", "cmd", "cmdline", "shellcommand", "bashcommand"}
SQL_WORDS = {"sql"}
CONTENT_WORDS = {"content", "contents", "text", "body", "data", "patch", "diff", "code", "message",
                 "prompt", "description", "readme", "doc", "docs", "string", "strings",
                 "replacement", "html", "markdown", "md", "json", "note", "notes", "comment",
                 "title", "summary", "pattern", "query", "old", "new", "snippet", "template"}
INTERACTIVE_TOOL_RE = re.compile(r"interact|send_input|write_process|terminal|stdin|send_keys", re.I)
SQL_TOOL_RE = re.compile(r"sql|database|\bdb\b|postgres|mysql|sqlite|supabase|query", re.I)


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


def key_words(key_path: str) -> List[str]:
    """'options.dataDir[0]' -> ['data', 'dir'] (last key segment, split on _ - . and camelCase)."""
    last = re.sub(r"\[\d+\]", "", key_path).split(".")[-1]
    last = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", last)
    return [w for w in re.split(r"[_\-\s]+", last.lower()) if w]


def classify_key(key_path: str) -> str:
    words = key_words(key_path)
    joined = "".join(words)
    if any(w in PATH_WORDS for w in words):
        return PATH_WRITE if any(w in {"dest", "dst", "destination", "output", "outfile", "target"} for w in words) else PATH_READ
    if any(w in URL_WORDS for w in words):
        return URL
    if any(w in COMMAND_WORDS for w in words) or joined in COMMAND_WORDS:
        return COMMAND
    if any(w in SQL_WORDS for w in words):
        return SQL
    if words and all(w in CONTENT_WORDS for w in words):
        return CONTENT
    return VALUE


def looks_like_path(val: str) -> bool:
    if not val or "\n" in val or len(val) > 4096:
        return False
    v = val.strip()
    return (
        v.startswith(("/", "\\", "~", "./", "../", ".\\", "..\\", "$HOME", "${HOME}", "%USERPROFILE%", "$env:"))
        or v in (".", "..")
        or looks_windows_path(v)
    )


def looks_like_url(val: str) -> bool:
    return bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://\S+$", val.strip()))


class AegisHarness:
    """Interceptor that gates tool execution in agent harnesses."""

    def __init__(self, gate: Optional[AegisGate] = None, base_dir: Optional[str] = None) -> None:
        self.gate = gate or AegisGate(base_dir=base_dir)
        self.base_dir = self.gate.base_dir
        self.hecatoncheires = HecatoncheiresClan()

    @property
    def policy(self) -> Any:
        return self.gate.policy

    def _role(self, tool_name: str, key_path: str) -> str:
        schema = TOOL_SCHEMAS.get(tool_name)
        top_key = re.sub(r"\[\d+\]", "", key_path).split(".")[0]
        if schema is not None:
            if top_key in schema:
                return schema[top_key]
            if top_key in COMMON_KEYS:
                return COMMON_KEYS[top_key]
        role = classify_key(key_path)
        if role in (VALUE, CONTENT) and INTERACTIVE_TOOL_RE.search(tool_name) and \
                any(w in {"input", "stdin", "keys", "data", "text"} for w in key_words(key_path)):
            return COMMAND
        if role == CONTENT and "query" in key_words(key_path) and SQL_TOOL_RE.search(tool_name):
            return SQL
        return role

    def _check(self, tool_name: str, key_path: str, val: str, role: str, windows: bool = False) -> Optional[Verdict]:
        """Return a non-PASS verdict for one string argument, or None if it is fine."""
        found: Optional[Verdict] = None

        def worse(v: Verdict) -> None:
            nonlocal found
            if v.level > DecisionLevel.PASS and (found is None or v.level > found.level):
                found = v

        if role == CONFIG:
            worse(Verdict(DecisionLevel.ASK, [f"{tool_name} changes connector/device configuration ({key_path})"], "AegisHarness"))
        elif role == COMMAND:
            worse(TartarusClan.inspect_command(val, base_dir=self.base_dir, policy=self.policy, windows=windows))
        elif role == SQL:
            worse(TartarusClan.inspect_sql(val))
        elif role == URL or (role not in (CONTENT, CONFIG) and looks_like_url(val)):
            if looks_like_url(val) or role == URL:
                url = val if "://" in val else ("http://" + val if role == URL and "." in val and " " not in val else "")
                if url:
                    worse(CustodyClan.inspect_url(url))
        if role in (PATH_READ, PATH_WRITE):
            if tool_name == "read_file" and looks_like_url(val):
                worse(CustodyClan.inspect_url(val))
            else:
                mode = "write" if role == PATH_WRITE else "read"
                if tool_name == "move_file" and key_path.split("[")[0] == "source":
                    mode = "delete"          # the source disappears from where it was
                worse(LabyrinthClan.inspect_path(val, base_dir=self.base_dir, mode=mode,
                                                 extra_roots=getattr(self.policy, "extra_roots", None),
                                                 policy=self.policy))
        elif role not in (CONTENT, COMMAND, CONFIG) and looks_like_path(val):
            worse(LabyrinthClan.inspect_path(val, base_dir=self.base_dir,
                                             extra_roots=getattr(self.policy, "extra_roots", None),
                                             policy=self.policy))

        # Every string: live credentials. Sending one out via a command/URL is exfiltration.
        sec = CustodyClan.inspect_secrets(val)
        if sec.level >= DecisionLevel.LOCK and getattr(self.policy, "secret_level", "lock") == "ask":
            sec = Verdict(DecisionLevel.ASK, [r + " (owner approval)" for r in sec.reasons], sec.clan, sec.metadata)
        if sec.level > DecisionLevel.PASS:
            worse(sec)
        return found

    def evaluate_tool_call(self, tool_name: str, arguments: Any) -> Verdict:
        """Evaluate an arbitrary tool call before it executes with full recursive coverage."""
        verdict = self._evaluate(tool_name, arguments)
        ledger = getattr(self.gate, "ledger", None)
        if ledger is not None:
            ledger.record(verdict, tool=tool_name, arguments=arguments)
        return verdict

    def _evaluate(self, tool_name: str, arguments: Any) -> Verdict:
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

            # 3. Unknown tools under strict policy go to the owner
            if tool_name not in TOOL_SCHEMAS and getattr(self.policy, "strict_tools", False):
                return self.gate.record(Verdict(
                    DecisionLevel.ASK, [f"Tool '{tool_name}' has no Aegis schema (strict_tools policy)"], "AegisHarness"))

            # 4. Every string argument, classified by role.
            # cmd/PowerShell parsing: when the call names that shell, or on Windows by default.
            shell = arguments.get("shell") if isinstance(arguments, dict) else None
            windows = bool(re.search(r"powershell|pwsh|cmd", shell, re.I)) if isinstance(shell, str) and shell \
                else os.name == "nt"
            worst: Optional[Verdict] = None
            for key_path, val in walk_arguments(arguments):
                role = self._role(tool_name, key_path)
                v = self._check(tool_name, key_path, val, role, windows=windows)
                if v is not None and (worst is None or v.level > worst.level):
                    worst = v
                    if v.level >= DecisionLevel.LOCK:
                        break
            if worst is not None:
                return self.gate.record(worst)

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
