"""Persistent, human-friendly Aegis policy configuration (~/.aegis/policy.json).

Stored inside AEGIS_HOME so it is automatically protected by the AEGIS_POLICY_TAMPER
hard boundary (agents cannot modify it; only the human owner or local UI can).
Environment variables (AEGIS_*) still override file values when explicitly set.
"""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any, Dict, List, Optional

from .boundaries import aegis_home
from .policy import AegisPolicy, DEFAULT_ALLOWED_DOMAINS

POLICY_SCHEMA = "aegis.policy.v1"

_ALLOWED_ENUMS = {
    "project_exec": ("allow", "ask"),
    "pass_policy": ("strict", "critical_only"),
    "unknown_binary": ("ask", "deny"),
    "secret_level": ("lock", "ask"),
    "inline_exec": ("ask", "allow"),
    "leak_guard": ("ask", "deny", "off"),
    "code_audit": ("warn", "off"),
}


def default_policy_path() -> str:
    return os.path.join(aegis_home(), "policy.json")


def _clean_str_list(value: Any, field: str, *, max_items: int = 200) -> List[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ValueError(f"Policy field '{field}' must be a list of strings")
    out: List[str] = []
    seen = set()
    for raw in value:
        item = raw.strip()
        if not item:
            continue
        if len(item) > 512 or "\x00" in item or "\n" in item or "\r" in item:
            raise ValueError(f"Invalid entry in policy field '{field}'")
        if item not in seen:
            seen.add(item)
            out.append(item)
        if len(out) > max_items:
            raise ValueError(f"Policy field '{field}' exceeds {max_items} items")
    return out


def _clean_ports(value: Any) -> List[int]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("Policy field 'allowed_loopback_ports' must be a list of port integers")
    out: List[int] = []
    seen = set()
    for item in value:
        if isinstance(item, bool) or not isinstance(item, int) or not (1 <= item <= 65535):
            raise ValueError(f"Invalid loopback port: {item!r}")
        if item not in seen:
            seen.add(item)
            out.append(item)
    return sorted(out)


def default_policy_dict() -> Dict[str, Any]:
    d = AegisPolicy()
    return {
        "schema": POLICY_SCHEMA,
        "project_exec": d.project_exec,
        "pass_policy": d.pass_policy,
        "unknown_binary": d.unknown_binary,
        "secret_level": d.secret_level,
        "inline_exec": d.inline_exec,
        "leak_guard": d.leak_guard,
        "code_audit": d.code_audit,
        "strict_tools": d.strict_tools,
        "extra_roots": [],
        "extra_allowed_binaries": [],
        "extra_allowed_domains": [],
        "allowed_loopback_ports": [],
        "blast_max_entries": d.blast_max_entries,
        "blast_max_bytes": d.blast_max_bytes,
    }


def validate_policy_dict(raw: Any) -> Dict[str, Any]:
    """Validate and normalize a user policy dictionary. Raises ValueError on bad inputs."""
    if not isinstance(raw, dict):
        raise ValueError("Policy config must be a JSON object")
    schema = raw.get("schema", POLICY_SCHEMA)
    if schema != POLICY_SCHEMA:
        raise ValueError(f"Unsupported policy schema: {schema!r}")

    normalized = default_policy_dict()
    for key, allowed in _ALLOWED_ENUMS.items():
        if key in raw and raw[key] is not None:
            val = str(raw[key]).strip().lower()
            if val not in allowed:
                raise ValueError(f"Policy field '{key}' must be one of {allowed}, got {val!r}")
            normalized[key] = val

    if "strict_tools" in raw and raw["strict_tools"] is not None:
        if not isinstance(raw["strict_tools"], bool):
            raise ValueError("Policy field 'strict_tools' must be a boolean")
        normalized["strict_tools"] = raw["strict_tools"]

    if "extra_roots" in raw:
        normalized["extra_roots"] = _clean_str_list(raw["extra_roots"], "extra_roots")
    if "extra_allowed_binaries" in raw:
        normalized["extra_allowed_binaries"] = [
            b.lower() for b in _clean_str_list(raw["extra_allowed_binaries"], "extra_allowed_binaries")
        ]
    if "extra_allowed_domains" in raw:
        normalized["extra_allowed_domains"] = [
            dom.lower().strip(".") for dom in _clean_str_list(raw["extra_allowed_domains"], "extra_allowed_domains")
        ]
    if "allowed_loopback_ports" in raw:
        normalized["allowed_loopback_ports"] = _clean_ports(raw["allowed_loopback_ports"])

    if "blast_max_entries" in raw and raw["blast_max_entries"] is not None:
        val = raw["blast_max_entries"]
        if isinstance(val, bool) or not isinstance(val, int) or not (1 <= val <= 100_000):
            raise ValueError("Policy field 'blast_max_entries' must be an integer between 1 and 100000")
        normalized["blast_max_entries"] = val

    if "blast_max_bytes" in raw and raw["blast_max_bytes"] is not None:
        val = raw["blast_max_bytes"]
        if isinstance(val, bool) or not isinstance(val, int) or not (1024 <= val <= 100 * 1024 * 1024 * 1024):
            raise ValueError("Policy field 'blast_max_bytes' must be an integer between 1024 and 100 GiB")
        normalized["blast_max_bytes"] = val

    return normalized


def load_policy_file(path: Optional[str] = None) -> Dict[str, Any]:
    """Load and validate ~/.aegis/policy.json. Missing file returns defaults; corrupt file raises."""
    cfg_path = path or default_policy_path()
    try:
        with open(cfg_path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except FileNotFoundError:
        return default_policy_dict()
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Invalid Aegis policy file '{cfg_path}': {exc}") from exc
    return validate_policy_dict(raw)


def save_policy_file(data: Dict[str, Any], path: Optional[str] = None) -> Dict[str, Any]:
    """Validate and atomically save ~/.aegis/policy.json."""
    normalized = validate_policy_dict(data)
    cfg_path = path or default_policy_path()
    directory = os.path.dirname(cfg_path) or "."
    os.makedirs(directory, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".policy-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(normalized, fh, indent=2)
            fh.write("\n")
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except OSError:
                pass
        os.replace(tmp, cfg_path)
        try:
            os.chmod(cfg_path, 0o600)
        except OSError:
            pass
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass
    return normalized


def build_policy_from_sources(workspace: Optional[str] = None, path: Optional[str] = None) -> AegisPolicy:
    """Build AegisPolicy from defaults -> ~/.aegis/policy.json -> AEGIS_* environment overrides."""
    cfg = load_policy_file(path)
    env = os.environ.get

    def pick_enum(env_name: str, key: str) -> str:
        raw = env(env_name)
        if raw is not None and raw.strip():
            val = raw.strip().lower()
            if val not in _ALLOWED_ENUMS[key]:
                raise ValueError(f"Invalid {env_name}={raw!r}; expected one of {_ALLOWED_ENUMS[key]}")
            return val
        return cfg[key]

    extra_roots = list(cfg["extra_roots"])
    env_roots = env("AEGIS_EXTRA_ROOTS")
    if env_roots is not None and env_roots.strip():
        for r in env_roots.split(os.pathsep):
            r = r.strip()
            if r and r not in extra_roots:
                extra_roots.append(r)

    strict_env = env("AEGIS_STRICT_TOOLS")
    if strict_env is not None and strict_env.strip():
        strict_tools = strict_env.strip().lower() in ("1", "true", "yes")
    else:
        strict_tools = bool(cfg["strict_tools"])

    domains = set(DEFAULT_ALLOWED_DOMAINS)
    domains.update(cfg["extra_allowed_domains"])

    return AegisPolicy(
        allowed_domains=domains,
        project_exec=pick_enum("AEGIS_PROJECT_EXEC", "project_exec"),
        pass_policy=pick_enum("AEGIS_PASS_POLICY", "pass_policy"),
        unknown_binary=pick_enum("AEGIS_UNKNOWN_BINARY", "unknown_binary"),
        extra_allowed_binaries=set(cfg["extra_allowed_binaries"]),
        strict_tools=strict_tools,
        extra_roots=extra_roots,
        secret_level=pick_enum("AEGIS_SECRET_LEVEL", "secret_level"),
        inline_exec=pick_enum("AEGIS_INLINE_EXEC", "inline_exec"),
        allowed_loopback_ports=set(cfg["allowed_loopback_ports"]),
        leak_guard=pick_enum("AEGIS_LEAK_GUARD", "leak_guard"),
        code_audit=pick_enum("AEGIS_CODE_AUDIT", "code_audit"),
        blast_max_entries=int(cfg["blast_max_entries"]),
        blast_max_bytes=int(cfg["blast_max_bytes"]),
    )
