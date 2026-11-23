"""One-click setup & health diagnostics for everyday AI tool users.

Detects and safely configures:
    - Claude Code (~/.claude/settings.json)
    - Gemini CLI (~/.gemini/settings.json)
    - Cursor MCP (~/.cursor/mcp.json)
    - Claude Desktop MCP (platform-specific claude_desktop_config.json)
    - Aegis Browser Extension (browser-extension/)

Every configuration edit creates a timestamped backup file first, preserves all
existing user settings/hooks, and can be cleanly reverted.
"""

from __future__ import annotations

import datetime
import json
import os
import platform
import shutil
import sys
import tempfile
from typing import Any, Dict, List, Optional

from . import __version__
from .boundaries import aegis_home, package_dir
from .config import default_policy_path, load_policy_file
from .ledger import DecisionLedger, default_ledger_path
from .clans.minotaur import Tripwires
from .pinning import ToolPins, default_pins_path
from . import sandbox


def _home() -> str:
    return os.path.expanduser("~")


def _aegis_command() -> str:
    """Return the best runnable command for `aegis` on this machine."""
    found = shutil.which("aegis")
    if found:
        return "aegis"
    return f'"{sys.executable}" -m aegis' if " " in sys.executable else f"{sys.executable} -m aegis"


def _aegis_argv() -> List[str]:
    if shutil.which("aegis"):
        return ["aegis"]
    return [sys.executable, "-m", "aegis"]


def claude_code_settings_path() -> str:
    return os.path.join(_home(), ".claude", "settings.json")


def gemini_cli_settings_path() -> str:
    return os.path.join(_home(), ".gemini", "settings.json")


def cursor_mcp_path() -> str:
    return os.path.join(_home(), ".cursor", "mcp.json")


def antigravity_mcp_path() -> str:
    return os.path.join(_home(), ".gemini", "antigravity", "mcp_config.json")


def vscode_mcp_path() -> str:
    sys_name = platform.system()
    if sys_name == "Windows":
        appdata = os.environ.get("APPDATA") or os.path.join(_home(), "AppData", "Roaming")
        return os.path.join(appdata, "Code", "User", "mcp.json")
    if sys_name == "Darwin":
        return os.path.join(_home(), "Library", "Application Support", "Code", "User", "mcp.json")
    xdg = os.environ.get("XDG_CONFIG_HOME") or os.path.join(_home(), ".config")
    return os.path.join(xdg, "Code", "User", "mcp.json")


def claude_desktop_config_path() -> str:
    sys_name = platform.system()
    if sys_name == "Windows":
        appdata = os.environ.get("APPDATA") or os.path.join(_home(), "AppData", "Roaming")
        return os.path.join(appdata, "Claude", "claude_desktop_config.json")
    if sys_name == "Darwin":
        return os.path.join(_home(), "Library", "Application Support", "Claude", "claude_desktop_config.json")
    xdg = os.environ.get("XDG_CONFIG_HOME") or os.path.join(_home(), ".config")
    return os.path.join(xdg, "Claude", "claude_desktop_config.json")


def browser_extension_dir() -> Optional[str]:
    candidate = os.path.abspath(os.path.join(package_dir(), os.pardir, "browser-extension"))
    if os.path.isfile(os.path.join(candidate, "manifest.json")):
        return candidate
    return None


def _read_json_file(path: str) -> Optional[Dict[str, Any]]:
    if not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object in {path}")
    return data


def _backup_and_write_json(path: str, data: Dict[str, Any]) -> Optional[str]:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    backup_path = None
    if os.path.isfile(path):
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup_path = f"{path}.aegis-backup-{stamp}.json"
        shutil.copy2(path, backup_path)
    fd, tmp = tempfile.mkstemp(prefix=".aegis-cfg-", dir=os.path.dirname(path) or ".")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
            fh.write("\n")
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except OSError:
                pass
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass
    return backup_path


def _is_aegis_hook_entry(entry: Any) -> bool:
    if not isinstance(entry, dict):
        return False
    hooks = entry.get("hooks")
    if not isinstance(hooks, list):
        return False
    for h in hooks:
        if isinstance(h, dict):
            cmd = str(h.get("command") or "")
            if "aegis" in cmd and "hook" in cmd:
                return True
    return False


def _has_aegis_hooks(data: Optional[Dict[str, Any]]) -> Dict[str, bool]:
    if not isinstance(data, dict):
        return {"pre": False, "post": False}
    hooks = data.get("hooks")
    if not isinstance(hooks, dict):
        return {"pre": False, "post": False}
    pre = any(_is_aegis_hook_entry(e) for e in (hooks.get("PreToolUse") or []))
    post = any(_is_aegis_hook_entry(e) for e in (hooks.get("PostToolUse") or []))
    return {"pre": pre, "post": post}


def configure_hook_host(path: str, *, enable: bool = True, command_prefix: Optional[str] = None) -> Dict[str, Any]:
    """Safely install or remove Aegis PreToolUse/PostToolUse hooks in a settings.json file."""
    data = _read_json_file(path) or {}
    hooks = data.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError(f"'hooks' in {path} is not a JSON object")

    cmd = (command_prefix or _aegis_command()).strip()
    pre_list = [e for e in (hooks.get("PreToolUse") or []) if not _is_aegis_hook_entry(e)]
    post_list = [e for e in (hooks.get("PostToolUse") or []) if not _is_aegis_hook_entry(e)]

    if enable:
        pre_list.append({
            "matcher": "*",
            "hooks": [{"type": "command", "command": f"{cmd} hook"}],
        })
        post_list.append({
            "matcher": "*",
            "hooks": [{"type": "command", "command": f"{cmd} hook --post"}],
        })

    if pre_list:
        hooks["PreToolUse"] = pre_list
    else:
        hooks.pop("PreToolUse", None)
    if post_list:
        hooks["PostToolUse"] = post_list
    else:
        hooks.pop("PostToolUse", None)

    backup = _backup_and_write_json(path, data)
    return {
        "path": path,
        "enabled": enable,
        "backup": backup,
        "command": cmd,
    }


def _is_native_tekton_server(name: str, cmd: str, args: List[str]) -> bool:
    """Detect Tekton MCP entries that enforce Aegis natively (avoid double-wrapping)."""
    low_name = name.lower()
    low_cmd = os.path.basename(cmd).lower()
    low_args = [a.lower() for a in args]
    if low_cmd in ("tekton", "tekton.exe", "tekton.cmd", "tekton-mcp", "tekton-mcp.exe", "tekton-mcp.cmd"):
        return True
    if "-m" in low_args:
        idx = low_args.index("-m")
        if idx + 1 < len(low_args) and low_args[idx + 1] in ("tekton", "tekton.mcp_server"):
            return True
    if low_name == "tekton" and any("tekton" in part for part in [low_cmd] + low_args):
        return True
    return False


def _mcp_servers_key(data: Dict[str, Any]) -> str:
    if isinstance(data.get("mcpServers"), dict):
        return "mcpServers"
    if isinstance(data.get("servers"), dict):
        return "servers"
    return "mcpServers"


def _inspect_mcp_file(path: str) -> Dict[str, Any]:
    exists = os.path.isfile(path)
    servers: List[Dict[str, Any]] = []
    error = None
    if exists:
        try:
            data = _read_json_file(path) or {}
            mcp_servers = data.get(_mcp_servers_key(data)) or {}
            if isinstance(mcp_servers, dict):
                for name, cfg in sorted(mcp_servers.items()):
                    if not isinstance(cfg, dict):
                        continue
                    cmd = str(cfg.get("command") or "")
                    args = [str(a) for a in (cfg.get("args") or [])] if isinstance(cfg.get("args"), list) else []
                    joined = " ".join([cmd] + args)
                    wrapped = (("mcp-proxy" in args) or ("mcp" in args and "wrap" in args)) and ("aegis" in joined.lower())
                    native_tekton = (not wrapped) and _is_native_tekton_server(name, cmd, args)
                    servers.append({
                        "name": name,
                        "command": cmd,
                        "args": args,
                        "protected": wrapped or native_tekton,
                        "wrapped": wrapped,
                        "nativeAegis": native_tekton,
                        "protectionKind": "aegis-mcp-proxy" if wrapped else ("tekton-native" if native_tekton else "unprotected"),
                    })
        except Exception as exc:
            error = str(exc)
    return {
        "path": path,
        "exists": exists,
        "servers": servers,
        "protectedCount": sum(1 for s in servers if s["protected"]),
        "nativeCount": sum(1 for s in servers if s.get("nativeAegis")),
        "totalCount": len(servers),
        "error": error,
    }


def configure_mcp_server(
    path: str,
    server_name: str,
    *,
    enable: bool = True,
    base_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """Wrap or unwrap an individual MCP server entry in mcp.json / claude_desktop_config.json."""
    data = _read_json_file(path)
    if data is None:
        raise FileNotFoundError(f"MCP config not found: {path}")
    servers_key = _mcp_servers_key(data)
    servers = data.get(servers_key)
    if not isinstance(servers, dict) or server_name not in servers:
        raise KeyError(f"MCP server '{server_name}' not found in {path}")
    entry = servers[server_name]
    if not isinstance(entry, dict):
        raise ValueError(f"MCP server '{server_name}' config is not an object")

    cmd = str(entry.get("command") or "")
    args = [str(a) for a in (entry.get("args") or [])] if isinstance(entry.get("args"), list) else []
    is_wrapped = (("mcp-proxy" in args) or ("mcp" in args and "wrap" in args)) and ("aegis" in " ".join([cmd] + args).lower())
    if enable and not is_wrapped and _is_native_tekton_server(server_name, cmd, args):
        return {
            "path": path,
            "server": server_name,
            "protected": True,
            "nativeAegis": True,
            "backup": None,
            "note": "Tekton enforces Aegis natively; mcp-proxy wrapping is not needed.",
        }

    if enable and not is_wrapped:
        if not cmd:
            raise ValueError(f"MCP server '{server_name}' has no command to wrap")
        prefix = _aegis_argv()
        proxy_args = prefix[1:] + ["mcp-proxy", "--server-id", server_name]
        if base_dir:
            proxy_args += ["--base-dir", os.path.abspath(base_dir)]
        proxy_args += ["--", cmd] + args
        entry["command"] = prefix[0]
        entry["args"] = proxy_args
    elif not enable and is_wrapped:
        if "--" not in args:
            raise ValueError(f"Cannot safely unwrap '{server_name}': missing '--' separator")
        sep = args.index("--")
        upstream = args[sep + 1:]
        if not upstream:
            raise ValueError(f"Cannot safely unwrap '{server_name}': no upstream command")
        entry["command"] = upstream[0]
        entry["args"] = upstream[1:]

    backup = _backup_and_write_json(path, data)
    return {
        "path": path,
        "server": server_name,
        "protected": enable,
        "backup": backup,
    }


def detect_hosts() -> Dict[str, Any]:
    """Detect installed AI hosts and whether Aegis protection is active on each."""
    hosts: Dict[str, Any] = {}

    for key, label, cfg_path in (
        ("claude_code", "Claude Code", claude_code_settings_path()),
        ("gemini_cli", "Gemini CLI", gemini_cli_settings_path()),
    ):
        parent_exists = os.path.isdir(os.path.dirname(cfg_path))
        file_exists = os.path.isfile(cfg_path)
        error = None
        hook_state = {"pre": False, "post": False}
        if file_exists:
            try:
                hook_state = _has_aegis_hooks(_read_json_file(cfg_path))
            except Exception as exc:
                error = str(exc)
        hosts[key] = {
            "id": key,
            "name": label,
            "kind": "hook",
            "path": cfg_path,
            "detected": parent_exists or file_exists,
            "configExists": file_exists,
            "protected": bool(hook_state["pre"] and hook_state["post"]),
            "preHook": hook_state["pre"],
            "postHook": hook_state["post"],
            "error": error,
        }

    for key, label, cfg_path in (
        ("cursor_mcp", "Cursor (MCP)", cursor_mcp_path()),
        ("claude_desktop_mcp", "Claude Desktop (MCP)", claude_desktop_config_path()),
        ("antigravity_mcp", "Antigravity IDE (MCP)", antigravity_mcp_path()),
        ("vscode_mcp", "VS Code (MCP)", vscode_mcp_path()),
    ):
        info = _inspect_mcp_file(cfg_path)
        hosts[key] = {
            "id": key,
            "name": label,
            "kind": "mcp",
            "detected": info["exists"] or os.path.isdir(os.path.dirname(cfg_path)),
            **info,
        }

    ext_dir = browser_extension_dir()
    hosts["browser_extension"] = {
        "id": "browser_extension",
        "name": "Aegis AI Shield (Browser Extension)",
        "kind": "extension",
        "detected": ext_dir is not None,
        "path": ext_dir,
    }
    return hosts


def run_doctor() -> Dict[str, Any]:
    """Collect a complete, truthful health snapshot of Aegis on this machine."""
    policy_path = default_policy_path()
    policy_ok = True
    policy_error = None
    try:
        policy_data = load_policy_file(policy_path)
    except Exception as exc:
        policy_ok = False
        policy_error = str(exc)
        policy_data = {}

    ledger_path = default_ledger_path()
    led = DecisionLedger(ledger_path)
    verify_res = led.verify()

    tripwires_ok = True
    tripwires_error = None
    decoy_count = 0
    canary_count = 0
    try:
        tw = Tripwires.load()
        decoy_count = len(tw.decoy_paths)
        canary_count = len(tw.canaries)
    except Exception as exc:
        tripwires_ok = False
        tripwires_error = str(exc)

    pins_path = default_pins_path()
    pins_ok = True
    pins_error = None
    pinned_servers: Dict[str, int] = {}
    try:
        pins = ToolPins(pins_path)
        for srv, rec in pins._data.get("servers", {}).items():
            pinned_servers[srv] = len(rec.get("tools", {}))
    except Exception as exc:
        pins_ok = False
        pins_error = str(exc)

    sb = sandbox.probe()
    hosts = detect_hosts()

    return {
        "version": __version__,
        "python": platform.python_version(),
        "platform": platform.system(),
        "aegisHome": aegis_home(),
        "command": _aegis_command(),
        "policy": {
            "path": policy_path,
            "exists": os.path.isfile(policy_path),
            "ok": policy_ok,
            "error": policy_error,
            "config": policy_data,
        },
        "ledger": {
            "path": ledger_path,
            "exists": os.path.isfile(ledger_path),
            "ok": verify_res.ok,
            "count": verify_res.count,
            "problem": verify_res.problem,
            "line": verify_res.line,
            "tip": verify_res.tip,
        },
        "tripwires": {
            "ok": tripwires_ok,
            "error": tripwires_error,
            "decoyCount": decoy_count,
            "canaryCount": canary_count,
            "active": decoy_count > 0 or canary_count > 0,
        },
        "pins": {
            "path": pins_path,
            "ok": pins_ok,
            "error": pins_error,
            "servers": pinned_servers,
        },
        "sandbox": sb,
        "hosts": hosts,
    }
