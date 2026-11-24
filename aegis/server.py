"""Aegis Local Control Center & Hardened Security Daemon (127.0.0.1 only).

Powers both `aegis ui` (opens the offline Control Center in your browser) and
`aegis serve` (background daemon + REST API).

Security properties:
    - Binds exclusively to 127.0.0.1 (never exposed to the network).
    - Rejects cross-origin POST requests via Sec-Fetch-Site and Origin checks.
    - Requires per-launch owner secret (X-Aegis-Token) on all state-mutating endpoints.
    - Caps request bodies at 1 MiB and runs on ThreadingHTTPServer.
    - Logs all gate decisions and approval outcomes to the SHA-256 DecisionLedger.
    - Enforces exact destructive confirmation phrases on pending destructive ASK items.
"""

from __future__ import annotations

import collections
import datetime
import hmac
import http.server
import json
import os
import secrets
import threading
import urllib.parse
import webbrowser
from typing import Any, Deque, Dict, Optional, Tuple

from . import __version__
from .approval import confirms
from .audit import scan_path
from .clans.minotaur import MinotaurClan, Tripwires, plant
from .config import default_policy_path, load_policy_file, save_policy_file, build_policy_from_sources
from .core import AegisGate, DecisionLevel, SUPREME_LAW, Verdict
from .dojo import run_dojo
from .harness import AegisHarness
from .ledger import DecisionLedger, default_ledger_path, summarize_arguments
from .mcp_proxy import AegisMcpProxy
from .setup_wizard import (
    antigravity_mcp_path,
    claude_code_settings_path,
    claude_desktop_config_path,
    configure_hook_host,
    configure_mcp_server,
    cursor_mcp_path,
    detect_hosts,
    gemini_cli_settings_path,
    run_doctor,
    vscode_mcp_path,
)
from .shell import analyze_command
from . import tekton_bridge

MAX_BODY_BYTES = 1024 * 1024
_UI_INDEX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ui", "index.html")


class AegisAppState:
    """Thread-safe runtime state for the local Aegis Control Center and REST API."""

    def __init__(
        self,
        *,
        base_dir: str = ".",
        owner_secret: Optional[str] = None,
        ledger_path: Optional[str] = None,
    ) -> None:
        self.base_dir = os.path.abspath(base_dir)
        self.owner_secret = owner_secret or os.environ.get("AEGIS_OWNER_SECRET") or secrets.token_hex(24)
        self.ledger = DecisionLedger(ledger_path or default_ledger_path(), session="aegis-local-app")
        self.policy = build_policy_from_sources(self.base_dir)
        self.gate = AegisGate(
            base_dir=self.base_dir,
            owner_secret=self.owner_secret,
            policy=self.policy,
            ledger=self.ledger,
        )
        self.harness = AegisHarness(gate=self.gate, base_dir=self.base_dir)
        self._lock = threading.Lock()
        self._approvals: Deque[Dict[str, Any]] = collections.deque(maxlen=200)
        self._verdicts_by_id: Dict[str, Verdict] = {}

    def verify_token(self, token: str) -> bool:
        if not token or not isinstance(token, str):
            return False
        return hmac.compare_digest(token.encode("utf-8"), self.owner_secret.encode("utf-8"))

    def reload_policy(self) -> Dict[str, Any]:
        pol = build_policy_from_sources(self.base_dir)
        with self._lock:
            self.policy = pol
            self.gate.policy = pol
            trip = Tripwires.load()
            if trip.active:
                self.gate.policy.tripwires = trip
            self.gate.minotaur = MinotaurClan(
                tripwires=trip,
                leak_guard=pol.leak_guard,
                probe_threshold=pol.probe_threshold,
                memory_seconds=pol.memory_seconds,
            )
        return load_policy_file()

    def set_workspace(self, path: str) -> Dict[str, Any]:
        cleaned = (path or "").strip()
        if not cleaned or not os.path.isdir(cleaned):
            raise ValueError(f"Directory does not exist: {cleaned or '(empty)'}")
        abs_dir = os.path.abspath(cleaned)
        pol = build_policy_from_sources(abs_dir)
        with self._lock:
            prev_level = self.gate.current_level
            self.base_dir = abs_dir
            self.policy = pol
            self.gate = AegisGate(
                base_dir=self.base_dir,
                owner_secret=self.owner_secret,
                policy=self.policy,
                ledger=self.ledger,
            )
            # Monotonic invariant: changing workspace can never clear an active LOCK/DENY
            if prev_level > self.gate.current_level:
                self.gate.current_level = prev_level
            self.harness = AegisHarness(gate=self.gate, base_dir=self.base_dir)
        return {"ok": True, "baseDir": self.base_dir}

    def build_diagnostics(self) -> Dict[str, Any]:
        from .detective import load_detective_config

        doc = run_doctor()
        v = self.ledger.verify()
        tk = tekton_bridge.get_tekton_status(include_relay=False)
        tk_doc = tk.get("doctor") if isinstance(tk.get("doctor"), dict) else None
        return {
            "generatedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "version": __version__,
            "baseDir": self.base_dir,
            "gate": self.gate.snapshot(),
            "policyPath": default_policy_path(),
            "ledgerPath": default_ledger_path(),
            "ledger": {
                "ok": v.ok,
                "count": v.count,
                "problem": v.problem,
                "tip": v.tip,
            },
            "detective": load_detective_config(),
            "sandbox": doc.get("sandbox"),
            "tripwires": doc.get("tripwires"),
            "tekton": {
                "installed": tk.get("installed", False),
                "version": tk_doc.get("version") if tk_doc else None,
                "aegisGateVersion": tk_doc.get("aegis_gate_version") if tk_doc else None,
                "policyFloor": tk_doc.get("policy_floor") if tk_doc else None,
                "nodeId": tk_doc.get("node_id") if tk_doc else None,
            },
        }

    def evaluate_live(self, tool: str, arguments: Any) -> Dict[str, Any]:
        verdict = self.harness.evaluate_tool_call(tool, arguments)
        out = verdict.to_dict()
        if verdict.level == DecisionLevel.ASK:
            aid = secrets.token_hex(8)
            record = {
                "id": aid,
                "tool": tool,
                "summary": summarize_arguments(tool, arguments),
                "level": verdict.level.name,
                "clan": verdict.clan,
                "reasons": list(verdict.reasons),
                "confirmation": verdict.metadata.get("confirmation"),
                "impact": verdict.metadata.get("impact") or [],
                "createdAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "status": "pending",
                "decidedAt": None,
            }
            with self._lock:
                self._approvals.appendleft(record)
                self._verdicts_by_id[aid] = verdict
                if len(self._verdicts_by_id) > 250:
                    valid_ids = {item["id"] for item in self._approvals}
                    self._verdicts_by_id = {k: v for k, v in self._verdicts_by_id.items() if k in valid_ids}
            out["approvalId"] = aid
        return out

    def list_approvals(self) -> list:
        with self._lock:
            return [dict(item) for item in self._approvals]

    def decide_approval(self, approval_id: str, decision: str, phrase: Optional[str] = None) -> Tuple[int, Dict[str, Any]]:
        if decision not in ("approve", "deny"):
            return 400, {"error": "decision must be 'approve' or 'deny'"}
        with self._lock:
            item = next((x for x in self._approvals if x["id"] == approval_id), None)
            verdict = self._verdicts_by_id.get(approval_id)
            if item is None or verdict is None:
                return 404, {"error": f"Approval '{approval_id}' not found"}
            if item["status"] != "pending":
                return 409, {"error": f"Approval '{approval_id}' is already {item['status']}"}
            if decision == "approve":
                if self.gate.current_level >= DecisionLevel.LOCK:
                    return 409, {"error": "Session is LOCKED; approvals cannot be granted until owner resets session"}
                if verdict.metadata.get("confirmation"):
                    if not confirms(verdict, phrase):
                        return 400, {
                            "error": "Destructive action requires typing the exact confirmation phrase",
                            "requiredPhrase": verdict.metadata["confirmation"]["phrase"],
                        }
                item["status"] = "approved"
            else:
                item["status"] = "denied"
            item["decidedAt"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            result_verdict = Verdict(
                DecisionLevel.PASS if decision == "approve" else DecisionLevel.DENY,
                [f"Owner {item['status']} pending action: {item['summary']}"],
                "OwnerApproval",
                metadata={"approvalId": approval_id, "approved": decision == "approve"},
            )
            self.ledger.record(result_verdict, tool=item["tool"], approved=(decision == "approve"), source="ui-approval")
            return 200, {"ok": True, "approval": dict(item)}

    def explain_dry_run(self, *, command: Optional[str] = None, tool: Optional[str] = None, arguments: Any = None) -> Dict[str, Any]:
        """Dry-run evaluation on an isolated gate so testing dangerous commands never locks live state."""
        pol = self.policy
        if command is not None:
            v = analyze_command(command, base_dir=self.base_dir, policy=pol)
            return {
                "input": command,
                "mode": "command",
                "verdict": v.to_dict(),
            }
        isolated = AegisGate(base_dir=self.base_dir, policy=pol)
        v = AegisHarness(gate=isolated, base_dir=self.base_dir).evaluate_tool_call(tool or "start_process", arguments or {})
        return {
            "input": {"tool": tool, "arguments": arguments},
            "mode": "tool",
            "verdict": v.to_dict(),
        }

    def scan_text(self, text: str) -> Dict[str, Any]:
        proxy = AegisMcpProxy(base_dir=self.base_dir, policy=self.policy)
        _ok, sanitized, verdict = proxy.filter_response(
            {"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": text}]}}
        )
        if verdict is None:
            verdict = Verdict(DecisionLevel.PASS, ["No hidden prompt injections, secrets, or decoy tokens found."], "McpResponseGuard")
        out = verdict.to_dict()
        out["sanitized"] = sanitized["result"]["content"][0]["text"] if sanitized else text
        return out


def _build_handler(state: AegisAppState, port: int):
    allowed_origins = {f"http://127.0.0.1:{port}", f"http://localhost:{port}"}

    class AegisHTTPHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            return  # Keep terminal clean

        def _send_headers(self, status: int, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cache-Control", "no-store")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                "connect-src 'self'; frame-ancestors 'none'",
            )
            self.end_headers()

        def _send_json(self, status: int, payload: Any) -> None:
            body = json.dumps(payload, indent=2, default=str).encode("utf-8")
            self._send_headers(status, "application/json; charset=utf-8")
            self.wfile.write(body)

        def _drain_small_body(self) -> None:
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if 0 < length <= 4096:
                    self.rfile.read(length)
            except (ValueError, OSError):
                pass

        def _check_origin(self) -> bool:
            sec_fetch = (self.headers.get("Sec-Fetch-Site") or "").strip().lower()
            if sec_fetch and sec_fetch not in ("same-origin", "none"):
                self._drain_small_body()
                self._send_json(403, {"error": f"Cross-origin request blocked ({sec_fetch})"})
                return False
            origin = (self.headers.get("Origin") or "").strip().rstrip("/")
            if origin and origin not in allowed_origins:
                self._drain_small_body()
                self._send_json(403, {"error": f"Origin '{origin}' is not permitted"})
                return False
            return True

        def _require_token(self) -> bool:
            token = self.headers.get("X-Aegis-Token", "")
            if not state.verify_token(token):
                self._drain_small_body()
                self._send_json(403, {"error": "Valid X-Aegis-Token header is required"})
                return False
            return True

        def _read_json_body(self) -> Dict[str, Any]:
            raw_len = self.headers.get("Content-Length", "0")
            try:
                length = int(raw_len)
            except ValueError as exc:
                raise ValueError("Invalid Content-Length") from exc
            if length < 0 or length > MAX_BODY_BYTES:
                raise ValueError("Request body exceeds 1 MiB limit")
            raw = self.rfile.read(length) if length > 0 else b"{}"
            data = json.loads(raw.decode("utf-8"))
            if not isinstance(data, dict):
                raise ValueError("Request body must be a JSON object")
            return data

        def do_GET(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path
            qs = urllib.parse.parse_qs(parsed.query)

            if path in ("/", "/index.html"):
                try:
                    with open(_UI_INDEX, "r", encoding="utf-8") as fh:
                        html = fh.read().replace("__AEGIS_SESSION_TOKEN__", state.owner_secret)
                    self._send_headers(200, "text/html; charset=utf-8")
                    self.wfile.write(html.encode("utf-8"))
                except OSError as exc:
                    self._send_json(500, {"error": f"UI asset missing: {exc}"})
                return

            if path in ("/status", "/api/status"):
                self._send_json(200, state.gate.snapshot())
                return

            if path == "/api/overview":
                doc = run_doctor()
                approvals = state.list_approvals()
                self._send_json(200, {
                    "version": __version__,
                    "supremeLaw": SUPREME_LAW,
                    "baseDir": state.base_dir,
                    "gate": state.gate.snapshot(),
                    "doctor": doc,
                    "pendingApprovalCount": sum(1 for a in approvals if a["status"] == "pending"),
                    "tektonDetected": bool(tekton_bridge.find_tekton_binary()),
                })
                return

            if path == "/api/ledger":
                try:
                    n = max(1, min(200, int((qs.get("n") or ["50"])[0])))
                except ValueError:
                    n = 50
                entries = list(reversed(state.ledger.tail(n)))
                v = state.ledger.verify()
                self._send_json(200, {
                    "entries": entries,
                    "verify": {
                        "ok": v.ok,
                        "count": v.count,
                        "problem": v.problem,
                        "line": v.line,
                        "tip": v.tip,
                    },
                })
                return

            if path == "/api/approvals":
                self._send_json(200, {"approvals": state.list_approvals()})
                return

            if path == "/api/policy":
                self._send_json(200, {
                    "path": default_policy_path(),
                    "config": load_policy_file(),
                })
                return

            if path == "/api/setup":
                self._send_json(200, {"hosts": detect_hosts()})
                return

            if path == "/api/detective":
                from . import session as session_store
                from .detective import get_tips, git_snapshot, latest_turn_id, load_detective_config

                sid = (qs.get("session") or ["default"])[0]
                cfg = load_detective_config()
                sdata = session_store.load(sid)
                det = sdata.get("detective") if isinstance(sdata.get("detective"), dict) else {}
                snap = git_snapshot(state.base_dir)
                self._send_json(200, {
                    "config": cfg,
                    "session": sid,
                    "telemetry": det,
                    "latestTurnId": det.get("turnId") or latest_turn_id(sid),
                    "git": snap,
                    "tips": get_tips(det),
                })
                return

            if path == "/api/tekton":
                include_relay = (qs.get("relay") or ["1"])[0] not in ("0", "false", "no")
                self._send_json(200, tekton_bridge.get_tekton_status(include_relay=include_relay))
                return

            if path == "/api/diagnostics":
                self._send_json(200, state.build_diagnostics())
                return

            if path == "/api/ledger/export":
                entries = list(reversed(state.ledger.tail(200)))
                v = state.ledger.verify()
                body = json.dumps({
                    "exportedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "version": __version__,
                    "verify": {"ok": v.ok, "count": v.count, "problem": v.problem, "tip": v.tip},
                    "entries": entries,
                }, indent=2, default=str).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Disposition", 'attachment; filename="aegis-decision-diary.json"')
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)
                return

            self._send_json(404, {"error": "Not found"})

        def do_POST(self) -> None:
            if not self._check_origin():
                return
            path = urllib.parse.urlparse(self.path).path

            if path in ("/gate", "/api/gate"):
                try:
                    payload = self._read_json_body()
                    tool = str(payload.get("tool") or "unknown")
                    arguments = payload.get("arguments", {})
                    self._send_json(200, state.evaluate_live(tool, arguments))
                except Exception as exc:
                    self._send_json(400, {"error": str(exc)})
                return

            if path in ("/reset", "/api/reset"):
                try:
                    payload = self._read_json_body()
                    token = str(payload.get("owner_token") or self.headers.get("X-Aegis-Token") or "")
                    success = state.gate.reset_session(token)
                    self._send_json(200 if success else 403, {
                        "reset": success,
                        "currentLevel": state.gate.current_level.name,
                    })
                except Exception as exc:
                    self._send_json(400, {"error": str(exc)})
                return

            # All Control Center actions below require the per-launch session token.
            if not self._require_token():
                return

            try:
                payload = self._read_json_body()
            except Exception as exc:
                self._send_json(400, {"error": str(exc)})
                return

            if path == "/api/explain":
                try:
                    if "command" in payload and payload["command"] is not None:
                        res = state.explain_dry_run(command=str(payload["command"]))
                    else:
                        res = state.explain_dry_run(
                            tool=str(payload.get("tool") or "start_process"),
                            arguments=payload.get("arguments", {}),
                        )
                    self._send_json(200, res)
                except Exception as exc:
                    self._send_json(400, {"error": str(exc)})
                return

            if path == "/api/scan-text":
                self._send_json(200, state.scan_text(str(payload.get("text") or "")))
                return

            if path == "/api/audit":
                target = str(payload.get("path") or state.base_dir).strip()
                if not target:
                    self._send_json(400, {"error": "Provide a folder or file path to scan"})
                    return
                try:
                    self._send_json(200, scan_path(target))
                except FileNotFoundError as exc:
                    self._send_json(404, {"error": str(exc)})
                except Exception as exc:
                    self._send_json(400, {"error": str(exc)})
                return

            if path == "/api/policy":
                try:
                    saved = save_policy_file(payload)
                    state.reload_policy()
                    self._send_json(200, {"ok": True, "path": default_policy_path(), "config": saved})
                except Exception as exc:
                    self._send_json(400, {"error": str(exc)})
                return

            if path == "/api/minotaur/init":
                ws = str(payload.get("workspace") or state.base_dir).strip()
                try:
                    summary = plant(workspace=ws)
                    state.reload_policy()
                    self._send_json(200, {"ok": True, "summary": summary})
                except Exception as exc:
                    self._send_json(400, {"error": str(exc)})
                return

            if path == "/api/dojo":
                pack = str(payload.get("pack") or "all")
                try:
                    report = run_dojo(mission="control-center-drill", pack=pack)
                    self._send_json(200, report)
                except Exception as exc:
                    self._send_json(400, {"error": str(exc)})
                return

            if path == "/api/approvals/decide":
                status, body = state.decide_approval(
                    str(payload.get("approval_id") or ""),
                    str(payload.get("decision") or ""),
                    phrase=payload.get("phrase"),
                )
                self._send_json(status, body)
                return

            if path == "/api/setup/hook":
                host = str(payload.get("host") or "")
                enable = bool(payload.get("enable", True))
                host_paths = {
                    "claude_code": claude_code_settings_path(),
                    "gemini_cli": gemini_cli_settings_path(),
                }
                if host not in host_paths:
                    self._send_json(400, {"error": f"Unsupported hook host: {host!r}"})
                    return
                try:
                    res = configure_hook_host(host_paths[host], enable=enable)
                    self._send_json(200, {"ok": True, "result": res, "hosts": detect_hosts()})
                except Exception as exc:
                    self._send_json(400, {"error": str(exc)})
                return

            if path == "/api/setup/mcp":
                host = str(payload.get("host") or "")
                server_name = str(payload.get("server") or "")
                enable = bool(payload.get("enable", True))
                base_dir = payload.get("base_dir") or state.base_dir
                host_paths = {
                    "cursor_mcp": cursor_mcp_path(),
                    "claude_desktop_mcp": claude_desktop_config_path(),
                    "antigravity_mcp": antigravity_mcp_path(),
                    "vscode_mcp": vscode_mcp_path(),
                }
                if host not in host_paths:
                    self._send_json(400, {"error": f"Unsupported MCP host: {host!r}"})
                    return
                try:
                    res = configure_mcp_server(host_paths[host], server_name, enable=enable, base_dir=base_dir)
                    self._send_json(200, {"ok": True, "result": res, "hosts": detect_hosts()})
                except Exception as exc:
                    self._send_json(400, {"error": str(exc)})
                return

            if path == "/api/detective/verify-reply":
                from . import session as session_store
                from .detective import verify_reply

                reply_text = str(payload.get("text") or "")
                sid = str(payload.get("session") or "default")
                mode = payload.get("mode")
                sdata = session_store.load(sid)
                det = sdata.get("detective") if isinstance(sdata.get("detective"), dict) else {}
                v = state.ledger.verify()
                warrant = verify_reply(
                    reply_text,
                    cwd=str(payload.get("cwd") or state.base_dir),
                    detective_state=det,
                    mode=str(mode) if mode else None,
                    ledger_tip=v.tip if v.ok else None,
                )
                self._send_json(200, warrant)
                return

            if path == "/api/detective/scan-diff":
                import subprocess
                from .detective import inspect_unified_diff

                target_cwd = str(payload.get("cwd") or state.base_dir)
                diff = subprocess.run(["git", "-C", target_cwd, "diff", "HEAD"], capture_output=True, text=True, check=False)
                findings = inspect_unified_diff(diff.stdout or "")
                self._send_json(200, {
                    "cwd": target_cwd,
                    "passed": not findings,
                    "findingCount": len(findings),
                    "findings": findings,
                })
                return

            if path == "/api/detective/config":
                from .detective import save_detective_config

                try:
                    cfg = save_detective_config(payload)
                    self._send_json(200, {"ok": True, "config": cfg})
                except Exception as exc:
                    self._send_json(400, {"error": str(exc)})
                return

            if path == "/api/detective/undo":
                from .detective import undo_turn

                res = undo_turn(payload.get("turnId"), dry_run=bool(payload.get("dryRun", False)))
                self._send_json(200 if res.get("ok") else 404, res)
                return

            if path == "/api/tekton/launch-gui":
                res = tekton_bridge.launch_tekton_gui()
                self._send_json(200 if res.get("ok") else 400, res)
                return

            if path == "/api/tekton/sync-policy-floor":
                res = tekton_bridge.sync_policy_floor()
                self._send_json(200 if res.get("ok") else 400, res)
                return

            if path == "/api/tekton/allow-dir":
                res = tekton_bridge.allow_workspace_dir(str(payload.get("path") or ""))
                self._send_json(200 if res.get("ok") else 400, res)
                return

            if path == "/api/tekton/remove-dir":
                res = tekton_bridge.remove_workspace_dir(str(payload.get("path") or ""))
                self._send_json(200 if res.get("ok") else 400, res)
                return

            if path == "/api/tekton/approve":
                res = tekton_bridge.decide_tekton_approval(str(payload.get("id") or ""), "approve")
                self._send_json(200 if res.get("ok") else 400, res)
                return

            if path == "/api/tekton/deny":
                res = tekton_bridge.decide_tekton_approval(str(payload.get("id") or ""), "deny")
                self._send_json(200 if res.get("ok") else 400, res)
                return

            if path == "/api/tekton/pair-approve":
                res = tekton_bridge.approve_pair_request(str(payload.get("id") or ""))
                self._send_json(200 if res.get("ok") else 400, res)
                return

            if path == "/api/tekton/unlock":
                res = tekton_bridge.unlock_tekton_session()
                self._send_json(200 if res.get("ok") else 400, res)
                return

            if path == "/api/workspace":
                try:
                    res = state.set_workspace(str(payload.get("path") or ""))
                    self._send_json(200, res)
                except ValueError as exc:
                    self._send_json(400, {"error": str(exc)})
                return

            if path == "/api/shutdown":
                self._send_json(200, {"ok": True, "message": "Aegis Control Center stopping cleanly."})
                threading.Timer(0.15, self.server.shutdown).start()
                return

            self._send_json(404, {"error": "Not found"})

    return AegisHTTPHandler


class AegisHTTPServer(http.server.ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def create_server(
    *,
    port: int = 9999,
    base_dir: str = ".",
    owner_secret: Optional[str] = None,
    ledger_path: Optional[str] = None,
) -> Tuple[AegisHTTPServer, AegisAppState]:
    state = AegisAppState(base_dir=base_dir, owner_secret=owner_secret, ledger_path=ledger_path)
    # Build server first so port=0 works cleanly in tests
    placeholder = _build_handler(state, port)
    server = AegisHTTPServer(("127.0.0.1", port), placeholder)
    actual_port = server.server_address[1]
    if actual_port != port:
        server.RequestHandlerClass = _build_handler(state, actual_port)
    return server, state


def run_server(
    *,
    port: int = 9999,
    base_dir: str = ".",
    owner_secret: Optional[str] = None,
    open_browser: bool = False,
) -> None:
    server, state = create_server(port=port, base_dir=base_dir, owner_secret=owner_secret)
    actual_port = server.server_address[1]
    url = f"http://127.0.0.1:{actual_port}"
    print(f"🛡️  Aegis Control Center running on {url}")
    print(f"   - Dashboard: {url}/")
    print(f"   - Status:    GET  {url}/status")
    print(f"   - Gate API:  POST {url}/gate")
    print(f"   - Reset API: POST {url}/reset")
    print(f"🔑 Session Owner Secret: {state.owner_secret}")
    if open_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nAegis Control Center stopped cleanly.")
    finally:
        server.server_close()
