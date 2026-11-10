"""Aegis CLI & Local Daemon.

Commands:
    aegis audit <target_path>       Scan code/config for OWASP & LLM vulnerabilities
    aegis gate <tool> <args_json>   Test a tool call against the negative gate
    aegis serve [--port 9999]       Run local background security daemon & REST API
"""

from __future__ import annotations

import argparse
import http.server
import json
import os
import secrets
import sys
from typing import Any, Dict, Optional
from .core import AegisGate, SUPREME_LAW, DecisionLevel
from .harness import AegisHarness
from .clans import LabyrinthClan, TartarusClan, CustodyClan

if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def run_audit(target_path: str) -> int:
    """Audit a directory or file."""
    if not os.path.exists(target_path):
        print(f"Error: Target path does not exist: {target_path}", file=sys.stderr)
        return 1

    print(f"🛡️  Aegis Sentinel Audit: {os.path.abspath(target_path)}")
    print(f"📜 Supreme Law: \"{SUPREME_LAW}\"\n")

    gate = AegisGate(base_dir=target_path)
    issues = 0

    if os.path.isfile(target_path):
        files_to_check = [target_path]
    else:
        files_to_check = []
        for root, _, files in os.walk(target_path):
            if any(p in root for p in {".git", "node_modules", ".venv", "__pycache__"}):
                continue
            for f in files:
                files_to_check.append(os.path.join(root, f))

    for filepath in files_to_check:
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            sec_verdict = CustodyClan.inspect_secrets(content)
            if not sec_verdict.passed:
                print(f"  🛑 [{sec_verdict.level.name}] {filepath}: {'; '.join(sec_verdict.reasons)}")
                gate.record(sec_verdict)
                issues += 1

            if filepath.endswith((".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rb", ".php", ".java",
                                  ".sh", ".yml", ".yaml", ".env", ".toml", ".cjs", ".mjs")):
                from .audit import audit_code
                code_verdict = audit_code(content, filepath)
                if not code_verdict.passed:
                    for r in code_verdict.reasons:
                        print(f"  ⚠️  [{code_verdict.level.name}] {filepath}: {r}")
                    issues += 1
        except Exception as e:
            print(f"  ⚠️  [FAIL_CLOSED] {filepath}: Could not read ({e})")
            issues += 1

    print("\n" + "=" * 60)
    if issues == 0:
        print("✅ PASS: Clean code repository. Zero security restrictions triggered.")
        return 0
    else:
        print(f"🛑 FAILED: {issues} security violation(s) detected. Gate escalated to: {gate.current_level.name}")
        return 1


def run_gate_check(tool_name: str, args_json: str, base_dir: Optional[str] = None) -> int:
    """Test a tool call against the gate."""
    try:
        args = json.loads(args_json)
    except Exception:
        print("Error: Invalid JSON arguments", file=sys.stderr)
        return 1

    if not base_dir:
        print("Warning: no --base-dir given, so workspace containment is OFF for this check.", file=sys.stderr)
    harness = AegisHarness(base_dir=base_dir)
    verdict = harness.evaluate_tool_call(tool_name, args)

    print(f"Tool:     {tool_name}")
    print(f"BaseDir:  {base_dir or 'None'}")
    print(f"Level:    {verdict.level.name} (Value: {verdict.level.value})")
    print(f"Passed:   {verdict.passed}")
    print(f"Reasons:  {', '.join(verdict.reasons)}")
    return 0 if verdict.passed else 1


def run_daemon(port: int = 9999, base_dir: str = ".", owner_secret: Optional[str] = None) -> None:
    """Run local desktop daemon REST API."""
    secret = owner_secret or os.environ.get("AEGIS_OWNER_SECRET") or secrets.token_hex(16)
    gate = AegisGate(base_dir=base_dir, owner_secret=secret)
    harness = AegisHarness(gate=gate, base_dir=base_dir)

    class DaemonHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            return  # Quiet logs

        def do_GET(self) -> None:
            if self.path == "/status" or self.path == "/api/status":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(gate.snapshot(), indent=2).encode())
            else:
                self.send_response(404)
                self.end_headers()

        def do_POST(self) -> None:
            if self.path == "/gate" or self.path == "/api/gate":
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)
                try:
                    payload = json.loads(body)
                    tool = payload.get("tool", "unknown")
                    arguments = payload.get("arguments", {})
                    verdict = harness.evaluate_tool_call(tool, arguments)
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(verdict.to_dict()).encode())
                except Exception as e:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": str(e)}).encode())
            elif self.path == "/reset" or self.path == "/api/reset":
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)
                try:
                    payload = json.loads(body)
                    token = payload.get("owner_token", "")
                    success = gate.reset_session(token)
                    self.send_response(200 if success else 403)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"reset": success, "currentLevel": gate.current_level.name}).encode())
                except Exception as e:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": str(e)}).encode())
            else:
                self.send_response(404)
                self.end_headers()

    print(f"🛡️  Aegis Security Daemon running on http://127.0.0.1:{port}")
    print(f"   - Status: GET  http://127.0.0.1:{port}/status")
    print(f"   - Gate:   POST http://127.0.0.1:{port}/gate")
    print(f"   - Reset:  POST http://127.0.0.1:{port}/reset")
    print(f"🔑 Session Owner Secret: {secret}")
    server = http.server.HTTPServer(("127.0.0.1", port), DaemonHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDaemon terminated cleanly.")


def run_explain(command: str, base_dir: Optional[str]) -> int:
    """Show why a shell command gets its verdict (like dcg explain)."""
    from .shell import analyze_command
    v = analyze_command(command, base_dir=base_dir or os.getcwd(), policy=None)
    print(f"Command: {command}")
    print(f"Verdict: {v.level.name}")
    if v.metadata.get("boundary"):
        print(f"Boundary: {v.metadata['boundary']}")
    if v.metadata.get("effects"):
        print(f"Effects: {', '.join(v.metadata['effects'])}")
    if v.metadata.get("impact"):
        for imp in v.metadata["impact"]:
            print(f"Impact: {imp['entries']} items, {imp['bytes']} bytes"
                  + ("+ (stopped early)" if not imp["complete"] else ""))
    for r in v.reasons:
        print(f"  - {r}")
    return 0 if v.level < DecisionLevel.ASK else (2 if v.level >= DecisionLevel.DENY else 1)


def run_minotaur(action: str, workspace: Optional[str]) -> int:
    from .clans.minotaur import MinotaurClan, Tripwires, plant
    if action == "init":
        summary = plant(workspace=workspace or os.getcwd())
        print(f"Planted {len(summary['planted'])} decoy(s), kept {len(summary['kept'])}; "
              f"registry {summary['registry']}")
        for p in summary["planted"]:
            print(f"  + {p}")
        return 0
    m = MinotaurClan(tripwires=Tripwires.load())
    print(json.dumps(m.snapshot(), indent=1))
    return 0


def run_ledger(action: str, n: int, expected_tip: Optional[str] = None) -> int:
    from .ledger import DecisionLedger, default_ledger_path
    led = DecisionLedger(default_ledger_path())
    if action == "verify":
        r = led.verify(expected_tip=expected_tip)
        print(f"{'OK' if r.ok else 'FAILED'}: {r.count} entries"
              + ("" if r.ok else f"; {r.problem} at line {r.line}"))
        return 0 if r.ok else 1
    for ev in led.tail(n):
        print(f"{ev.get('at','')[:19]} {ev.get('level','?'):8} {ev.get('tool','?'):16} "
              f"{ev.get('boundary') or ''} {ev.get('summary','')}")
    return 0


def run_sandbox(action: str, command: Optional[str], base_dir: Optional[str]) -> int:
    from . import sandbox
    if action == "probe":
        print(json.dumps(sandbox.probe(), indent=1))
        return 0
    if action == "run":
        if not command:
            print("Error: provide a command to run", file=sys.stderr)
            return 1
        ws = base_dir or os.getcwd()
        try:
            return sandbox.run(sandbox.SandboxProfile.from_policy(_policy_from_env(), ws), command).returncode
        except sandbox.SandboxUnavailable as exc:
            print(f"Sandbox unavailable: {exc}", file=sys.stderr)
            return 3
    return 1


def run_pin(action: str, server: str, tools_json: str) -> int:
    from .pinning import ToolPins
    try:
        tools = json.loads(tools_json)
        if isinstance(tools, dict):
            tools = tools.get("tools", [])
    except ValueError:
        print("Error: tools must be JSON (a list of tool definitions)", file=sys.stderr)
        return 1
    pins = ToolPins()
    if action == "pin":
        pins.pin(server, tools)
        print(f"Pinned {len(tools)} tool(s) for '{server}'.")
        return 0
    changes = pins.check(server, tools)
    if not changes:
        print(f"'{server}': no changes from the pinned catalogue.")
        return 0
    for c in changes:
        print(f"  [{c.kind}] {c.tool}: {c.detail}")
    return 2


def run_learn(n: int) -> int:
    """Suggest policy tweaks from what has been ASKed most often (you stay in control)."""
    from collections import Counter
    from .ledger import default_ledger_path, iter_entries
    asks: Counter = Counter()
    for ev in iter_entries(default_ledger_path()):
        if ev.get("level") == "ASK" and ev.get("binary"):
            asks[ev["binary"]] += 1
    if not asks:
        print("No ASK history yet. Let Aegis run in your work, then try again.")
        return 0
    print("Most-asked commands (consider adding safe ones to extra_allowed_binaries):")
    for binary, count in asks.most_common(n):
        print(f"  {count:4}  {binary}")
    return 0


def _policy_from_env():
    from .integrations.generic import load_policy
    return load_policy()


def run_hook(post: bool = False, fmt: str = "claude") -> int:
    """Vendor-neutral agent hook. Reads one tool call (or tool result) as JSON on stdin."""
    from .integrations import generic
    from .integrations.claude_code import run_posttooluse, _read_event
    try:
        event = _read_event()
        if post or event.get("hook_event_name") == "PostToolUse":
            return run_posttooluse(event, fmt=fmt)
        d = generic.evaluate(event.get("tool_name") or "", event.get("tool_input", {}),
                             cwd=event.get("cwd"), session_id=event.get("session_id") or "default")
    except Exception as exc:   # fail closed: ask a human rather than silently allow
        d = generic.HookDecision("deny", f"Aegis could not evaluate this call ({type(exc).__name__}).",
                                 "LOCK", None)
    out, code = generic.render(d, fmt=fmt)
    if out:
        (sys.stderr if fmt == "exit" else sys.stdout).write(out + "\n")
    return code


def main() -> None:
    parser = argparse.ArgumentParser(description="Aegis: deterministic negative security gate & firewall for AI agents")
    sub = parser.add_subparsers(dest="subcommand")
    dojo = sub.add_parser("dojo", help="Run bounded offline simulations from the six legacy knowledge packs")
    dojo.add_argument("--mission", required=True)
    dojo.add_argument("--pack", choices=("all", "01", "02", "03", "04", "05", "06"), default="all")

    ap = sub.add_parser("audit", help="Scan a file or directory for secrets and OWASP issues")
    ap.add_argument("path", default=".", nargs="?")

    gp = sub.add_parser("gate", help="Evaluate a tool call (JSON args)")
    gp.add_argument("tool"); gp.add_argument("args")
    gp.add_argument("--base-dir", default=None)

    ep = sub.add_parser("explain", help="Explain the verdict for a shell command")
    ep.add_argument("command"); ep.add_argument("--base-dir", default=None)

    mp = sub.add_parser("minotaur", help="Tripwires: init (plant decoys) or status")
    mp.add_argument("action", choices=["init", "status"]); mp.add_argument("--workspace", default=None)

    lp = sub.add_parser("ledger", help="Decision ledger: tail or verify")
    lp.add_argument("action", choices=["tail", "verify"]); lp.add_argument("-n", type=int, default=20)
    lp.add_argument("--expect-tip", default=None, help="Trusted external digest to detect removed tail entries")

    spn = sub.add_parser("sandbox", help="Confinement: probe the host or run a command confined")
    spn.add_argument("action", choices=["probe", "run"]); spn.add_argument("command", nargs="?")
    spn.add_argument("--base-dir", default=None)

    pp = sub.add_parser("pin", help="MCP tool pinning: check or pin a server's tools")
    pp.add_argument("action", choices=["check", "pin"]); pp.add_argument("server"); pp.add_argument("tools")

    lrn = sub.add_parser("learn", help="Suggest policy tweaks from the ledger (you decide)")
    lrn.add_argument("-n", type=int, default=15)

    hp = sub.add_parser("hook", help="Run as an agent hook (reads a tool call as JSON on stdin)")
    hp.add_argument("--post", action="store_true", help="PostToolUse mode (scan output for decoys)")
    hp.add_argument("--format", choices=("claude", "json", "exit"), default="claude",
                    help="Output shape: claude/gemini/copilot JSON (default), plain json, or exit-code only")

    svp = sub.add_parser("serve", help="Run local security daemon")
    svp.add_argument("--port", type=int, default=9999); svp.add_argument("--base-dir", default=".")

    args = parser.parse_args()
    if args.subcommand == "dojo":
        from .dojo import run_dojo
        report = run_dojo(mission=args.mission, pack=args.pack)
        print(json.dumps(report, indent=2))
        sys.exit(0 if report["passed"] else 1)
    elif args.subcommand == "audit":
        sys.exit(run_audit(args.path))
    elif args.subcommand == "gate":
        sys.exit(run_gate_check(args.tool, args.args, base_dir=args.base_dir))
    elif args.subcommand == "explain":
        sys.exit(run_explain(args.command, args.base_dir))
    elif args.subcommand == "minotaur":
        sys.exit(run_minotaur(args.action, args.workspace))
    elif args.subcommand == "ledger":
        sys.exit(run_ledger(args.action, args.n, args.expect_tip))
    elif args.subcommand == "sandbox":
        sys.exit(run_sandbox(args.action, args.command, args.base_dir))
    elif args.subcommand == "pin":
        sys.exit(run_pin(args.action, args.server, args.tools))
    elif args.subcommand == "learn":
        sys.exit(run_learn(args.n))
    elif args.subcommand == "hook":
        sys.exit(run_hook(post=args.post, fmt=args.format))
    elif args.subcommand == "serve":
        run_daemon(args.port, base_dir=args.base_dir)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
