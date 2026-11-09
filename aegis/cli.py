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
import sys
from typing import Any, Dict
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


def run_gate_check(tool_name: str, args_json: str) -> int:
    """Test a tool call against the gate."""
    try:
        args = json.loads(args_json)
    except Exception:
        print("Error: Invalid JSON arguments", file=sys.stderr)
        return 1

    harness = AegisHarness()
    verdict = harness.evaluate_tool_call(tool_name, args)

    print(f"Tool:    {tool_name}")
    print(f"Level:   {verdict.level.name} (Value: {verdict.level.value})")
    print(f"Passed:  {verdict.passed}")
    print(f"Reasons: {', '.join(verdict.reasons)}")
    return 0 if verdict.passed else 1


def run_daemon(port: int = 9999, base_dir: str = ".") -> None:
    """Run local desktop daemon REST API."""
    gate = AegisGate(base_dir=base_dir)
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
            else:
                self.send_response(404)
                self.end_headers()

    print(f"🛡️  Aegis Security Daemon running on http://127.0.0.1:{port}")
    print(f"   - Status: GET  http://127.0.0.1:{port}/status")
    print(f"   - Gate:   POST http://127.0.0.1:{port}/gate")
    server = http.server.HTTPServer(("127.0.0.1", port), DaemonHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDaemon terminated cleanly.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Aegis: Deterministic Monotonic Negative Security Gate for AI Agents")
    subparsers = parser.add_subparsers(dest="command")

    # Audit command
    audit_parser = subparsers.add_parser("audit", help="Audit a file or directory")
    audit_parser.add_argument("path", default=".", nargs="?", help="Path to audit (default: .)")

    # Gate command
    gate_parser = subparsers.add_parser("gate", help="Evaluate a tool call")
    gate_parser.add_argument("tool", help="Tool name (e.g. bash, write_file)")
    gate_parser.add_argument("args", help="Arguments in JSON format")

    # Serve command
    serve_parser = subparsers.add_parser("serve", help="Run local security daemon")
    serve_parser.add_argument("--port", type=int, default=9999, help="Port to listen on (default: 9999)")

    args = parser.parse_args()
    if args.command == "audit":
        sys.exit(run_audit(args.path))
    elif args.command == "gate":
        sys.exit(run_gate_check(args.tool, args.args))
    elif args.command == "serve":
        run_daemon(args.port)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
