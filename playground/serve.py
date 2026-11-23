"""Aegis Stress Lab Local Server with Live Aegis Negative Gate API."""

import http.server
import json
import os
import sys

# Add parent directory to path so aegis can be imported directly
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import secrets

from aegis.core import AegisGate, DecisionLevel, Verdict
from aegis.harness import AegisHarness
from aegis.mcp_proxy import AegisMcpProxy

PORT = 9999
DIRECTORY = os.path.dirname(os.path.abspath(__file__))

OWNER_SECRET = os.environ.get("AEGIS_OWNER_SECRET") or secrets.token_hex(16)
# Telemetry gate: records every demo verdict without escalating, so one LOCK demo
# does not freeze the playground. Each demo call is evaluated on a fresh session.
gate = AegisGate(base_dir=DIRECTORY, owner_secret=OWNER_SECRET)


def evaluate(tool, arguments):
    session = AegisGate(base_dir=DIRECTORY, owner_secret=OWNER_SECRET)
    verdict = AegisHarness(gate=session, base_dir=DIRECTORY).evaluate_tool_call(tool, arguments)
    gate.record(verdict, escalate=False)
    return verdict


def scan(text):
    proxy = AegisMcpProxy(base_dir=DIRECTORY, owner_secret=OWNER_SECRET)
    ok, sanitized, verdict = proxy.filter_response(
        {"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": text}]}})
    if verdict is None:
        verdict = Verdict(DecisionLevel.PASS, ["Tool output is clean"], "McpResponseGuard")
    gate.record(verdict, escalate=False)
    out = verdict.to_dict()
    out["sanitized"] = sanitized["result"]["content"][0]["text"] if sanitized else text
    return out


MAX_BODY_BYTES = 1024 * 1024


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def log_message(self, format, *args):
        return  # Quiet logging

    def _read_json(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length < 0 or length > MAX_BODY_BYTES:
            raise ValueError("Request body too large")
        return json.loads(self.rfile.read(length) if length else b"{}")

    def do_GET(self):
        if self.path in {"/status", "/api/status"}:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(gate.snapshot(), indent=2).encode())
        elif self.path in {"/", "/index.html"}:
            self.path = "/index.html"
            super().do_GET()
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        sec_fetch = self.headers.get("Sec-Fetch-Site", "")
        if sec_fetch and sec_fetch not in ("same-origin", "none"):
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Cross-origin requests are forbidden"}).encode())
            return
        if self.path in {"/gate", "/api/gate"}:
            try:
                data = self._read_json()
                tool = data.get("tool", "test_tool")
                arguments = data.get("arguments", {})
                verdict = evaluate(tool, arguments)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(verdict.to_dict()).encode())
            except Exception as e:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode())
        elif self.path in {"/scan", "/api/scan"}:
            try:
                data = self._read_json()
                body = json.dumps(scan(str(data.get("text", "")))).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)
            except Exception as e:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode())
        elif self.path in {"/reset", "/api/reset"}:
            try:
                data = self._read_json()
                token = data.get("owner_token", "")
                success = gate.reset_session(token)
                self.send_response(200 if success else 403)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"reset": success, "currentLevel": gate.current_level.name}).encode())
            except Exception as e:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode())
        else:
            self.send_response(404)
            self.end_headers()


if __name__ == "__main__":
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    print(f"🛡️  Aegis Adversarial Stress Lab running at: http://127.0.0.1:{PORT}")
    print(f"   Live Gate API mounted at http://127.0.0.1:{PORT}/gate and /scan")
    print(f"🔑 Owner secret for /reset: {OWNER_SECRET}")
    server = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStress lab server stopped.")
