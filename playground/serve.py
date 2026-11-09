"""Aegis Stress Lab Local Server with Live Aegis Negative Gate API."""

import http.server
import json
import os
import sys

# Add parent directory to path so aegis can be imported directly
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from aegis.core import AegisGate
from aegis.harness import AegisHarness

PORT = 9999
DIRECTORY = os.path.dirname(os.path.abspath(__file__))

gate = AegisGate(base_dir=DIRECTORY)
harness = AegisHarness(gate=gate, base_dir=DIRECTORY)


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def log_message(self, format, *args):
        return  # Quiet logging

    def do_GET(self):
        if self.path in {"/status", "/api/status"}:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(gate.snapshot(), indent=2).encode())
        else:
            super().do_GET()

    def do_POST(self):
        if self.path in {"/gate", "/api/gate"}:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            try:
                data = json.loads(body)
                tool = data.get("tool", "test_tool")
                arguments = data.get("arguments", {})
                verdict = harness.evaluate_tool_call(tool, arguments)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(verdict.to_dict()).encode())
            except Exception as e:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode())
        elif self.path in {"/reset", "/api/reset"}:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            try:
                data = json.loads(body)
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
    print(f"   Live Gate API mounted at http://127.0.0.1:{PORT}/gate")
    server = http.server.HTTPServer(("127.0.0.1", PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStress lab server stopped.")
