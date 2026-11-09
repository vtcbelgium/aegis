"""Aegis Stress Lab Local Server."""

import http.server
import os
import sys

PORT = 9999
DIRECTORY = os.path.dirname(os.path.abspath(__file__))


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def log_message(self, format, *args):
        # Quiet logging
        return


if __name__ == "__main__":
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    print(f"🛡️  Aegis Adversarial Stress Lab running at: http://127.0.0.1:{PORT}")
    print(f"   Open this URL in your browser to stress-test prompt injection, SSRF & concurrency!")
    server = http.server.HTTPServer(("127.0.0.1", PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStress lab server stopped.")
