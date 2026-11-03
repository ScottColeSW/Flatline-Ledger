#!/usr/bin/env python3
"""A minimal reverse-proxy compensating control for pt07.

The admin account's own password can't be rotated from outside the
running container without reaching into its database, so the realistic
fix at this layer is what NIST 800-63B actually recommends: reject
known-weak/breached passwords at login time, regardless of whose
account is being logged into. proxy.py blocks any login attempt whose
password is on a small blocklist, before it ever reaches the backend.

A real deployment would check against a proper breached-password list
(e.g. HaveIBeenPwned's Pwned Passwords); this uses the small blueprint
list instead, to keep the control's own behavior fully offline and
reproducible.

Toggle with FLATLINE_ENFORCE=0 to run the identical code path with the
blocklist disabled.

Standard library only.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
import ledger  # noqa: E402

BACKEND = os.environ.get("FLATLINE_BACKEND", "http://localhost:3001")
PROXY_PORT = int(os.environ.get("FLATLINE_PROXY_PORT", "3009"))
ENFORCE = os.environ.get("FLATLINE_ENFORCE", "1") != "0"

ledger.guard_target_host(BACKEND)

BLOCKLIST_PATH = Path(__file__).resolve().parent / "blueprints" / "pt07-001.json"
PASSWORD_BLOCKLIST = set(json.loads(BLOCKLIST_PATH.read_text())["password_blocklist"])


class ProxyHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = self.headers.get("Content-Length")
        body = self.rfile.read(int(length)) if length else b""

        if ENFORCE and self.path == "/rest/user/login" and body:
            try:
                parsed = json.loads(body)
            except Exception:
                parsed = {}
            if parsed.get("password") in PASSWORD_BLOCKLIST:
                blocked = json.dumps({
                    "status": "forbidden",
                    "message": "pt07 compensating control: password is on the known-weak blocklist",
                }).encode()
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(blocked)))
                self.end_headers()
                self.wfile.write(blocked)
                return

        req = urllib.request.Request(BACKEND + self.path, data=body, method="POST")
        if self.headers.get("Content-Type"):
            req.add_header("Content-Type", self.headers["Content-Type"])
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                status, resp_body = resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            status, resp_body = exc.code, exc.read()

        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp_body)))
        self.end_headers()
        self.wfile.write(resp_body)

    def log_message(self, fmt, *args):
        pass


def main() -> None:
    mode = "ENFORCING" if ENFORCE else "passthrough (no enforcement)"
    print(f"pt07 proxy: {mode}, {BACKEND} -> 127.0.0.1:{PROXY_PORT}")
    server = ThreadingHTTPServer(("127.0.0.1", PROXY_PORT), ProxyHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
