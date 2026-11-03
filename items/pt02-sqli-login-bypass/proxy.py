#!/usr/bin/env python3
"""A minimal reverse-proxy compensating control for pt02.

Juice Shop's login endpoint builds its SQL query by string-concatenating
the submitted email, so a crafted email short-circuits the WHERE clause.
Like pt01, the "fix" here is a control in front of a vendored image we
can't patch: a login-request filter that rejects common SQL-injection
metacharacters in the email/password fields before forwarding to the
real backend.

This is deliberately the naive version of that filter (reject on sight
of a single quote, --, ;, or /* */), because the naive version is what
most teams actually ship first, and it is worth being honest about what
it costs: it also rejects a login whose email legitimately contains an
apostrophe (see README). Toggle with FLATLINE_ENFORCE=0 to run the
identical code path with the filter disabled.

Standard library only.
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
import ledger  # noqa: E402

BACKEND = os.environ.get("FLATLINE_BACKEND", "http://localhost:3001")
PROXY_PORT = int(os.environ.get("FLATLINE_PROXY_PORT", "3003"))
ENFORCE = os.environ.get("FLATLINE_ENFORCE", "1") != "0"

ledger.guard_target_host(BACKEND)

SUSPICIOUS_PATTERN = re.compile(r"'|--|;|/\*|\*/")


class ProxyHandler(BaseHTTPRequestHandler):
    def _forward(self, method: str) -> None:
        length = self.headers.get("Content-Length")
        body = self.rfile.read(int(length)) if length else None

        if ENFORCE and method == "POST" and self.path == "/rest/user/login" and body:
            try:
                parsed = json.loads(body)
            except Exception:
                parsed = {}
            email = parsed.get("email", "") or ""
            password = parsed.get("password", "") or ""
            if SUSPICIOUS_PATTERN.search(email) or SUSPICIOUS_PATTERN.search(password):
                blocked = json.dumps({
                    "status": "forbidden",
                    "message": "pt02 compensating control: suspicious character in login field",
                }).encode()
                self.send_response(403)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(blocked)))
                self.end_headers()
                self.wfile.write(blocked)
                return

        req = urllib.request.Request(BACKEND + self.path, data=body, method=method)
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

    def do_GET(self):
        self._forward("GET")

    def do_POST(self):
        self._forward("POST")

    def log_message(self, fmt, *args):
        pass


def main() -> None:
    mode = "ENFORCING" if ENFORCE else "passthrough (no enforcement)"
    print(f"pt02 proxy: {mode}, {BACKEND} -> 127.0.0.1:{PROXY_PORT}")
    server = ThreadingHTTPServer(("127.0.0.1", PROXY_PORT), ProxyHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
