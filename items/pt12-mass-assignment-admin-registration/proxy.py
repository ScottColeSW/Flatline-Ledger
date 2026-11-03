#!/usr/bin/env python3
"""A minimal reverse-proxy compensating control for pt12.

POST /api/Users accepts and assigns a client-supplied "role" field
outright. The compensating control: strip "role" from the registration
body entirely before forwarding, the same "correct, don't reject"
approach pt11 uses. Registration still succeeds; it just can no longer
self-assign a privilege level.

Toggle with FLATLINE_ENFORCE=0 to run the identical code path with the
stripping disabled.

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
PROXY_PORT = int(os.environ.get("FLATLINE_PROXY_PORT", "3014"))
ENFORCE = os.environ.get("FLATLINE_ENFORCE", "1") != "0"

ledger.guard_target_host(BACKEND)


class ProxyHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = self.headers.get("Content-Length")
        body = self.rfile.read(int(length)) if length else b""

        if ENFORCE and self.path == "/api/Users" and body:
            try:
                parsed = json.loads(body)
            except Exception:
                parsed = {}
            parsed.pop("role", None)  # strip, never trust a self-assigned privilege level
            body = json.dumps(parsed).encode()

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
    print(f"pt12 proxy: {mode}, {BACKEND} -> 127.0.0.1:{PROXY_PORT}")
    server = ThreadingHTTPServer(("127.0.0.1", PROXY_PORT), ProxyHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
