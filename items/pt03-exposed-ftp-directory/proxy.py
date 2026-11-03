#!/usr/bin/env python3
"""A minimal reverse-proxy compensating control for pt03.

The /ftp/ path is a legacy file drop with directory listing turned on
and no authentication at all. The realistic fix a team ships fast,
without redesigning the backend, is a default-deny on that whole path
with an explicit allowlist for anything confirmed to be intentionally
public. Here that allowlist is exactly one file: legal.md, which has no
"confidential" marker and reads like a genuine public terms document
(see README for why this isn't assumed, it's checked).

Everything else under /ftp/, including the directory listing itself,
gets blocked. Toggle with FLATLINE_ENFORCE=0 to run the identical code
path with the block disabled.

Standard library only.
"""

from __future__ import annotations

import http.client
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
PROXY_PORT = int(os.environ.get("FLATLINE_PROXY_PORT", "3004"))
ENFORCE = os.environ.get("FLATLINE_ENFORCE", "1") != "0"

ledger.guard_target_host(BACKEND)

ALLOWLIST = {"/ftp/legal.md"}


class ProxyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if ENFORCE and self.path.startswith("/ftp/") and self.path not in ALLOWLIST:
            blocked = json.dumps({
                "status": "forbidden",
                "message": "pt03 compensating control: /ftp/ is default-deny except the public-doc allowlist",
            }).encode()
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(blocked)))
            self.end_headers()
            self.wfile.write(blocked)
            return

        req = urllib.request.Request(BACKEND + self.path, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                try:
                    status, resp_body = resp.status, resp.read()
                except http.client.IncompleteRead as exc:
                    status, resp_body = resp.status, exc.partial
        except urllib.error.HTTPError as exc:
            status, resp_body = exc.code, exc.read()

        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(resp_body)))
        self.end_headers()
        self.wfile.write(resp_body)

    def log_message(self, fmt, *args):
        pass


def main() -> None:
    mode = "ENFORCING" if ENFORCE else "passthrough (no enforcement)"
    print(f"pt03 proxy: {mode}, {BACKEND} -> 127.0.0.1:{PROXY_PORT}")
    server = ThreadingHTTPServer(("127.0.0.1", PROXY_PORT), ProxyHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
