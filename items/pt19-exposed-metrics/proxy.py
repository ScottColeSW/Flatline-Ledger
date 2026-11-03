#!/usr/bin/env python3
"""A minimal reverse-proxy compensating control for pt19.

GET /metrics has no authorization middleware at all. The compensating
control: require a shared-secret header before forwarding, the same
pattern a real deployment would put a monitoring scraper's credential
behind. The token here is a stand-in value for this item's own test,
not a real secret.

Toggle with FLATLINE_ENFORCE=0 to run the identical code path with the
check disabled.

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
PROXY_PORT = int(os.environ.get("FLATLINE_PROXY_PORT", "3020"))
ENFORCE = os.environ.get("FLATLINE_ENFORCE", "1") != "0"

ledger.guard_target_host(BACKEND)

METRICS_TOKEN_HEADER = "X-Metrics-Token"
METRICS_TOKEN_VALUE = "flatline-pt19-shared-secret"


class ProxyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if ENFORCE and self.path == "/metrics" and self.headers.get(METRICS_TOKEN_HEADER) != METRICS_TOKEN_VALUE:
            blocked = json.dumps({
                "status": "forbidden",
                "message": "pt19 compensating control: missing or incorrect metrics token",
            }).encode()
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(blocked)))
            self.end_headers()
            self.wfile.write(blocked)
            return

        req = urllib.request.Request(BACKEND + self.path, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                status, resp_body = resp.status, resp.read()
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
    print(f"pt19 proxy: {mode}, {BACKEND} -> 127.0.0.1:{PROXY_PORT}")
    server = ThreadingHTTPServer(("127.0.0.1", PROXY_PORT), ProxyHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
