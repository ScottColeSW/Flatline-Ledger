#!/usr/bin/env python3
"""A minimal reverse-proxy compensating control for pt21.

Whatever triggers an unhandled backend error, the response should
never be a raw stack trace. The compensating control: inspect every
outbound response body for the markers Juice Shop's own error
template always includes (file paths under node_modules, the
<ul id="stacktrace"> block, "<file>.js:<line>" fragments) and replace
the body with a generic error message before it reaches the client,
preserving the original status code.

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
PROXY_PORT = int(os.environ.get("FLATLINE_PROXY_PORT", "3022"))
ENFORCE = os.environ.get("FLATLINE_ENFORCE", "1") != "0"

ledger.guard_target_host(BACKEND)

LEAK_MARKERS = (b"node_modules", b"stacktrace", b".js:")


def _leaks_internals(body: bytes) -> bool:
    return any(marker in body for marker in LEAK_MARKERS)


class ProxyHandler(BaseHTTPRequestHandler):
    def _forward(self, method: str) -> None:
        length = self.headers.get("Content-Length")
        body = self.rfile.read(int(length)) if length else None

        req = urllib.request.Request(BACKEND + self.path, data=body, method=method)
        if self.headers.get("Content-Type"):
            req.add_header("Content-Type", self.headers["Content-Type"])
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                status, resp_body = resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            status, resp_body = exc.code, exc.read()

        if ENFORCE and _leaks_internals(resp_body):
            resp_body = json.dumps({
                "status": "error",
                "message": "An internal error occurred.",
            }).encode()

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
    print(f"pt21 proxy: {mode}, {BACKEND} -> 127.0.0.1:{PROXY_PORT}")
    server = ThreadingHTTPServer(("127.0.0.1", PROXY_PORT), ProxyHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
