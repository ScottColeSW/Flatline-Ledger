#!/usr/bin/env python3
"""A minimal reverse-proxy compensating control for pt29.

PATCH /rest/products/reviews passes req.body.id straight into a
marsdb filter with no type check at all: a MongoDB-style query
operator object (such as {"$in": [...]} or {"$ne": null}) in place of
a plain string id reaches every review that operator matches, not
just the caller's own. The real frontend only ever sends a plain
string id for the single review being edited, so this proxy rejects
any request whose id field is not a string before it ever reaches the
backend. Every other request shape passes through unchanged.

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
PROXY_PORT = int(os.environ.get("FLATLINE_PROXY_PORT", "3030"))
ENFORCE = os.environ.get("FLATLINE_ENFORCE", "1") != "0"

ledger.guard_target_host(BACKEND)


class ProxyHandler(BaseHTTPRequestHandler):
    def do_PATCH(self):
        length = self.headers.get("Content-Length")
        body = self.rfile.read(int(length)) if length else b""

        if ENFORCE and self.path == "/rest/products/reviews":
            try:
                parsed = json.loads(body) if body else {}
            except Exception:
                parsed = {}
            if "id" in parsed and not isinstance(parsed["id"], str):
                resp_body = b'{"error":"id must be a plain string, not a query object."}'
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp_body)))
                self.end_headers()
                self.wfile.write(resp_body)
                return

        self._forward("PATCH", body)

    def do_PUT(self):
        length = self.headers.get("Content-Length")
        body = self.rfile.read(int(length)) if length else b""
        self._forward("PUT", body)

    def do_POST(self):
        length = self.headers.get("Content-Length")
        body = self.rfile.read(int(length)) if length else b""
        self._forward("POST", body)

    def do_GET(self):
        self._forward("GET", None)

    def _forward(self, method: str, body: bytes | None) -> None:
        req = urllib.request.Request(BACKEND + self.path, data=body, method=method)
        for header in ("Content-Type", "Authorization"):
            if self.headers.get(header):
                req.add_header(header, self.headers[header])
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
    print(f"pt29 proxy: {mode}, {BACKEND} -> 127.0.0.1:{PROXY_PORT}")
    server = ThreadingHTTPServer(("127.0.0.1", PROXY_PORT), ProxyHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
