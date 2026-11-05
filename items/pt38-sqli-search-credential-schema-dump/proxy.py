#!/usr/bin/env python3
"""A minimal reverse-proxy compensating control for pt38.

GET /rest/products/search builds its SQL query with raw string
interpolation on the q parameter, no parameterization at all. A real
fix belongs in the backend (bind q as a parameter instead of
concatenating it into the query string); short of patching the
vendored image, this proxy rejects any search query containing the
SQL keywords that make this specific exploitation technique (UNION-
based injection) possible, before the request ever reaches the
backend. Ordinary search terms, including ones a real customer might
plausibly type, are never affected: 'union' or 'select' alone, not
paired with the other, do not trip it, and real product names/
descriptions don't contain this keyword pairing.

Toggle with FLATLINE_ENFORCE=0 to run the identical code path with the
check disabled.

Standard library only.
"""

from __future__ import annotations

import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
import ledger  # noqa: E402

BACKEND = os.environ.get("FLATLINE_BACKEND", "http://localhost:3001")
PROXY_PORT = int(os.environ.get("FLATLINE_PROXY_PORT", "3039"))
ENFORCE = os.environ.get("FLATLINE_ENFORCE", "1") != "0"

ledger.guard_target_host(BACKEND)

UNION_SELECT_PATTERN = re.compile(r"union\s+select", re.IGNORECASE)


class ProxyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/rest/products/search"):
            query = urllib.parse.urlparse(self.path).query
            params = urllib.parse.parse_qs(query)
            q = params.get("q", [""])[0]

            if ENFORCE and UNION_SELECT_PATTERN.search(q):
                resp_body = b'{"error":"Invalid search query."}'
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp_body)))
                self.end_headers()
                self.wfile.write(resp_body)
                return

        self._forward()

    def do_POST(self):
        length = self.headers.get("Content-Length")
        body = self.rfile.read(int(length)) if length else b""
        req = urllib.request.Request(BACKEND + self.path, data=body, method="POST")
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

    def _forward(self) -> None:
        req = urllib.request.Request(BACKEND + self.path, method="GET")
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
    print(f"pt38 proxy: {mode}, {BACKEND} -> 127.0.0.1:{PROXY_PORT}")
    server = ThreadingHTTPServer(("127.0.0.1", PROXY_PORT), ProxyHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
