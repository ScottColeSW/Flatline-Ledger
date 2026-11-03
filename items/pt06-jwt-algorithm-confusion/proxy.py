#!/usr/bin/env python3
"""A minimal reverse-proxy compensating control for pt06.

Juice Shop always signs real tokens with RS256 (insecurity.js's
authorize() hardcodes it). The vendor-side fix is a one-line change
(pass {algorithms: ['RS256']} to jsonwebtoken.verify), but that's a
code change inside a vendored image, not something this repo patches.
The compensating control: reject any request carrying a `token` cookie
whose JWT header claims an algorithm other than RS256, before it ever
reaches the backend's unrestricted verify() call. A real login never
produces anything but RS256, so legitimate traffic is untouched.

Toggle with FLATLINE_ENFORCE=0 to run the identical code path with the
check disabled.

Standard library only.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import urllib.error
import urllib.request
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
import ledger  # noqa: E402

BACKEND = os.environ.get("FLATLINE_BACKEND", "http://localhost:3001")
PROXY_PORT = int(os.environ.get("FLATLINE_PROXY_PORT", "3008"))
ENFORCE = os.environ.get("FLATLINE_ENFORCE", "1") != "0"

ledger.guard_target_host(BACKEND)

ALLOWED_ALGORITHMS = {"RS256"}


def _token_algorithm(token: str) -> str | None:
    try:
        header_b64 = token.split(".")[0]
        padded = header_b64 + "=" * (-len(header_b64) % 4)
        header = json.loads(base64.urlsafe_b64decode(padded))
        return header.get("alg")
    except Exception:
        return None


class ProxyHandler(BaseHTTPRequestHandler):
    def _forward(self, method: str) -> None:
        length = self.headers.get("Content-Length")
        body = self.rfile.read(int(length)) if length else None

        if ENFORCE and self.headers.get("Cookie"):
            cookie = SimpleCookie()
            cookie.load(self.headers["Cookie"])
            token_morsel = cookie.get("token")
            if token_morsel:
                alg = _token_algorithm(token_morsel.value)
                if alg not in ALLOWED_ALGORITHMS:
                    blocked = json.dumps({
                        "status": "forbidden",
                        "message": f"pt06 compensating control: token algorithm '{alg}' is not on the allowlist",
                    }).encode()
                    self.send_response(401)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(blocked)))
                    self.end_headers()
                    self.wfile.write(blocked)
                    return

        req = urllib.request.Request(BACKEND + self.path, data=body, method=method)
        for header in ("Content-Type", "Cookie", "Authorization"):
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

    def do_GET(self):
        self._forward("GET")

    def do_POST(self):
        self._forward("POST")

    def log_message(self, fmt, *args):
        pass


def main() -> None:
    mode = "ENFORCING" if ENFORCE else "passthrough (no enforcement)"
    print(f"pt06 proxy: {mode}, {BACKEND} -> 127.0.0.1:{PROXY_PORT}")
    server = ThreadingHTTPServer(("127.0.0.1", PROXY_PORT), ProxyHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
