#!/usr/bin/env python3
"""A minimal reverse-proxy compensating control for pt13.

POST /profile changes the logged-in user's username, authenticated
purely by the "token" cookie, with no anti-CSRF token and no actual
Origin check. The compensating control: reject the request unless its
Origin header matches this proxy's own address, the same thing an
Origin-checking CSRF defense would do at the application layer.

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
PROXY_PORT = int(os.environ.get("FLATLINE_PROXY_PORT", "3015"))
ENFORCE = os.environ.get("FLATLINE_ENFORCE", "1") != "0"
SELF_ORIGIN = f"http://localhost:{PROXY_PORT}"

ledger.guard_target_host(BACKEND)


class _NoRedirect(urllib.request.HTTPErrorProcessor):
    def http_response(self, request, response):
        return response  # the 302 + its Set-Cookie must reach the client as-is

    https_response = http_response


_backend_opener = urllib.request.build_opener(_NoRedirect)


class ProxyHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = self.headers.get("Content-Length")
        body = self.rfile.read(int(length)) if length else b""

        if ENFORCE and self.path == "/profile":
            origin = self.headers.get("Origin", "")
            if origin != SELF_ORIGIN:
                blocked = json.dumps({
                    "status": "forbidden",
                    "message": f"pt13 compensating control: Origin '{origin}' does not match this app's own address",
                }).encode()
                self.send_response(403)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(blocked)))
                self.end_headers()
                self.wfile.write(blocked)
                return

        req = urllib.request.Request(BACKEND + self.path, data=body, method="POST")
        for header in ("Content-Type", "Cookie"):
            if self.headers.get(header):
                req.add_header(header, self.headers[header])
        try:
            with _backend_opener.open(req, timeout=10) as resp:
                status, resp_body = resp.status, resp.read()
                set_cookie = resp.headers.get("Set-Cookie")
        except urllib.error.HTTPError as exc:
            status, resp_body = exc.code, exc.read()
            set_cookie = exc.headers.get("Set-Cookie") if exc.headers else None

        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(resp_body)))
        if set_cookie:
            self.send_header("Set-Cookie", set_cookie)
        self.end_headers()
        self.wfile.write(resp_body)

    def log_message(self, fmt, *args):
        pass


def main() -> None:
    mode = "ENFORCING" if ENFORCE else "passthrough (no enforcement)"
    print(f"pt13 proxy: {mode}, {BACKEND} -> 127.0.0.1:{PROXY_PORT} (self origin: {SELF_ORIGIN})")
    server = ThreadingHTTPServer(("127.0.0.1", PROXY_PORT), ProxyHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
