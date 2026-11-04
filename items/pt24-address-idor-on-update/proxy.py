#!/usr/bin/env python3
"""A minimal reverse-proxy compensating control for pt24.

PUT /api/Addresss/:id has no ownership check at all, while
GET /api/Addresss/:id on the same resource does (an explicit handler
in the vendor's own code). The compensating control reuses the
backend's own correct logic as an authorization oracle rather than
reimplementing it: before forwarding a PUT, it calls the backend's own
GET for that id using the caller's own credentials. If the backend
itself says the caller doesn't own it, the PUT never reaches the
backend at all.

Toggle with FLATLINE_ENFORCE=0 to run the identical code path with the
check disabled.

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
PROXY_PORT = int(os.environ.get("FLATLINE_PROXY_PORT", "3025"))
ENFORCE = os.environ.get("FLATLINE_ENFORCE", "1") != "0"

ledger.guard_target_host(BACKEND)

ADDRESS_PUT_PATH = re.compile(r"^/api/Addresss/(\d+)$")


def _backend_get(path: str, auth_header: str | None) -> int:
    req = urllib.request.Request(f"{BACKEND}{path}", method="GET")
    if auth_header:
        req.add_header("Authorization", auth_header)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code


class ProxyHandler(BaseHTTPRequestHandler):
    def do_PUT(self):
        length = self.headers.get("Content-Length")
        body = self.rfile.read(int(length)) if length else None

        match = ADDRESS_PUT_PATH.match(self.path)
        if ENFORCE and match:
            # Ask the backend's own GET, which already enforces ownership
            # correctly, whether this caller actually owns this address.
            owns_it = _backend_get(f"/api/Addresss/{match.group(1)}", self.headers.get("Authorization")) == 200
            if not owns_it:
                blocked = json.dumps({
                    "status": "forbidden",
                    "message": "pt24 compensating control: the backend's own GET says you don't own this address",
                }).encode()
                self.send_response(403)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(blocked)))
                self.end_headers()
                self.wfile.write(blocked)
                return

        req = urllib.request.Request(BACKEND + self.path, data=body, method="PUT")
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

    def do_GET(self):
        req = urllib.request.Request(BACKEND + self.path, method="GET")
        if self.headers.get("Authorization"):
            req.add_header("Authorization", self.headers["Authorization"])
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

    def do_POST(self):
        length = self.headers.get("Content-Length")
        body = self.rfile.read(int(length)) if length else None
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

    def log_message(self, fmt, *args):
        pass


def main() -> None:
    mode = "ENFORCING" if ENFORCE else "passthrough (no enforcement)"
    print(f"pt24 proxy: {mode}, {BACKEND} -> 127.0.0.1:{PROXY_PORT}")
    server = ThreadingHTTPServer(("127.0.0.1", PROXY_PORT), ProxyHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
