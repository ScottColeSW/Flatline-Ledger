#!/usr/bin/env python3
"""A minimal reverse-proxy compensating control for pt22.

likeProductReviews.js checks "already liked" against stale state, then
sleeps, then writes, a real check-then-act race window. The
compensating control doesn't (and can't, from outside) fix the
backend's own race; instead it closes the window at the edge, before
any request reaches the backend at all: a lock-guarded in-memory set
tracks (caller_email, review_id) pairs currently in flight or already
completed, and rejects any request for a pair that's already in either
set, so concurrent requests from one account for one review are
serialized before they ever race the backend's own sleep.

Toggle with FLATLINE_ENFORCE=0 to run the identical code path with the
check disabled.

Standard library only.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
import ledger  # noqa: E402

BACKEND = os.environ.get("FLATLINE_BACKEND", "http://localhost:3001")
PROXY_PORT = int(os.environ.get("FLATLINE_PROXY_PORT", "3023"))
ENFORCE = os.environ.get("FLATLINE_ENFORCE", "1") != "0"

ledger.guard_target_host(BACKEND)

_lock = threading.Lock()
_in_flight_or_done: set[tuple[str, str]] = set()


def _caller_email(auth_header: str | None) -> str | None:
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    token = auth_header[len("Bearer "):]
    try:
        payload_b64 = token.split(".")[1]
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded))
        return payload.get("data", {}).get("email")
    except Exception:
        return None


class ProxyHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = self.headers.get("Content-Length")
        body = self.rfile.read(int(length)) if length else b""

        key = None
        if ENFORCE and self.path == "/rest/products/reviews" and body:
            try:
                parsed = json.loads(body)
            except Exception:
                parsed = {}
            email = _caller_email(self.headers.get("Authorization"))
            review_id = parsed.get("id")
            if email and review_id:
                key = (email, review_id)
                with _lock:
                    if key in _in_flight_or_done:
                        blocked = json.dumps({
                            "status": "forbidden",
                            "message": "pt22 compensating control: a like for this account and review is already in flight or completed",
                        }).encode()
                        self.send_response(403)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(blocked)))
                        self.end_headers()
                        self.wfile.write(blocked)
                        return
                    _in_flight_or_done.add(key)

        req = urllib.request.Request(BACKEND + self.path, data=body, method="POST")
        for header in ("Content-Type", "Authorization"):
            if self.headers.get(header):
                req.add_header(header, self.headers[header])
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                status, resp_body = resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            status, resp_body = exc.code, exc.read()
            if key is not None and status != 200:
                # the backend itself refused (e.g. already liked before this
                # proxy ever ran); don't leave a false "in flight" entry
                with _lock:
                    _in_flight_or_done.discard(key)

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

    def do_PUT(self):
        length = self.headers.get("Content-Length")
        body = self.rfile.read(int(length)) if length else None
        req = urllib.request.Request(BACKEND + self.path, data=body, method="PUT")
        if self.headers.get("Content-Type"):
            req.add_header("Content-Type", self.headers["Content-Type"])
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

    def log_message(self, fmt, *args):
        pass


def main() -> None:
    mode = "ENFORCING" if ENFORCE else "passthrough (no enforcement)"
    print(f"pt22 proxy: {mode}, {BACKEND} -> 127.0.0.1:{PROXY_PORT}")
    server = ThreadingHTTPServer(("127.0.0.1", PROXY_PORT), ProxyHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
