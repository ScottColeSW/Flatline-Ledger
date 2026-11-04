#!/usr/bin/env python3
"""A minimal reverse-proxy compensating control for pt28.

POST /rest/user/login has no logging, alerting, or lockout of any
kind: repeated failed attempts against one account look identical to
normal traffic from the server's point of view. This proxy adds the
missing monitoring-and-response layer the backend never had: it
watches failed-login responses per account email, logs ("alerts" on)
a burst of them to stderr, and once a threshold is crossed within a
short window, blocks further attempts against that account before
they ever reach the backend, exactly the account-lockout response a
real logging/alerting pipeline would trigger. A successful login
clears the account's recorded failures.

Toggle with FLATLINE_ENFORCE=0 to run the identical code path with the
lockout disabled (attempts are still logged either way).

Standard library only.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
import ledger  # noqa: E402

BACKEND = os.environ.get("FLATLINE_BACKEND", "http://localhost:3001")
PROXY_PORT = int(os.environ.get("FLATLINE_PROXY_PORT", "3029"))
ENFORCE = os.environ.get("FLATLINE_ENFORCE", "1") != "0"

# At most MAX_FAILURES failed attempts against one account per
# WINDOW_SECONDS before further attempts against it are blocked.
# Generous enough that a real person who mistypes their password once
# or twice is never affected; tight enough that a sustained guess-and-
# check attack against one account gets cut off quickly.
MAX_FAILURES = 5
WINDOW_SECONDS = 60

ledger.guard_target_host(BACKEND)

_lock = threading.Lock()
_failures_by_email: dict[str, list[float]] = {}


def _recent_failures(email: str) -> int:
    now = time.monotonic()
    with _lock:
        recent = [t for t in _failures_by_email.get(email, []) if now - t < WINDOW_SECONDS]
        _failures_by_email[email] = recent
        return len(recent)


def _record_failure(email: str) -> None:
    with _lock:
        _failures_by_email.setdefault(email, []).append(time.monotonic())


def _clear_failures(email: str) -> None:
    with _lock:
        _failures_by_email.pop(email, None)


class ProxyHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = self.headers.get("Content-Length")
        body = self.rfile.read(int(length)) if length else b""

        if self.path == "/rest/user/login":
            self._handle_login(body)
            return

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

    def _handle_login(self, body: bytes) -> None:
        try:
            email = json.loads(body).get("email") if body else None
        except Exception:
            email = None

        if ENFORCE and email and _recent_failures(email) >= MAX_FAILURES:
            print(f"pt28 proxy: ALERT - account locked out, {MAX_FAILURES}+ failed attempts against {email} in the last {WINDOW_SECONDS}s", file=sys.stderr)
            resp_body = b'{"error":"Too many failed attempts, account temporarily locked."}'
            self.send_response(429)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp_body)))
            self.end_headers()
            self.wfile.write(resp_body)
            return

        req = urllib.request.Request(BACKEND + "/rest/user/login", data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                status, resp_body = resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            status, resp_body = exc.code, exc.read()

        if email:
            if status == 200:
                _clear_failures(email)
            elif status == 401:
                _record_failure(email)
                print(f"pt28 proxy: logged failed login attempt for {email} ({_recent_failures(email)}/{MAX_FAILURES} in window)", file=sys.stderr)

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

    def log_message(self, fmt, *args):
        pass


def main() -> None:
    mode = "ENFORCING" if ENFORCE else "passthrough (no enforcement)"
    print(f"pt28 proxy: {mode}, {BACKEND} -> 127.0.0.1:{PROXY_PORT}")
    server = ThreadingHTTPServer(("127.0.0.1", PROXY_PORT), ProxyHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
