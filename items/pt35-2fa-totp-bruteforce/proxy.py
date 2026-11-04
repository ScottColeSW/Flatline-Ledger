#!/usr/bin/env python3
"""A minimal reverse-proxy compensating control for pt35.

POST /rest/2fa/verify has no rate limiting, lockout, or logging of
failed attempts around its otplib.authenticator.check(...) call,
the same missing-monitoring shape pt28 found on the primary login
endpoint. This proxy adds that missing layer itself: it tracks failed
2FA attempts per tmpToken (the session already proves the caller knew
the account's password; this is specifically about brute-forcing the
second factor) and, once 5 accumulate within a 60-second window,
blocks further attempts against that session with 429 before they
ever reach the backend's otplib check.

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
PROXY_PORT = int(os.environ.get("FLATLINE_PROXY_PORT", "3036"))
ENFORCE = os.environ.get("FLATLINE_ENFORCE", "1") != "0"

MAX_FAILURES = 5
WINDOW_SECONDS = 60

ledger.guard_target_host(BACKEND)

_lock = threading.Lock()
_failures_by_session: dict[str, list[float]] = {}


def _recent_failures(session_key: str) -> int:
    now = time.monotonic()
    with _lock:
        recent = [t for t in _failures_by_session.get(session_key, []) if now - t < WINDOW_SECONDS]
        _failures_by_session[session_key] = recent
        return len(recent)


def _record_failure(session_key: str) -> None:
    with _lock:
        _failures_by_session.setdefault(session_key, []).append(time.monotonic())


def _clear_failures(session_key: str) -> None:
    with _lock:
        _failures_by_session.pop(session_key, None)


class ProxyHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = self.headers.get("Content-Length")
        body = self.rfile.read(int(length)) if length else b""

        if self.path == "/rest/2fa/verify":
            self._handle_verify(body)
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

    def _handle_verify(self, body: bytes) -> None:
        try:
            session_key = json.loads(body).get("tmpToken") if body else None
        except Exception:
            session_key = None

        if ENFORCE and session_key and _recent_failures(session_key) >= MAX_FAILURES:
            print(f"pt35 proxy: ALERT - 2FA session locked out, {MAX_FAILURES}+ failed attempts in the last {WINDOW_SECONDS}s", file=sys.stderr)
            resp_body = b'{"error":"Too many failed 2FA attempts, try again later."}'
            self.send_response(429)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp_body)))
            self.end_headers()
            self.wfile.write(resp_body)
            return

        req = urllib.request.Request(BACKEND + "/rest/2fa/verify", data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                status, resp_body = resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            status, resp_body = exc.code, exc.read()

        if session_key:
            if status == 200:
                _clear_failures(session_key)
            elif status == 401:
                _record_failure(session_key)
                print(f"pt35 proxy: logged failed 2FA attempt ({_recent_failures(session_key)}/{MAX_FAILURES} in window)", file=sys.stderr)

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
    print(f"pt35 proxy: {mode}, {BACKEND} -> 127.0.0.1:{PROXY_PORT}")
    server = ThreadingHTTPServer(("127.0.0.1", PROXY_PORT), ProxyHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
