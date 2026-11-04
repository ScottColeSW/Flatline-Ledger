#!/usr/bin/env python3
"""A minimal reverse-proxy compensating control for pt26.

GET /rest/user/security-question has no rate limiting of any kind: it
is an unauthenticated oracle that answers as fast as it is asked,
letting anyone enumerate registered accounts and harvest their
security questions at whatever rate they choose. The real
forgot-password flow has to stay unauthenticated (that is the whole
point of the feature, recovering an account you cannot log into), so
this cannot be fixed by rejecting unauthenticated calls. Instead this
throttles by caller IP: a small number of requests in a short window
pass straight through unchanged, further requests in that same window
get HTTP 429 instead of an answer.

Toggle with FLATLINE_ENFORCE=0 to run the identical code path with the
throttling disabled.

Standard library only.
"""

from __future__ import annotations

import os
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
import ledger  # noqa: E402

BACKEND = os.environ.get("FLATLINE_BACKEND", "http://localhost:3001")
PROXY_PORT = int(os.environ.get("FLATLINE_PROXY_PORT", "3027"))
ENFORCE = os.environ.get("FLATLINE_ENFORCE", "1") != "0"

# A fixed window: at most MAX_REQUESTS calls to the oracle per caller IP
# per WINDOW_SECONDS. Generous enough that a real person checking their
# own forgotten email once is never affected; tight enough that a burst
# scan across many emails gets cut off quickly.
MAX_REQUESTS = 3
WINDOW_SECONDS = 10

ledger.guard_target_host(BACKEND)

_lock = threading.Lock()
_request_log: dict[str, list[float]] = {}


def _throttled(client_ip: str) -> bool:
    now = time.monotonic()
    with _lock:
        recent = [t for t in _request_log.get(client_ip, []) if now - t < WINDOW_SECONDS]
        recent.append(now)
        _request_log[client_ip] = recent
        return len(recent) > MAX_REQUESTS


class ProxyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if ENFORCE and self.path.startswith("/rest/user/security-question") and self._throttle_check():
            body = b'{"error":"Too many requests, try again later."}'
            self.send_response(429)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

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

    def _throttle_check(self) -> bool:
        return _throttled(self.client_address[0])

    def log_message(self, fmt, *args):
        pass


def main() -> None:
    mode = "ENFORCING" if ENFORCE else "passthrough (no enforcement)"
    print(f"pt26 proxy: {mode}, {BACKEND} -> 127.0.0.1:{PROXY_PORT}")
    server = ThreadingHTTPServer(("127.0.0.1", PROXY_PORT), ProxyHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
