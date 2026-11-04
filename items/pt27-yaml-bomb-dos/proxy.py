#!/usr/bin/env python3
"""A minimal reverse-proxy compensating control for pt27.

POST /file-upload runs any .yml/.yaml attachment through js-yaml's
yaml.load() under a 2-second server-side timeout. That timeout caps
the cost of one request but not how many a single caller can fire at
once; five billion-laughs uploads in parallel measurably stall
unrelated traffic on the same server. Rejecting .yml/.yaml entirely
isn't this proxy's call to make (that's a product decision, not a
security one), so instead it throttles by caller IP: a small number of
such uploads in a short window pass straight through unchanged,
further ones in that same window are refused with HTTP 429 before they
ever reach the backend parser. Every other upload (.pdf, .xml, .zip)
is untouched.

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
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
import ledger  # noqa: E402

BACKEND = os.environ.get("FLATLINE_BACKEND", "http://localhost:3001")
PROXY_PORT = int(os.environ.get("FLATLINE_PROXY_PORT", "3028"))
ENFORCE = os.environ.get("FLATLINE_ENFORCE", "1") != "0"

# At most MAX_YAML_UPLOADS .yml/.yaml uploads per caller IP per
# WINDOW_SECONDS. Generous enough that a one-off legitimate .yml
# complaint attachment is never affected; tight enough that a
# concurrent-bomb barrage from one caller gets cut off almost
# immediately.
MAX_YAML_UPLOADS = 1
WINDOW_SECONDS = 15

ledger.guard_target_host(BACKEND)

_lock = threading.Lock()
_upload_log: dict[str, list[float]] = {}


def _is_yaml_filename(filename: str) -> bool:
    lower = filename.lower()
    return lower.endswith(".yml") or lower.endswith(".yaml")


def _throttled_yaml_upload(client_ip: str) -> bool:
    now = time.monotonic()
    with _lock:
        recent = [t for t in _upload_log.get(client_ip, []) if now - t < WINDOW_SECONDS]
        recent.append(now)
        _upload_log[client_ip] = recent
        return len(recent) > MAX_YAML_UPLOADS


class ProxyHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = self.headers.get("Content-Length")
        body = self.rfile.read(int(length)) if length else b""

        if ENFORCE and self.path == "/file-upload" and self._is_yaml_bomb_candidate(body):
            if self._throttle_check():
                resp_body = b'{"error":"Too many YAML uploads, try again later."}'
                self.send_response(429)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp_body)))
                self.end_headers()
                self.wfile.write(resp_body)
                return

        req = urllib.request.Request(BACKEND + self.path, data=body, method="POST")
        for header in ("Content-Type", "Authorization"):
            if self.headers.get(header):
                req.add_header(header, self.headers[header])
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                status, resp_body = resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            status, resp_body = exc.code, exc.read()

        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp_body)))
        self.end_headers()
        self.wfile.write(resp_body)

    def _is_yaml_bomb_candidate(self, body: bytes) -> bool:
        content_type = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in content_type:
            return False
        # The multipart part header carries the uploaded filename; a plain
        # substring scan for a .yml/.yaml filename is enough to decide
        # whether this upload is the thing being throttled.
        lower = body.lower()
        return b'filename="' in lower and (b".yml\"" in lower or b".yaml\"" in lower)

    def _throttle_check(self) -> bool:
        return _throttled_yaml_upload(self.client_address[0])

    def log_message(self, fmt, *args):
        pass


def main() -> None:
    mode = "ENFORCING" if ENFORCE else "passthrough (no enforcement)"
    print(f"pt27 proxy: {mode}, {BACKEND} -> 127.0.0.1:{PROXY_PORT}")
    server = ThreadingHTTPServer(("127.0.0.1", PROXY_PORT), ProxyHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
