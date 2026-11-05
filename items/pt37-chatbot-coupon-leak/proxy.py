#!/usr/bin/env python3
"""A minimal reverse-proxy compensating control for pt37.

The chatbot's 'queries.couponCode' intent has several canned refusal
answers and one that actually calls a function returning a real,
working discount coupon, with no authorization check or rate limit
of any kind. Repeating a coupon-related question enough times cycles
through to that answer. This proxy inspects every chatbot response
before it reaches the client: if it matches the coupon-issuing
pattern, it's replaced with one of the bot's own legitimate refusal
lines instead, so a real coupon is never handed out through this
channel at all. Every other chatbot response (name-setting, product
price lookups, ordinary conversation) passes through unchanged.

Toggle with FLATLINE_ENFORCE=0 to run the identical code path with the
substitution disabled.

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
PROXY_PORT = int(os.environ.get("FLATLINE_PROXY_PORT", "3038"))
ENFORCE = os.environ.get("FLATLINE_ENFORCE", "1") != "0"

ledger.guard_target_host(BACKEND)

COUPON_MARKER = "coupon code for you: "
SAFE_REFUSAL = "Sorry, I am not allowed to hand out coupon codes."


class ProxyHandler(BaseHTTPRequestHandler):
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

        if ENFORCE and self.path == "/rest/chatbot/respond" and status == 200:
            try:
                parsed = json.loads(resp_body)
                if COUPON_MARKER in parsed.get("body", ""):
                    parsed["body"] = SAFE_REFUSAL
                    resp_body = json.dumps(parsed).encode()
            except Exception:
                pass

        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp_body)))
        self.end_headers()
        self.wfile.write(resp_body)

    def log_message(self, fmt, *args):
        pass


def main() -> None:
    mode = "ENFORCING" if ENFORCE else "passthrough (no enforcement)"
    print(f"pt37 proxy: {mode}, {BACKEND} -> 127.0.0.1:{PROXY_PORT}")
    server = ThreadingHTTPServer(("127.0.0.1", PROXY_PORT), ProxyHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
