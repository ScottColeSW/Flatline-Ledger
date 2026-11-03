#!/usr/bin/env python3
"""A minimal reverse-proxy compensating control for pt15.

upgradeToDeluxe only validates payment when paymentMode is exactly
"wallet" or "card"; anything else, including a missing field, skips
both payment branches and still upgrades the account. The
compensating control: reject the request outright unless paymentMode
is one of those two known-good values, a default-deny the vendor's
own code never wrote.

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
PROXY_PORT = int(os.environ.get("FLATLINE_PROXY_PORT", "3017"))
ENFORCE = os.environ.get("FLATLINE_ENFORCE", "1") != "0"

ledger.guard_target_host(BACKEND)

ALLOWED_PAYMENT_MODES = {"wallet", "card"}


class ProxyHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = self.headers.get("Content-Length")
        body = self.rfile.read(int(length)) if length else b""

        if ENFORCE and self.path == "/rest/deluxe-membership":
            try:
                parsed = json.loads(body) if body else {}
            except Exception:
                parsed = {}
            if parsed.get("paymentMode") not in ALLOWED_PAYMENT_MODES:
                blocked = json.dumps({
                    "status": "forbidden",
                    "message": "pt15 compensating control: paymentMode must be 'wallet' or 'card'",
                }).encode()
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(blocked)))
                self.end_headers()
                self.wfile.write(blocked)
                return

        self._forward("POST", body)

    def do_GET(self):
        self._forward("GET", None)

    def do_PUT(self):
        length = self.headers.get("Content-Length")
        body = self.rfile.read(int(length)) if length else None
        self._forward("PUT", body)

    def _forward(self, method: str, body: bytes | None) -> None:
        req = urllib.request.Request(BACKEND + self.path, data=body, method=method)
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
    print(f"pt15 proxy: {mode}, {BACKEND} -> 127.0.0.1:{PROXY_PORT}")
    server = ThreadingHTTPServer(("127.0.0.1", PROXY_PORT), ProxyHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
