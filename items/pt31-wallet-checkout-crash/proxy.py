#!/usr/bin/env python3
"""A minimal reverse-proxy compensating control for pt31.

A checkout paid via wallet, when the balance is insufficient, crashes
the entire backend process: order.ts's PDF-stream 'finish' callback
and its own "Insufficient wallet balance" error handler both try to
send a response with no coordination, and whichever runs second
throws an uncaught exception that kills the whole Node process. This
proxy re-implements the same balance check the backend does, in front
of it, where a failure returns a clean error instead of crashing
anything: on a checkout whose paymentId is "wallet", it reads the
caller's own basket contents and wallet balance (using the caller's
own Authorization header, no privilege elevation involved) and
estimates the order total; if that estimate exceeds the wallet
balance, the checkout is rejected before it ever reaches the backend.
Every other checkout (any other paymentId, or wallet with enough
balance) passes through unchanged.

This is a best-effort estimate (price * quantity per basket item); it
does not replicate delivery fees or coupon discounts, so it is
deliberately conservative, a legitimate, sufficiently-funded checkout
is never blocked by this proxy for underestimating the total.

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

BACKEND = os.environ.get("FLATLINE_BACKEND", "http://localhost:3012")
PROXY_PORT = int(os.environ.get("FLATLINE_PROXY_PORT", "3032"))
ENFORCE = os.environ.get("FLATLINE_ENFORCE", "1") != "0"

ledger.guard_target_host(BACKEND)


def _backend_get(path: str, auth_header: str | None):
    req = urllib.request.Request(BACKEND + path, method="GET")
    if auth_header:
        req.add_header("Authorization", auth_header)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read())
        except Exception:
            return exc.code, {}
    except Exception:
        return None, {}


class ProxyHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = self.headers.get("Content-Length")
        body = self.rfile.read(int(length)) if length else b""

        if ENFORCE and self.path.startswith("/rest/basket/") and self.path.endswith("/checkout"):
            if self._would_overdraw_wallet(body):
                resp_body = b'{"error":"Insufficient wallet balance."}'
                self.send_response(402)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp_body)))
                self.end_headers()
                self.wfile.write(resp_body)
                return

        self._forward("POST", body)

    def do_PUT(self):
        length = self.headers.get("Content-Length")
        body = self.rfile.read(int(length)) if length else b""
        self._forward("PUT", body)

    def do_GET(self):
        self._forward("GET", None)

    def _would_overdraw_wallet(self, body: bytes) -> bool:
        try:
            parsed = json.loads(body) if body else {}
        except Exception:
            return False
        if parsed.get("orderDetails", {}).get("paymentId") != "wallet":
            return False

        auth_header = self.headers.get("Authorization")
        bid = self.path.split("/")[3]

        basket_status, basket_body = _backend_get(f"/rest/basket/{bid}", auth_header)
        if basket_status != 200:
            return False
        estimated_total = 0.0
        for product in basket_body.get("data", {}).get("Products", []):
            item = product.get("BasketItem", {})
            estimated_total += product.get("price", 0) * item.get("quantity", 0)

        balance_status, balance_body = _backend_get("/rest/wallet/balance", auth_header)
        if balance_status != 200:
            return False
        balance = balance_body.get("data", 0)

        return estimated_total > balance

    def _forward(self, method: str, body: bytes | None) -> None:
        req = urllib.request.Request(BACKEND + self.path, data=body, method=method)
        for header in ("Content-Type", "Authorization"):
            if self.headers.get(header):
                req.add_header(header, self.headers[header])
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
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
    print(f"pt31 proxy: {mode}, {BACKEND} -> 127.0.0.1:{PROXY_PORT}")
    server = ThreadingHTTPServer(("127.0.0.1", PROXY_PORT), ProxyHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
