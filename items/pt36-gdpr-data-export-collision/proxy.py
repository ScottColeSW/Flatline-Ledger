#!/usr/bin/env python3
"""A minimal reverse-proxy compensating control for pt36.

The GDPR data-export endpoint looks up order history by a
vowel-redacted email, which different real accounts can be made to
collide on, leaking one account's orders into another's export. The
backend has no safe endpoint to re-derive correct ownership (the
/rest/order-history endpoint uses the identical flawed lookup), so
this proxy adds the missing, non-colliding state itself: it watches
every successful checkout going through it and records
(orderId -> real caller email), keyed by a genuinely unique identity
(the JWT's own email claim, not the redacted lookup key the backend
uses). On a data-export request, it forwards to the backend as usual,
then filters the returned "orders" array down to only the ones its own
map confirms belong to the caller; anything not recorded as theirs is
dropped.

This can only protect orders placed *through this proxy* while it has
been running; pre-existing orders have no recorded true owner and are
hidden from everyone rather than guessed at or shown to all, the same
limitation and the same honest choice pt25's fix documents for a
different missing-state problem.

Toggle with FLATLINE_ENFORCE=0 to run the identical code path with the
filtering disabled.

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
PROXY_PORT = int(os.environ.get("FLATLINE_PROXY_PORT", "3037"))
ENFORCE = os.environ.get("FLATLINE_ENFORCE", "1") != "0"

ledger.guard_target_host(BACKEND)

_lock = threading.Lock()
_order_owner_by_id: dict[str, str] = {}


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

        req = urllib.request.Request(BACKEND + self.path, data=body, method="POST")
        for header in ("Content-Type", "Authorization"):
            if self.headers.get(header):
                req.add_header(header, self.headers[header])
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                status, resp_body = resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            status, resp_body = exc.code, exc.read()

        if self.path.startswith("/rest/basket/") and self.path.endswith("/checkout") and status == 200:
            email = _caller_email(self.headers.get("Authorization"))
            try:
                order_id = json.loads(resp_body).get("orderConfirmation")
            except Exception:
                order_id = None
            if email and order_id:
                with _lock:
                    _order_owner_by_id[order_id] = email

        if ENFORCE and self.path == "/rest/user/data-export" and status == 200:
            email = _caller_email(self.headers.get("Authorization"))
            try:
                parsed = json.loads(resp_body)
                user_data = json.loads(parsed["userData"])
                with _lock:
                    user_data["orders"] = [o for o in user_data.get("orders", []) if _order_owner_by_id.get(o.get("orderId")) == email]
                parsed["userData"] = json.dumps(user_data, indent=2)
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
    print(f"pt36 proxy: {mode}, {BACKEND} -> 127.0.0.1:{PROXY_PORT}")
    server = ThreadingHTTPServer(("127.0.0.1", PROXY_PORT), ProxyHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
