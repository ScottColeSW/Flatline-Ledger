#!/usr/bin/env python3
"""A minimal reverse-proxy compensating control for pt39.

POST /api/BasketItems never checks whether the requested product is
soft-deleted (discontinued or safety-recalled), only whether there's
enough stock. The backend's own single-product read path
(GET /api/Products/:id) already gets this right: Sequelize's default
paranoid mode means that endpoint 404s for a soft-deleted product
without any extra code. This proxy reuses that existing, already-
correct endpoint as an authorization oracle, the same pattern pt24
uses for a different resource: before forwarding a basket-item add,
it calls the backend's own GET /api/Products/:id for the product in
question; if that doesn't come back 200, the add is rejected before
it ever reaches the basket.

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
PROXY_PORT = int(os.environ.get("FLATLINE_PROXY_PORT", "3040"))
ENFORCE = os.environ.get("FLATLINE_ENFORCE", "1") != "0"

ledger.guard_target_host(BACKEND)


def _product_is_listed(product_id) -> bool:
    try:
        req = urllib.request.Request(f"{BACKEND}/api/Products/{product_id}", method="GET")
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except urllib.error.HTTPError:
        return False
    except Exception:
        return False


class ProxyHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = self.headers.get("Content-Length")
        body = self.rfile.read(int(length)) if length else b""

        if ENFORCE and self.path == "/api/BasketItems":
            try:
                product_id = json.loads(body).get("ProductId") if body else None
            except Exception:
                product_id = None
            if product_id is not None and not _product_is_listed(product_id):
                resp_body = b'{"error":"Product is not available."}'
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp_body)))
                self.end_headers()
                self.wfile.write(resp_body)
                return

        self._forward("POST", body)

    def do_GET(self):
        self._forward("GET", None)

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
    print(f"pt39 proxy: {mode}, {BACKEND} -> 127.0.0.1:{PROXY_PORT}")
    server = ThreadingHTTPServer(("127.0.0.1", PROXY_PORT), ProxyHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
