#!/usr/bin/env python3
"""A minimal reverse-proxy compensating control for pt01.

Juice Shop's own backend has no server-side ownership check on
GET /rest/basket/{id}: any authenticated user's token can read any
basket by id. Since this is a vendored lab image, not our own source,
the "fix" takes the form every team eventually ships against code they
can't touch: an output-filtering control in front of it.

This proxy forwards every request to the real backend unchanged, except
for GET /rest/basket/{id}: it decodes the caller's JWT (no signature
check needed, the payload is unencrypted; this is a lab, not a trust
boundary of its own) to get the caller's user id, and if the response
body's UserId doesn't match the caller, it replaces the response with
403 instead of forwarding the leaked body.

Toggle with FLATLINE_ENFORCE=0 to run the "before fix" condition through
the same code path, so pre/post differ only in one flag, not two
different processes doing unrelated things.

Standard library only.
"""

from __future__ import annotations

import base64
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
PROXY_PORT = int(os.environ.get("FLATLINE_PROXY_PORT", "3002"))
ENFORCE = os.environ.get("FLATLINE_ENFORCE", "1") != "0"

ledger.guard_target_host(BACKEND)


def _caller_id_from_bearer(auth_header: str | None) -> int | None:
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    token = auth_header[len("Bearer "):]
    try:
        payload_b64 = token.split(".")[1]
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded))
        return payload.get("data", {}).get("id")
    except Exception:
        return None


class ProxyHandler(BaseHTTPRequestHandler):
    def _forward(self, method: str) -> None:
        body = None
        length = self.headers.get("Content-Length")
        if length:
            body = self.rfile.read(int(length))

        req = urllib.request.Request(BACKEND + self.path, data=body, method=method)
        for header in ("Content-Type", "Authorization"):
            if self.headers.get(header):
                req.add_header(header, self.headers[header])

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                status, resp_body = resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            status, resp_body = exc.code, exc.read()

        if ENFORCE and method == "GET" and self.path.startswith("/rest/basket/") and status == 200:
            caller_id = _caller_id_from_bearer(self.headers.get("Authorization"))
            try:
                parsed = json.loads(resp_body)
                owner_id = parsed.get("data", {}).get("UserId")
            except Exception:
                owner_id = None
            if caller_id is not None and owner_id is not None and caller_id != owner_id:
                blocked = json.dumps({
                    "status": "forbidden",
                    "message": "pt01 compensating control: basket owner mismatch",
                }).encode()
                self.send_response(403)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(blocked)))
                self.end_headers()
                self.wfile.write(blocked)
                return

        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp_body)))
        self.end_headers()
        self.wfile.write(resp_body)

    def do_GET(self):
        self._forward("GET")

    def do_POST(self):
        self._forward("POST")

    def log_message(self, fmt, *args):
        pass  # keep test output quiet; nothing here is a secret worth hiding, just noise


def main() -> None:
    mode = "ENFORCING" if ENFORCE else "passthrough (no enforcement)"
    print(f"pt01 proxy: {mode}, {BACKEND} -> 127.0.0.1:{PROXY_PORT}")
    server = ThreadingHTTPServer(("127.0.0.1", PROXY_PORT), ProxyHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
