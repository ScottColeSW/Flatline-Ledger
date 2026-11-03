#!/usr/bin/env python3
"""A minimal reverse-proxy compensating control for pt11.

POST /api/Feedbacks trusts a client-supplied UserId outright. The
compensating control: decode the caller's own id from their JWT and
overwrite (not just check) the UserId field in the request body before
forwarding, so the backend only ever sees the caller's real identity,
whatever the client claimed.

Toggle with FLATLINE_ENFORCE=0 to run the identical code path with the
check disabled.

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
PROXY_PORT = int(os.environ.get("FLATLINE_PROXY_PORT", "3013"))
ENFORCE = os.environ.get("FLATLINE_ENFORCE", "1") != "0"

ledger.guard_target_host(BACKEND)


def _caller_id(auth_header: str | None) -> int | None:
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
    def do_POST(self):
        length = self.headers.get("Content-Length")
        body = self.rfile.read(int(length)) if length else b""

        if ENFORCE and self.path == "/api/Feedbacks" and body:
            caller_id = _caller_id(self.headers.get("Authorization"))
            if caller_id is None:
                blocked = json.dumps({
                    "status": "forbidden",
                    "message": "pt11 compensating control: no valid caller identity for this feedback",
                }).encode()
                self.send_response(403)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(blocked)))
                self.end_headers()
                self.wfile.write(blocked)
                return
            try:
                parsed = json.loads(body)
            except Exception:
                parsed = {}
            parsed["UserId"] = caller_id  # overwrite, never trust the client's claim
            body = json.dumps(parsed).encode()

        req = urllib.request.Request(BACKEND + self.path, data=body, method="POST")
        if self.headers.get("Content-Type"):
            req.add_header("Content-Type", self.headers["Content-Type"])
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
    print(f"pt11 proxy: {mode}, {BACKEND} -> 127.0.0.1:{PROXY_PORT}")
    server = ThreadingHTTPServer(("127.0.0.1", PROXY_PORT), ProxyHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
