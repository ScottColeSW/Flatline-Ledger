#!/usr/bin/env python3
"""A minimal reverse-proxy compensating control for pt25.

GET /api/Complaints returns every account's complaints to anyone
logged in. Unlike every other item's fix in this repo, this one can't
lean on an ownership field the backend already has and merely fails to
check, because the backend never records who submitted a complaint at
all (every row comes back UserId: null regardless of who posted it).
The compensating control has to add the missing state itself: it
intercepts POST and remembers, in memory, which caller submitted which
exact message text, then filters the GET response down to only the
entries it recorded for that same caller.

This can only scope complaints submitted *through this proxy* while it
has been running; pre-existing data (like the one seeded complaint in
this container) has no recorded owner and is hidden from everyone
rather than guessed at or shown to all, see README for why that
limitation is stated rather than hidden.

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
PROXY_PORT = int(os.environ.get("FLATLINE_PROXY_PORT", "3026"))
ENFORCE = os.environ.get("FLATLINE_ENFORCE", "1") != "0"

ledger.guard_target_host(BACKEND)

_lock = threading.Lock()
_owner_by_message: dict[str, str] = {}


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

        if self.path == "/api/Complaints" and status == 201:
            email = _caller_email(self.headers.get("Authorization"))
            try:
                sent = json.loads(body)
                message = sent.get("message")
            except Exception:
                message = None
            if email and message:
                with _lock:
                    _owner_by_message[message] = email

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

        if ENFORCE and self.path == "/api/Complaints" and status == 200:
            email = _caller_email(self.headers.get("Authorization"))
            try:
                parsed = json.loads(resp_body)
                with _lock:
                    parsed["data"] = [c for c in parsed.get("data", []) if _owner_by_message.get(c.get("message")) == email]
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
    print(f"pt25 proxy: {mode}, {BACKEND} -> 127.0.0.1:{PROXY_PORT}")
    server = ThreadingHTTPServer(("127.0.0.1", PROXY_PORT), ProxyHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
