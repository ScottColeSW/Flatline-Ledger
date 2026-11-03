#!/usr/bin/env python3
"""A minimal reverse-proxy compensating control for pt17.

POST /file-upload parses an uploaded .xml file with external entity
resolution enabled. The compensating control: scan the raw multipart
body for the DOCTYPE/ENTITY/SYSTEM signature an XXE payload needs and
reject the whole upload before it reaches the backend's vulnerable
parser at all. A benign XML file with no DOCTYPE passes through
untouched.

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
PROXY_PORT = int(os.environ.get("FLATLINE_PROXY_PORT", "3019"))
ENFORCE = os.environ.get("FLATLINE_ENFORCE", "1") != "0"

ledger.guard_target_host(BACKEND)

XXE_SIGNATURES = (b"<!DOCTYPE", b"<!ENTITY", b"SYSTEM")


def _looks_like_xxe(body: bytes) -> bool:
    return all(sig in body for sig in XXE_SIGNATURES)


class ProxyHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = self.headers.get("Content-Length")
        body = self.rfile.read(int(length)) if length else b""

        if ENFORCE and self.path == "/file-upload" and _looks_like_xxe(body):
            blocked = json.dumps({
                "status": "forbidden",
                "message": "pt17 compensating control: upload contains an external-entity DOCTYPE",
            }).encode()
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(blocked)))
            self.end_headers()
            self.wfile.write(blocked)
            return

        req = urllib.request.Request(BACKEND + self.path, data=body, method="POST")
        if self.headers.get("Content-Type"):
            req.add_header("Content-Type", self.headers["Content-Type"])
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                status, resp_body = resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            status, resp_body = exc.code, exc.read()

        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(resp_body)))
        self.end_headers()
        self.wfile.write(resp_body)

    def log_message(self, fmt, *args):
        pass


def main() -> None:
    mode = "ENFORCING" if ENFORCE else "passthrough (no enforcement)"
    print(f"pt17 proxy: {mode}, {BACKEND} -> 127.0.0.1:{PROXY_PORT}")
    server = ThreadingHTTPServer(("127.0.0.1", PROXY_PORT), ProxyHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
