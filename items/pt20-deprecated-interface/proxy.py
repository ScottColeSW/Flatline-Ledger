#!/usr/bin/env python3
"""A minimal reverse-proxy compensating control for pt20.

The vendor's own "fix" for this B2B interface was to leave the route
live and have it respond 410 with a message, which still means real
parsing logic ran first. The actual fix the challenge's own name
implies is decommissioning: make the route behave as if it never
existed. The compensating control: inspect the uploaded filename's
extension and return a plain 404 for .xml/.yml/.yaml uploads before
the request ever reaches the backend's parser; anything else (the
still-supported .pdf attachment path) passes through untouched.

Toggle with FLATLINE_ENFORCE=0 to run the identical code path with the
check disabled.

Standard library only.
"""

from __future__ import annotations

import os
import re
import sys
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
import ledger  # noqa: E402

BACKEND = os.environ.get("FLATLINE_BACKEND", "http://localhost:3001")
PROXY_PORT = int(os.environ.get("FLATLINE_PROXY_PORT", "3021"))
ENFORCE = os.environ.get("FLATLINE_ENFORCE", "1") != "0"

ledger.guard_target_host(BACKEND)

DEPRECATED_EXTENSIONS = {"xml", "yml", "yaml"}
FILENAME_PATTERN = re.compile(rb'filename="([^"]+)"')


def _uploaded_extension(body: bytes) -> str | None:
    match = FILENAME_PATTERN.search(body)
    if not match:
        return None
    filename = match.group(1).decode(errors="replace")
    return filename.rsplit(".", 1)[-1].lower() if "." in filename else None


class ProxyHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = self.headers.get("Content-Length")
        body = self.rfile.read(int(length)) if length else b""

        if ENFORCE and self.path == "/file-upload" and _uploaded_extension(body) in DEPRECATED_EXTENSIONS:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
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
    print(f"pt20 proxy: {mode}, {BACKEND} -> 127.0.0.1:{PROXY_PORT}")
    server = ThreadingHTTPServer(("127.0.0.1", PROXY_PORT), ProxyHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
