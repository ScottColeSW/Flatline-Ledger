#!/usr/bin/env python3
"""A minimal reverse-proxy compensating control for pt14.

The vendor's own addBasketItem has a parser differential: its
ownership check and its actual insert read different occurrences of a
duplicated "BasketId" key. The compensating control here doesn't try
to replicate that parser or guess which occurrence is "real"; it
rejects any POST /api/BasketItems body that names the same top-level
key more than once at all, the HTTP Parameter Pollution itself, not
just this one consequence of it.

This is a flat-JSON-specific check (a regex over top-level `"key":`
occurrences), not a general nested-JSON duplicate-key detector; see
README for that limitation stated plainly.

Toggle with FLATLINE_ENFORCE=0 to run the identical code path with the
check disabled.

Standard library only.
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
import ledger  # noqa: E402

BACKEND = os.environ.get("FLATLINE_BACKEND", "http://localhost:3001")
PROXY_PORT = int(os.environ.get("FLATLINE_PROXY_PORT", "3016"))
ENFORCE = os.environ.get("FLATLINE_ENFORCE", "1") != "0"

ledger.guard_target_host(BACKEND)

TOP_LEVEL_KEY = re.compile(r'"(\w+)"\s*:')


def _has_duplicate_top_level_key(raw_body: bytes) -> bool:
    try:
        text = raw_body.decode()
    except Exception:
        return False
    keys = TOP_LEVEL_KEY.findall(text)
    counts = Counter(keys)
    return any(n > 1 for n in counts.values())


class ProxyHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = self.headers.get("Content-Length")
        body = self.rfile.read(int(length)) if length else b""

        if ENFORCE and self.path == "/api/BasketItems" and _has_duplicate_top_level_key(body):
            blocked = json.dumps({
                "status": "forbidden",
                "message": "pt14 compensating control: duplicate key in request body (HTTP Parameter Pollution)",
            }).encode()
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(blocked)))
            self.end_headers()
            self.wfile.write(blocked)
            return

        req = urllib.request.Request(BACKEND + self.path, data=body, method="POST")
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
    print(f"pt14 proxy: {mode}, {BACKEND} -> 127.0.0.1:{PROXY_PORT}")
    server = ThreadingHTTPServer(("127.0.0.1", PROXY_PORT), ProxyHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
