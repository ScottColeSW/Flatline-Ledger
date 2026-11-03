#!/usr/bin/env python3
"""A minimal reverse-proxy compensating control for pt04.

Juice Shop's profile-image-by-URL feature will fetch literally anything
the caller names. The realistic fix without touching vendor code: an
allowlist of destination hosts the feature is permitted to fetch from
at all (the way a real deployment would allowlist a handful of known
image CDNs), default-deny everything else, including anything that
looks like an internal/loopback address.

ALLOWED_DESTINATIONS here has exactly one entry, matching this item's
blueprint's trusted_image_cdn_host. Toggle with FLATLINE_ENFORCE=0 to
run the identical code path with the allowlist check disabled.

Standard library only.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
import ledger  # noqa: E402

BACKEND = os.environ.get("FLATLINE_BACKEND", "http://localhost:3001")
PROXY_PORT = int(os.environ.get("FLATLINE_PROXY_PORT", "3007"))
ENFORCE = os.environ.get("FLATLINE_ENFORCE", "1") != "0"

ledger.guard_target_host(BACKEND)

ALLOWED_DESTINATIONS = {"host.docker.internal:3006"}


class ProxyHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = self.headers.get("Content-Length")
        body = self.rfile.read(int(length)) if length else b""

        if ENFORCE and self.path == "/profile/image/url":
            form = urllib.parse.parse_qs(body.decode())
            image_url = (form.get("imageUrl") or [""])[0]
            parsed = urllib.parse.urlparse(image_url)
            destination = f"{parsed.hostname}:{parsed.port}" if parsed.port else parsed.hostname
            if destination not in ALLOWED_DESTINATIONS:
                blocked = json.dumps({
                    "status": "forbidden",
                    "message": f"pt04 compensating control: destination '{destination}' is not on the image-CDN allowlist",
                }).encode()
                self.send_response(403)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(blocked)))
                self.end_headers()
                self.wfile.write(blocked)
                return

        self._forward("POST", body)

    def do_GET(self):
        self._forward("GET", None)

    def _forward(self, method: str, body: bytes | None) -> None:
        req = urllib.request.Request(BACKEND + self.path, data=body, method=method)
        if self.headers.get("Content-Type"):
            req.add_header("Content-Type", self.headers["Content-Type"])
        if self.headers.get("Cookie"):
            req.add_header("Cookie", self.headers["Cookie"])
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
    print(f"pt04 proxy: {mode}, {BACKEND} -> 127.0.0.1:{PROXY_PORT}")
    server = ThreadingHTTPServer(("127.0.0.1", PROXY_PORT), ProxyHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
