#!/usr/bin/env python3
"""A minimal reverse-proxy compensating control for pt33.

GET /redirect?to=X is allowed through if X merely *contains* one of a
handful of trusted URLs anywhere in it (lib/insecurity.ts's
url.includes(allowedUrl)), not if X actually starts at a trusted
origin. This proxy re-checks the same allowlist itself, correctly:
X must start with one of the allowlisted URLs, not just contain one
somewhere in its path or query string. Anything that fails that
stricter check is rejected before the backend's own (permissive)
check ever runs.

Toggle with FLATLINE_ENFORCE=0 to run the identical code path with the
stricter check disabled (the backend's own permissive check is used
instead, the original vulnerable behavior).

Standard library only.
"""

from __future__ import annotations

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
PROXY_PORT = int(os.environ.get("FLATLINE_PROXY_PORT", "3034"))
ENFORCE = os.environ.get("FLATLINE_ENFORCE", "1") != "0"

ledger.guard_target_host(BACKEND)

REDIRECT_ALLOWLIST = [
    "https://github.com/juice-shop/juice-shop",
    "https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm",
    "https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW",
    "https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6",
    "http://shop.spreadshirt.com/juiceshop",
    "http://shop.spreadshirt.de/juiceshop",
    "https://www.stickeryou.com/products/owasp-juice-shop/794",
    "http://leanpub.com/juice-shop",
]


def _actually_allowed(url: str) -> bool:
    return any(url.startswith(allowed) for allowed in REDIRECT_ALLOWLIST)


class _NoRedirect(urllib.request.HTTPErrorProcessor):
    """urlopen auto-follows 3xx redirects by default, which would
    silently discard the Location header this proxy needs to inspect
    and relay; this makes it return the redirect response unchanged
    instead (same pattern pt13 and pt26 use for the same reason)."""

    def http_response(self, request, response):
        return response

    https_response = http_response


_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirect)


class ProxyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/redirect?"):
            query = urllib.parse.urlparse(self.path).query
            params = urllib.parse.parse_qs(query)
            to_url = params.get("to", [None])[0]

            if ENFORCE and (to_url is None or not _actually_allowed(to_url)):
                resp_body = f'Unrecognized target URL for redirect: {to_url}'.encode()
                self.send_response(406)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(resp_body)))
                self.end_headers()
                self.wfile.write(resp_body)
                return

        self._forward()

    def _forward(self) -> None:
        req = urllib.request.Request(BACKEND + self.path, method="GET")
        try:
            with _NO_REDIRECT_OPENER.open(req, timeout=10) as resp:
                status, resp_body, location = resp.status, resp.read(), resp.headers.get("Location")
        except urllib.error.HTTPError as exc:
            status, resp_body, location = exc.code, exc.read(), exc.headers.get("Location")

        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(resp_body)))
        if location:
            self.send_header("Location", location)
        self.end_headers()
        self.wfile.write(resp_body)

    def log_message(self, fmt, *args):
        pass


def main() -> None:
    mode = "ENFORCING" if ENFORCE else "passthrough (no enforcement)"
    print(f"pt33 proxy: {mode}, {BACKEND} -> 127.0.0.1:{PROXY_PORT}")
    server = ThreadingHTTPServer(("127.0.0.1", PROXY_PORT), ProxyHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
