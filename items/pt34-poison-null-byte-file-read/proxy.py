#!/usr/bin/env python3
"""A minimal reverse-proxy compensating control for pt34.

GET /ftp/{file} checks the RAW requested filename for an allowed
extension (.md/.pdf) before truncating it at a poison null byte, so a
name like 'eastere.gg%2500.md' passes the check on the full string but
serves whatever is before the null byte instead. This proxy performs
the same truncation itself, first, and only allows the request through
if the TRUNCATED name is what actually ends in an allowed extension.

Toggle with FLATLINE_ENFORCE=0 to run the identical code path with the
check disabled (forwarded as-is, the original vulnerable order).

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
PROXY_PORT = int(os.environ.get("FLATLINE_PROXY_PORT", "3035"))
ENFORCE = os.environ.get("FLATLINE_ENFORCE", "1") != "0"

ledger.guard_target_host(BACKEND)

ALLOWED_EXTENSIONS = (".md", ".pdf")


def _truncated_name_is_allowed(raw_file: str) -> bool:
    truncated = raw_file.split("%00", 1)[0]
    return truncated.lower().endswith(ALLOWED_EXTENSIONS) or truncated == "incident-support.kdbx"


class ProxyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/ftp/"):
            raw_file = urllib.parse.unquote(self.path[len("/ftp/"):])
            if ENFORCE and not _truncated_name_is_allowed(raw_file):
                resp_body = b"Only .md and .pdf files are allowed!"
                self.send_response(403)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(resp_body)))
                self.end_headers()
                self.wfile.write(resp_body)
                return

        self._forward()

    def _forward(self) -> None:
        req = urllib.request.Request(BACKEND + self.path, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                status, resp_body = resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            status, resp_body = exc.code, exc.read()

        self.send_response(status)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(resp_body)))
        self.end_headers()
        self.wfile.write(resp_body)

    def log_message(self, fmt, *args):
        pass


def main() -> None:
    mode = "ENFORCING" if ENFORCE else "passthrough (no enforcement)"
    print(f"pt34 proxy: {mode}, {BACKEND} -> 127.0.0.1:{PROXY_PORT}")
    server = ThreadingHTTPServer(("127.0.0.1", PROXY_PORT), ProxyHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
