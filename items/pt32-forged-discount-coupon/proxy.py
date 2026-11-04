#!/usr/bin/env python3
"""A minimal reverse-proxy compensating control for pt32.

Every coupon the backend accepts is just z85.encode(MMMYY + '-' +
discount), a reversible, unkeyed, public encoding. Anyone can forge
one offline for any discount, for the current month, with no server
interaction. This proxy becomes the real issuing authority instead:
it exposes its own GET /rest/coupon/issue/{discount} that returns a
coupon HMAC-signed with a secret the backend never sees, and on
PUT .../coupon/{coupon} it verifies that signature itself before
reconstructing the backend's own native z85 coupon format and
forwarding that (never the attacker-supplied value) to the backend.
Anything that doesn't carry a valid signature, including a
perfectly well-formed z85 coupon forged the old way, is rejected
before the backend's decode step ever sees it.

Toggle with FLATLINE_ENFORCE=0 to run the identical code path with the
signature check disabled (coupons are forwarded as-is, the original
vulnerable behavior).

Standard library only.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
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
PROXY_PORT = int(os.environ.get("FLATLINE_PROXY_PORT", "3033"))
ENFORCE = os.environ.get("FLATLINE_ENFORCE", "1") != "0"

# A secret only this proxy knows, standing in for a real backend-office
# coupon-issuance secret the vendor never had in the first place.
SECRET = os.environ.get("FLATLINE_COUPON_SECRET", "flatline-pt32-demo-secret").encode()

Z85_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#"
MONTHS = ["JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"]

ledger.guard_target_host(BACKEND)


def _z85_encode(data: bytes) -> str:
    out = []
    for i in range(0, len(data), 4):
        value = int.from_bytes(data[i:i + 4], "big")
        chunk = []
        for _ in range(5):
            chunk.append(Z85_ALPHABET[value % 85])
            value //= 85
        out.append("".join(reversed(chunk)))
    return "".join(out)


def _current_mmmyy() -> str:
    now = datetime.datetime.now()
    return MONTHS[now.month - 1] + str(now.year)[2:4]


def _sign(discount: int, mmmyy: str) -> str:
    message = f"{mmmyy}-{discount}".encode()
    return hmac.new(SECRET, message, hashlib.sha256).hexdigest()[:16]


def _issue_signed_coupon(discount: int) -> str:
    mmmyy = _current_mmmyy()
    signature = _sign(discount, mmmyy)
    payload = f"{mmmyy}-{discount}-{signature}"
    return base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")


def _verify_and_translate(coupon: str) -> str | None:
    """Returns the backend's native z85 coupon if the signature is
    valid for the current month, else None."""
    try:
        padded = coupon + "=" * (-len(coupon) % 4)
        payload = base64.urlsafe_b64decode(padded).decode()
        mmmyy, discount_str, signature = payload.split("-")
        discount = int(discount_str)
    except Exception:
        return None

    if mmmyy != _current_mmmyy():
        return None
    if not hmac.compare_digest(signature, _sign(discount, mmmyy)):
        return None

    return _z85_encode(f"{mmmyy}-{discount}".encode())


class ProxyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/rest/coupon/issue/"):
            try:
                discount = int(self.path.rsplit("/", 1)[-1])
            except ValueError:
                discount = 0
            coupon = _issue_signed_coupon(discount)
            body = f'{{"coupon":"{coupon}"}}'.encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        self._forward("GET", None)

    def do_PUT(self):
        length = self.headers.get("Content-Length")
        body = self.rfile.read(int(length)) if length else b""

        if ENFORCE and "/coupon/" in self.path:
            prefix, _, raw_coupon = self.path.partition("/coupon/")
            supplied = urllib.parse.unquote(raw_coupon)
            translated = _verify_and_translate(supplied)
            if translated is None:
                resp_body = b'{"error":"Coupon signature invalid or expired."}'
                self.send_response(403)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp_body)))
                self.end_headers()
                self.wfile.write(resp_body)
                return
            self.path = prefix + "/coupon/" + urllib.parse.quote(translated, safe="")

        self._forward("PUT", body)

    def do_POST(self):
        length = self.headers.get("Content-Length")
        body = self.rfile.read(int(length)) if length else b""
        self._forward("POST", body)

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
    print(f"pt32 proxy: {mode}, {BACKEND} -> 127.0.0.1:{PROXY_PORT}")
    server = ThreadingHTTPServer(("127.0.0.1", PROXY_PORT), ProxyHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
