#!/usr/bin/env python3
"""pt02: SQL injection login bypass on Juice Shop's /rest/user/login.

A crafted email ("' OR 1=1--") short-circuits the backend's WHERE clause
and authenticates as the first user row (the admin account) with no
valid password. Checks three things every run:

1. The attack: does the injection still authenticate as admin?
2. The ordinary legitimate case: does a normal email/password login
   still work?
3. A legitimate EDGE case: does an email that legitimately contains an
   apostrophe (a real character in RFC 5322 local-parts, e.g. a name
   like O'Brien) still work? This is reported honestly even when the
   answer is "no, and not because of anything we built" -- see README.

Standard library only (urllib). Refuses to run against anything but a
localhost target -- see ledger.guard_target_host.
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

DEFAULT_BLUEPRINT = Path(__file__).resolve().parent / "blueprints" / "pt02-001.json"


def _request(method: str, url: str, body: dict | None = None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def _try_json(text: str):
    try:
        return json.loads(text)
    except Exception:
        return None


def _jwt_payload(token: str) -> dict:
    """Decode (not verify -- this is read-only inspection of our own test
    traffic) the middle segment of a JWT to read its claims."""
    try:
        payload_b64 = token.split(".")[1]
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return {}


def run(target: str, vuln_id: str, mitre_technique: str, attack_payload: dict) -> dict:
    ledger.guard_target_host(target)
    stamp = str(time.time()).replace(".", "")

    # 1. The attack itself. The role claim lives inside the JWT's base64
    #    payload, not in the plaintext response body, so it has to be
    #    decoded, not string-matched.
    exploit_status, exploit_text = _request("POST", f"{target}/rest/user/login", body=attack_payload)
    exploit_body = _try_json(exploit_text) or {}
    exploit_token = exploit_body.get("authentication", {}).get("token", "")
    exploit_claims = _jwt_payload(exploit_token)
    exploit_role = exploit_claims.get("data", {}).get("role")

    if exploit_status in (400, 401, 403):
        status = "REMEDIATED"
        summary = f"Blocked with HTTP {exploit_status}."
    elif exploit_status == 200 and exploit_role == "admin":
        status = "VULNERABLE"
        summary = (
            f"Injection payload authenticated as admin ({exploit_claims.get('data', {}).get('email')}) "
            "with no valid password."
        )
    else:
        status = "ERROR"
        summary = f"Inconclusive: HTTP {exploit_status}, role={exploit_role!r}."

    # 2. Ordinary legitimate login must keep working in every condition.
    normal_email = f"pt02-legit-{stamp}@flatline.test"
    normal_password = "LegitPass123!"
    _request("POST", f"{target}/api/Users", body={
        "email": normal_email, "password": normal_password, "passwordRepeat": normal_password,
    })
    normal_status, normal_text = _request("POST", f"{target}/rest/user/login", body={
        "email": normal_email, "password": normal_password,
    })
    legitimate_normal_login_ok = normal_status == 200 and normal_email in normal_text

    # 3. The quoted-email edge case, reported as observed, not forced to
    #    pass or fail -- see README for why this matters.
    quoted_email = f"o'brien-{stamp}@flatline.test"
    quoted_password = "ObrienPass123!"
    reg_status, _ = _request("POST", f"{target}/api/Users", body={
        "email": quoted_email, "password": quoted_password, "passwordRepeat": quoted_password,
    })
    quoted_login_status, quoted_login_text = _request("POST", f"{target}/rest/user/login", body={
        "email": quoted_email, "password": quoted_password,
    })
    quoted_email_registered = reg_status == 201
    quoted_email_login_ok = quoted_login_status == 200 and quoted_email in quoted_login_text

    result = {
        "vulnerability_id": vuln_id,
        "mitre_technique": mitre_technique,
        "target": target,
        "status": status,
        "exploit_http_status": exploit_status,
        "summary": summary,
        "legitimate_normal_login_ok": legitimate_normal_login_ok,
        "legitimate_quoted_email_registered": quoted_email_registered,
        "legitimate_quoted_email_login_ok": quoted_email_login_ok,
        "legitimate_quoted_email_login_http_status": quoted_login_status,
    }
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--blueprint", default=str(DEFAULT_BLUEPRINT))
    parser.add_argument("--target", default=None, help="Overrides the blueprint's target.host, e.g. to point at the proxy instead.")
    args = parser.parse_args()

    blueprint = json.loads(Path(args.blueprint).read_text())
    target = args.target or blueprint["target"]["host"]

    result = run(target, blueprint["vulnerability_id"], blueprint["mitre_technique"], blueprint["attack_payload"])
    print(json.dumps(result, indent=2))

    results_dir = Path(__file__).resolve().parent / "results"
    results_dir.mkdir(exist_ok=True)
    out_path = results_dir / f"{result['vulnerability_id']}-{int(time.time())}.json"
    out_path.write_text(json.dumps(result, indent=2))

    ledger._append_log({"event": "replay_run", "item": "pt02-sqli-login-bypass", **result})

    if result["status"] == "ERROR":
        sys.exit(2)


if __name__ == "__main__":
    main()
