#!/usr/bin/env python3
"""pt21: an unhandled error renders a full Node.js stack trace as the response.

Logging in with an email that legitimately contains an apostrophe (the
same trigger pt02 found by accident while testing a different thing)
crashes the backend's own query construction and returns the crash
as HTML: internal file paths, the ORM, the database engine, exact
line numbers. This item measures the general hygiene gap, not the
apostrophe-specific root cause pt02 already owns: whatever triggers an
unhandled error, the response should never be a raw stack trace.

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

DEFAULT_BLUEPRINT = Path(__file__).resolve().parent / "blueprints" / "pt21-001.json"
LEAK_MARKERS = ("node_modules", "stacktrace", ".js:")


def _request(method: str, url: str, body: dict | None = None) -> tuple[int, str]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if body is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode(errors="replace")


def run(target: str, blueprint: dict) -> dict:
    ledger.guard_target_host(target)
    stamp = str(int(time.time() * 1000))

    trigger_email = f"{blueprint['trigger_email_local_part']}-{stamp}@flatline.test"
    password = "Pt21Pass123!"
    _request("POST", f"{target}/api/Users", body={"email": trigger_email, "password": password, "passwordRepeat": password})

    exploit_status, exploit_body = _request("POST", f"{target}/rest/user/login", body={"email": trigger_email, "password": password})
    leaked_markers = [m for m in LEAK_MARKERS if m in exploit_body]

    if leaked_markers:
        status = "VULNERABLE"
        summary = f"HTTP {exploit_status} response leaked internal details: {leaked_markers}."
    elif exploit_status in (400, 401, 403, 500) and not leaked_markers:
        status = "REMEDIATED"
        summary = f"HTTP {exploit_status} with no file paths, library names, or stack trace content."
    else:
        status = "ERROR"
        summary = f"Inconclusive: HTTP {exploit_status}, leaked_markers={leaked_markers}."

    legit_email = f"pt21-legit-{stamp}@flatline.test"
    _request("POST", f"{target}/api/Users", body={"email": legit_email, "password": password, "passwordRepeat": password})
    legit_status, legit_body = _request("POST", f"{target}/rest/user/login", body={"email": legit_email, "password": password})
    legitimate_login_ok = legit_status == 200 and '"authentication"' in legit_body

    return {
        "vulnerability_id": blueprint["vulnerability_id"],
        "mitre_technique": blueprint["mitre_technique"],
        "target": target,
        "status": status,
        "exploit_http_status": exploit_status,
        "summary": summary,
        "legitimate_login_ok": legitimate_login_ok,
        "legitimate_login_http_status": legit_status,
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

    ledger._append_log({"event": "replay_run", "item": "pt21-verbose-error-disclosure", **result})

    if result["status"] == "ERROR":
        sys.exit(2)


if __name__ == "__main__":
    main()
