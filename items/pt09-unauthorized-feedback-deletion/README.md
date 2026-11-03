# pt09: Unauthorized Feedback Deletion — OWASP Juice Shop

**Status: run live, 2026-11-03.** Found by reading an odd solve condition literally instead of assuming it meant something simpler.

## Target

Same container as the earlier items: `bkimminich/juice-shop:v17.3.0`, `http://localhost:3001`.

## How this was found

Juice Shop's own "Five-Star Feedback" challenge (difficulty 2, Broken Access Control) has a solve condition that reads oddly at first:

```js
function feedbackChallenge() {
    FeedbackModel.findAndCountAll({ where: { rating: 5 } }).then(({ count }) => {
        if (count === 0) { challengeUtils.solve(challenges.feedbackChallenge); }
    });
}
```

Solved when the count of 5-star feedback rows hits **zero**. The only way that number goes down is deletion, so the intended exploit isn't submitting a good review, it's deleting someone else's. Tested directly: a plain customer account calling `DELETE /api/Feedbacks/1` (the seeded admin-owned 5-star review) got HTTP 200, and the row was gone. The scoreboard flipped the moment a subsequent request passed through Juice Shop's global challenge-check middleware.

## Classification

**CWE-862** (Missing Authorization). **OWASP: A01:2021 - Broken Access Control.** **MITRE ATT&CK: T1485** (Data Destruction), the practical impact of letting anyone delete anyone else's data.

## What was run

```bash
python items/pt09-unauthorized-feedback-deletion/scenario.py                               # pre-fix, direct to :3001
python items/pt09-unauthorized-feedback-deletion/proxy.py                                  # separate shell, FLATLINE_ENFORCE=1 by default
python items/pt09-unauthorized-feedback-deletion/scenario.py --target http://localhost:3011 # post-fix, through the proxy
```

`scenario.py` doesn't depend on the one-time seeded data (which this investigation already deleted): it registers a fresh victim, submits a real 5-star feedback attributed to them, has an unrelated attacker account delete it, then separately confirms the victim can still delete a different feedback entry of their own.

Two real quirks cost debugging time along the way, documented in `PREREGISTRATION.md` rather than left to be rediscovered: the feedback form's captcha answer field is named `captcha`, not `captchaAnswer`, and `GET /rest/user/whoami` only ever reads the `token` cookie, never the `Authorization` header (a different quirk from the one pt01 found in the same cache).

## The fix: check ownership before deleting

`proxy.py` intercepts `DELETE /api/Feedbacks/{id}`, fetches the row first (same backend, same credentials), decodes the caller's own id from their JWT, and compares. A mismatch gets `403` with no delete attempted at all.

## Result

| Condition | Target | Unauthorized delete | Self-delete |
| --- | --- | --- | --- |
| No control | `http://localhost:3001` (direct) | `VULNERABLE` — HTTP 200, row gone | OK |
| Ownership-check proxy | `http://localhost:3011` (proxy, enforcing) | `REMEDIATED` — HTTP 403 | OK |

Raw per-run output: `results/pt09-001-*.json`. `python ledger.py verify` from the repo root confirms both runs are in the hash-chained log untampered.

## What this does not show

- Only `DELETE` was checked. Whether other write operations on `/api/Feedbacks` (or other models) have the same gap wasn't tested here.
- The captcha bypass used to submit feedback at all is a real, separate bug; this item doesn't measure or fix it, only uses it to reach the actual finding.
- Same caveats as the earlier items: one vendor image, one run, no ticket-loop integration yet.
