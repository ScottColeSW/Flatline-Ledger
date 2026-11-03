# pt11: Forged Feedback (Identity Spoofing) — OWASP Juice Shop

**Status: run live, 2026-11-03.** Built directly on pt09's feedback-submission machinery, same captcha quirks apply.

## Target

Same container as the earlier items: `bkimminich/juice-shop:v17.3.0`, `http://localhost:3001`.

## Finding

`POST /api/Feedbacks` accepts a client-supplied `UserId` field and saves it outright. Nothing checks it against the authenticated caller's own id. Confirmed in Juice Shop's own solve condition for "Forged Feedback" (`build/routes/verify.js`):

```js
challengeUtils.solveIf(challenges.forgedFeedbackChallenge, () => {
    const user = security.authenticatedUsers.from(req);
    return req.body?.UserId && req.body.UserId != user?.data?.id;
});
```

Any logged-in account can author feedback that appears to come from a different, real account, pt09 found the same endpoint had no ownership check on *deletion*; this is the matching gap on *creation*.

## Classification

**CWE-345** (Insufficient Verification of Data Authenticity). **OWASP: A04:2021 - Insecure Design**, trusting a client-supplied identity field is a design choice, not a single missing guard clause. **MITRE ATT&CK: T1565.001** (Stored Data Manipulation), primary; **T1036** (Masquerading), secondary, the practical effect is making content look like it came from someone else.

## What was run

```bash
python items/pt11-forged-feedback-identity-spoofing/scenario.py                               # pre-fix, direct to :3001
python items/pt11-forged-feedback-identity-spoofing/proxy.py                                  # separate shell, FLATLINE_ENFORCE=1 by default
python items/pt11-forged-feedback-identity-spoofing/scenario.py --target http://localhost:3013 # post-fix, through the proxy
```

Same captcha quirks pt09 documented apply here (the answer field is named `captcha`, not `captchaAnswer`); `scenario.py` reuses that pattern directly. It also primes the attacker's token into Juice Shop's `authenticatedUsers` cache first (the same quirk pt01 and pt09 found), since this challenge's own solve check depends on it to know the caller's real id.

## The fix: correct the claim, don't just reject it

`proxy.py` decodes the caller's own id from their JWT and **overwrites** the `UserId` field in the request body before forwarding, rather than rejecting the request outright. The request still succeeds; it just can no longer claim to be anyone but its actual author. This changes what "remediated" looks like: the response is still `HTTP 201`, not a `4xx`, so `scenario.py` had to check the created row's actual `UserId`, not just the status code, to tell the fix apart from a no-op. See `PREREGISTRATION.md` for why that distinction mattered.

## Result

| Condition | Target | Forged attribution | Self attribution |
| --- | --- | --- | --- |
| No control | `http://localhost:3001` (direct) | `VULNERABLE` — row saved under the victim's real id | OK |
| Identity-pinning proxy | `http://localhost:3013` (proxy, enforcing) | `REMEDIATED` — row saved under the attacker's own real id, same HTTP 201 | OK |

Raw per-run output: `results/pt11-001-*.json`. `python ledger.py verify` from the repo root confirms both runs are in the hash-chained log untampered.

## What this does not show

- Other Sequelize-backed models likely accept the same kind of client-supplied foreign key unchecked; only `Feedbacks` was tested here.
- The fix silently corrects rather than audits; a real deployment might also want to log the mismatch as a signal, which this item doesn't do.
- Same caveats as the earlier items: one vendor image, one run, no ticket-loop integration yet.
