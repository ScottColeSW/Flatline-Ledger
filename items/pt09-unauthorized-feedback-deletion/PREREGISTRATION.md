# Preregistration: pt09-unauthorized-feedback-deletion

**Status: run live, 2026-11-03. Prediction held exactly, confirmed by the real scoreboard first.**

## Prediction

- Expected result before any fix: `VULNERABLE` (an unrelated account deletes another account's feedback)
- Expected result after the fix: `REMEDIATED`
- Expected cost to legitimate traffic: none, an account must still be able to delete its own feedback.

## Result

- Pre-fix: `VULNERABLE`. A freshly registered attacker account deleted a victim account's 5-star feedback by id, HTTP 200, confirmed gone afterward. Found by hand first: deleting the seeded `UserId: 1` 5-star feedback as a plain customer flipped Juice Shop's own "Five-Star Feedback" scoreboard entry, which only solves when the count of 5-star rows hits zero.
- Post-fix (through an ownership-check proxy): `REMEDIATED`, HTTP 403.
- Legitimate check: the victim account could still delete its own, separate feedback entry in both conditions.

## Working around real quirks in the live app, not the finding itself

Two unrelated behaviors cost debugging time and are worth recording so they don't get rediscovered:

- Submitting feedback at all needs a captcha, and its own "CAPTCHA Bypass" bug (the answer is returned in the same response as the question) is used here only to get past the form, it is not this item's finding.
- The feedback submission endpoint expects the answer field named `captcha`, not `captchaAnswer`.
- `GET /rest/user/whoami` only reads `req.cookies.token`, never the `Authorization` header, a different quirk from the `authenticatedUsers` cache-priming one pt01 documents. `scenario.py` avoids it entirely by decoding the JWT locally for anything that needs the caller's own id.

Raw results in `results/pt09-001-*.json`; both runs are in the repo-root hash-chained log (`python ledger.py verify`).
