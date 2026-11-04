# Preregistration: pt23-forged-unauthenticated-review

**Status: run live, 2026-11-04. Prediction held exactly, confirmed on the real scoreboard.**

## Prediction

- Expected result before any fix: `VULNERABLE` (a review posts with no auth at all under a fabricated identity)
- Expected result after the fix: `REMEDIATED`
- Expected cost to legitimate traffic: none, a real authenticated review must keep working.

## Result

- Pre-fix: `VULNERABLE`. `PUT /rest/products/1/reviews` with no `Authorization` header at all, and `author` set to `totally-fake@nobody.test`, a string that doesn't correspond to any real account, returned HTTP 201 and persisted exactly as submitted.
- Post-fix (through an auth-and-identity-pinning proxy): `REMEDIATED`, HTTP 401.
- Legitimate check: a real, authenticated review under the correct account worked in both conditions.

## Found while working on pt22, flagged by Scott, formalized here

The scoreboard's "Forged Review" entry flipped on its own while pt22's review-creation probing was underway (that probe omitted an `author` field entirely, which was enough to satisfy Juice Shop's own mismatch check). Investigating why turned up something more severe than the author-forgery angle alone: the route has no authorization middleware at all, unlike its PATCH and POST siblings on the same model. This item measures the fuller finding, not just the narrower one that happened to flip the scoreboard first.

Raw results in `results/pt23-001-*.json`; both runs are in the repo-root hash-chained log (`python ledger.py verify`).
