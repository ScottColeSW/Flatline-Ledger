# Preregistration: pt21-verbose-error-disclosure

**Status: run live, 2026-11-03. Prediction held exactly.**

## Prediction

- Expected result before any fix: `VULNERABLE` (an unhandled error renders as a raw stack trace)
- Expected result after the fix: `REMEDIATED`
- Expected cost to legitimate traffic: none, a normal login must keep succeeding.

## Result

- Pre-fix: `VULNERABLE`. Logging in with an email that legitimately contains an apostrophe (the same trigger pt02 found by accident) returned HTTP 500 with a full stack trace: `node_modules/sequelize/lib/dialects/sqlite/query.js:185:27`, internal file paths, the ORM, the database engine.
- Post-fix (through a leak-scrubbing proxy): `REMEDIATED`, same HTTP 500, no internal details in the body.
- Legitimate check: a normal login worked in both conditions.

## Formalizing an already-solved challenge, same reasoning as pt19/pt20

"Error Handling" was already `solved: true` on the scoreboard, triggered as a side effect of pt02's own apostrophe-email testing. This item gives it the same predict/verify/record treatment the deliberately-targeted items get, per the same request that produced pt19 and pt20.

Raw results in `results/pt21-001-*.json`; both runs are in the repo-root hash-chained log (`python ledger.py verify`).
