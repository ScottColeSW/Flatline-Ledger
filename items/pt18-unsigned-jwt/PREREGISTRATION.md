# Preregistration: pt18-unsigned-jwt

**Status: run live, 2026-11-03. Prediction held exactly, including the "no new code needed" claim.**

## Prediction

- Expected result before any fix: `VULNERABLE` (an unsigned `alg: none` token authenticates as admin)
- Expected result against pt06's existing proxy, with zero changes: `REMEDIATED`
- Expected cost to legitimate traffic: none, a real RS256-signed session must keep working.

## Result

- Pre-fix: `VULNERABLE`. A token with `alg: "none"` and an empty signature segment authenticated as `admin@juice-sh.op` via `GET /rest/user/whoami`, HTTP 200. Confirmed by hand first; also corroborated against Juice Shop's own "Unsigned JWT" scoreboard entry using the themed `jwtn3d@` email pattern its check wants.
- Against pt06's proxy, unmodified: `REMEDIATED`, HTTP 401. No new proxy was written for this item; pt06's `proxy.py` already pins to `RS256`, and `none` isn't `RS256`.
- Legitimate check: a real RS256-signed session from an actual login worked in both conditions.

## Why this is its own item and not folded into pt06

Same root cause (`jsonwebtoken.verify()` called with no `algorithms` restriction), but a genuinely different forged value (`none` vs `HS256`-with-public-key), and Juice Shop tracks them as two separate challenges with two separate solve conditions. Keeping them as separate items lets each one's result stand on its own, while still making the point explicit that one fix generalizes across both, the same relationship pt04-001 and pt04-002 have.

Raw results in `results/pt18-001-*.json`; both runs are in the repo-root hash-chained log (`python ledger.py verify`).
