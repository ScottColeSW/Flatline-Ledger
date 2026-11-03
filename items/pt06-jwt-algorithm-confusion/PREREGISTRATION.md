# Preregistration: pt06-jwt-algorithm-confusion

**Status: run live, 2026-11-03. Prediction held exactly.**

## Prediction

- Expected result before any fix: `VULNERABLE` (a forged HS256 token, signed with the RS256 public key, authenticates as admin with no login)
- Expected result after the fix: `REMEDIATED`
- Expected cost to legitimate traffic: none, a real RS256-signed session from an actual login must keep working in every condition.

## Result

- Pre-fix: `VULNERABLE`. `GET /rest/user/whoami` with a forged HS256 token returned HTTP 200 and `admin@juice-sh.op`, with zero prior login. Confirmed by hand first (the server set the forged token back as a valid session cookie), then reproduced automatically.
- Post-fix (through an algorithm-pinning proxy): `REMEDIATED`, HTTP 401.
- Legitimate check: a real, RS256-signed session from an actual registration/login worked in both conditions.

## Why this isn't a theoretical pairing with pt05

pt05's SCA scan found `jsonwebtoken@0.4.0` (CVE-2015-9235, among others) and `express-jwt@0.1.3` present in the dependency tree, but explicitly declined to claim the running app's real authentication path uses either of them; detection isn't exploitation. This item traced the actual code (`build/lib/insecurity.js`'s `updateAuthenticatedUsers`) and found `jsonwebtoken.verify(token, publicKey, callback)` called with no `algorithms` restriction, exactly the vulnerable pattern those advisories describe, then confirmed it live. The two items together are a complete loop: pt05 found the vulnerable library class was present, pt06 confirmed the app's real behavior is exploitable through it.

Raw results in `results/pt06-001-*.json`; both runs are in the repo-root hash-chained log (`python ledger.py verify`).
