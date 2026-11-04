# Preregistration: pt28-login-bruteforce-no-monitoring

## Prediction

- Expected result before any fix: `VULNERABLE`. 15 consecutive wrong-password attempts against one freshly registered account all answer identically (HTTP 401), none blocked, and the correct password works immediately afterward with no delay or extra step.
- Expected result after the fix (a reverse proxy that logs failed attempts per account and blocks further ones once 5 accumulate in a 60-second window): `REMEDIATED`. Some of the 15 attempts come back HTTP 429 instead of 401, before ever reaching the backend.
- Expected cost to legitimate traffic: none. A different, freshly registered account logging in correctly on its very first attempt, no prior failures, succeeds immediately in both conditions.

## Why this one, found black-box

Fifteen wrong-password attempts in a row against a real test account, timed back to back, produced fifteen identical `401 Invalid email or password.` responses. No slowdown, no CAPTCHA requirement, no lockout message, nothing that looked different between attempt 1 and attempt 15. The very next request, with the correct password, logged in instantly, as if the preceding attack never happened.

## Corroboration against source

`routes/login.ts`'s handler is a raw SQL lookup (`SELECT * FROM Users WHERE email = '...' AND password = '...'`) with a plain `401` on no match, nothing else around it: no counter, no delay, no lockout. A repo-wide check of `server.ts`, `app.ts`, and the reset-password flow (`routes/resetPassword.ts`, whose own challenge hint mentions "rate limiting" for a different endpoint) turned up no rate-limiting or brute-force-detection middleware anywhere in this application. The single most attacked endpoint in any web app has no defensive logging or response of any kind.

## Result

**Status: run live, 2026-11-04. Prediction held exactly.**

- Pre-fix: `VULNERABLE`. All 15 wrong-password attempts against one test account answered `401`, none blocked, and the correct password worked immediately afterward.
- Post-fix (through a proxy logging failed attempts per account and locking out further ones after 5 in a 60s window): `REMEDIATED`. Attempts 1-5 answered `401` and were logged; attempts 6-15 answered `429` before reaching the backend at all, including the final attempt with the correct password, the account was locked out by the time it was tried, which is the intended behavior of a real lockout control, not a broken legitimate case.
- Legitimate check: a separate, freshly registered account with no prior failures logged in successfully on its very first attempt, in both conditions.

## Last uncovered OWASP category now covered

With this item, all ten OWASP Top 10 2021 categories have at least one item in this repo.

Raw results in `results/pt28-001-*.json`; both runs are in the repo-root hash-chained log (`python ledger.py verify`).
