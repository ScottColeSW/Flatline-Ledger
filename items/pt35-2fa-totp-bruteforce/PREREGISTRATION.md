# Preregistration: pt35-2fa-totp-bruteforce

## Prediction

- Expected result before any fix: `VULNERABLE`. 15 random wrong-TOTP attempts against one account's 2FA verification all answer identically (401), none blocked, and the real code still works immediately afterward.
- Expected result after the fix (a reverse proxy locking a 2FA session out after 5 failures in a 60s window): `REMEDIATED`. Some of the 15 attempts come back 429 before reaching the backend.
- Expected cost to legitimate traffic: none. A correct code on the first attempt, no prior failures, still succeeds immediately.

## Why this one, found white-box

`data/static/challenges.yml`'s 2FA challenge only scores extracting a specific named account's (wurstbrot) TOTP secret through a separate data-exposure bug; it says nothing about the verify endpoint's own resistance to brute force. `routes/2fa.ts` was pulled and read before a single guess was sent: `otplib.authenticator.check(totpToken, user.totpSecret)` has no rate limiting, no lockout, no logging of failures anywhere around it, the same missing-monitoring shape [pt28](../pt28-login-bruteforce-no-monitoring/) found on the primary login endpoint.

## Result

**Status: run live, 2026-11-04. Prediction held exactly.**

- Pre-fix: `VULNERABLE`. All 15 random wrong-TOTP guesses against one account's 2FA answered `401`, none blocked, and the real code worked instantly afterward.
- Post-fix (through a proxy locking a 2FA session out after 5 failures in a 60s window): `REMEDIATED`. Attempts 1-5 answered `401`; attempts 6-15 answered `429`, including the final attempt with the real code, the session was locked out by then, the same intended trade-off [pt28](../pt28-login-bruteforce-no-monitoring/)'s fix makes.
- Legitimate check: a separate, freshly 2FA-enabled account's correct code on the very first attempt succeeded, in both conditions.

## Not in Juice Shop's own challenge catalog

Checked the scoreboard: `twoFactorAuthUnsafeSecretStorageChallenge` stayed unsolved, since it only flips for the specific named account `wurstbrot` via an unrelated data-exposure vector, not for demonstrating the verify endpoint's own lack of rate limiting. Sixth item now (after pt24, pt25, pt26, pt28, pt31) found outside Juice Shop's own 109-item catalog.

Raw results in `results/pt35-001-*.json`; both runs are in the repo-root hash-chained log (`python ledger.py verify`).
