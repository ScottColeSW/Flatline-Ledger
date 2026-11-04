# Preregistration: pt35-2fa-totp-bruteforce

## Prediction

- Expected result before any fix: `VULNERABLE`. 15 random wrong-TOTP attempts against one account's 2FA verification all answer identically (401), none blocked, and the real code still works immediately afterward.
- Expected result after the fix (a reverse proxy locking a 2FA session out after 5 failures in a 60s window): `REMEDIATED`. Some of the 15 attempts come back 429 before reaching the backend.
- Expected cost to legitimate traffic: none. A correct code on the first attempt, no prior failures, still succeeds immediately.

## Why this one, found white-box

`data/static/challenges.yml`'s 2FA challenge only scores extracting a specific named account's (wurstbrot) TOTP secret through a separate data-exposure bug; it says nothing about the verify endpoint's own resistance to brute force. `routes/2fa.ts` was pulled and read before a single guess was sent: `otplib.authenticator.check(totpToken, user.totpSecret)` has no rate limiting, no lockout, no logging of failures anywhere around it, the same missing-monitoring shape [pt28](../pt28-login-bruteforce-no-monitoring/) found on the primary login endpoint.

## Result

(Filled in after the live run.)
