# pt35: 2FA TOTP Verify Has No Brute-Force Protection — OWASP Juice Shop

**Status: run live, 2026-11-04.** Sixth item not in Juice Shop's own challenge catalog, found white-box.

## Target

Same container as the earlier items: `bkimminich/juice-shop:v17.3.0`, `http://localhost:3001`.

## Finding

`routes/2fa.ts`'s verify handler:

```ts
const isValid = otplib.authenticator.check(totpToken, user.totpSecret)
if (!isValid) {
  return res.status(401).send()
}
```

No rate limiting, no lockout, no logging of failed attempts anywhere around this check. A TOTP code is six digits, a 1,000,000-value space, with a `window: 1` tolerance that widens the set of currently-valid codes slightly. Once an attacker has a `tmpToken` (meaning they already know the account's password, step one of login), nothing stops an unlimited number of guesses against the second factor.

Confirmed live: fifteen random wrong six-digit codes against one real test account's 2FA all answered identically (`401`), with no slowdown or change in behavior, and the real code worked instantly on the next attempt, as if the preceding guesses never happened.

## Classification

**CWE-307** (Improper Restriction of Excessive Authentication Attempts). **OWASP: A07:2021 - Identification and Authentication Failures.** **MITRE ATT&CK: T1110.001** (Brute Force: Password Guessing).

## Why this one, found white-box

Read directly from `data/static/challenges.yml`: the catalog's only 2FA challenge, `twoFactorAuthUnsafeSecretStorageChallenge`, scores extracting a specific named account's (`wurstbrot`) TOTP secret through a separate data-exposure vulnerability, nothing about the verify endpoint's own resistance to brute force. `routes/2fa.ts` was pulled and read before a single guess was sent: the same missing-monitoring shape [pt28](../pt28-login-bruteforce-no-monitoring/) found on the primary login endpoint, now on the second factor that's specifically meant to survive a stolen password.

## Checked the scoreboard

`twoFactorAuthUnsafeSecretStorageChallenge` stayed unsolved, as expected, since this item targets the verify endpoint's lack of rate limiting on a self-controlled test account, not extracting a named NPC's secret through a different vulnerability. Sixth item now (after [pt24](../pt24-address-idor-on-update/), [pt25](../pt25-complaint-enumeration/), [pt26](../pt26-security-question-enumeration/), [pt28](../pt28-login-bruteforce-no-monitoring/), [pt31](../pt31-wallet-checkout-crash/)) found outside Juice Shop's own 109-item catalog.

## What was run

```bash
python items/pt35-2fa-totp-bruteforce/scenario.py                               # pre-fix, direct to :3001
python items/pt35-2fa-totp-bruteforce/proxy.py                                  # separate shell, FLATLINE_ENFORCE=1 by default
python items/pt35-2fa-totp-bruteforce/scenario.py --target http://localhost:3036 # post-fix, through the proxy
```

## The fix

Same shape as pt28's: `proxy.py` tracks failed 2FA attempts per `tmpToken` (the session already proves the caller knew the password; this is specifically about the second factor), logs each one, and once 5 accumulate in a 60-second window, locks that session out with `429` before the backend's `otplib` check ever runs. Like pt28, this is the one deliberate case where the fix also blocks a subsequent legitimate-looking attempt once the threshold trips, that's what a real lockout does; the case this control protects is a correct code on the first attempt, which is never touched.

## Result

| Condition | Target | 15-attempt brute-force burst | Real code after the burst | Fresh session, first-attempt 2FA |
| --- | --- | --- | --- | --- |
| No control | `http://localhost:3001` (direct) | `VULNERABLE` — 15/15 answered, none blocked | Worked instantly | OK |
| Lockout proxy | `http://localhost:3036` (proxy, enforcing) | `REMEDIATED` — 10/15 blocked after the 5th failure | Blocked (locked out) | OK |

Raw per-run output: `results/pt35-001-*.json`. `python ledger.py verify` from the repo root confirms both runs are in the hash-chained log untampered.

## What this does not show

- The TOTP code used in this item's setup and verification steps was generated with a from-scratch, stdlib-only implementation of RFC 6238, not a third-party library, correctness confirmed against the live server accepting it during 2FA setup before being relied on for the exploit.
- Same lockout-granularity caveat as pt28: a real attacker spreading attempts across many sessions at once would need a broader detection strategy than this per-session counter.
- Same caveats as the earlier items: one vendor image, one run, no ticket-loop integration yet.
