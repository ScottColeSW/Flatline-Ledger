# pt07: Weak Default Admin Credentials — OWASP Juice Shop

**Status: run live, 2026-11-03.**

## Target

Same container as the earlier items: `bkimminich/juice-shop:v17.3.0`, `http://localhost:3001`.

## Finding

Unlike every item before this, there's no injection, no forgery, no SSRF, no misconfiguration to discover, just a weak credential. The real admin account, `admin@juice-sh.op`, logs in with the password `admin123`. Confirmed in `build/routes/login.js`'s own solve condition for the "Password Strength" challenge:

```js
challengeUtils.solveIf(challenges.weakPasswordChallenge, () => {
    return req.body.email === 'admin@' + config.get('application.domain') && req.body.password === 'admin123';
});
```

That's not a narrow, themed solve path like pt04's self-referential SSRF check or pt06's `rsa_lord@` email requirement, it's a direct literal match on the actual login attempt. The scoreboard flipped on the first try.

## Classification

**CWE-521** (Weak Password Requirements). **OWASP: A07:2021 - Identification and Authentication Failures.** **MITRE ATT&CK: T1078.001** (Valid Accounts: Default Accounts), this is exactly that: a default, weak credential on a real, privileged account, not a technique that bypasses authentication, one that walks through the front door.

## What was run

```bash
python items/pt07-weak-default-credentials/scenario.py                               # pre-fix, direct to :3001
python items/pt07-weak-default-credentials/proxy.py                                  # separate shell, FLATLINE_ENFORCE=1 by default
python items/pt07-weak-default-credentials/scenario.py --target http://localhost:3009 # post-fix, through the proxy
```

## The fix: a password blocklist, since the account can't be rotated from here

The real fix is rotating the admin account's password, a database change this repo has no path to make against a vendored image's running state. The realistic compensating control, and genuinely what NIST 800-63B recommends regardless: reject known-weak or breached passwords at login time. `proxy.py` blocks any login attempt whose password is on a small blocklist (`admin123` included) before it reaches the backend at all. A real deployment would check against something like HaveIBeenPwned's Pwned Passwords list; this uses the blueprint's own small list instead, so the control's behavior stays fully offline and reproducible.

## Result

| Condition | Target | Weak-credential login | Legitimate login |
| --- | --- | --- | --- |
| No control | `http://localhost:3001` (direct) | `VULNERABLE` — HTTP 200, real admin session | OK |
| Password blocklist | `http://localhost:3009` (proxy, enforcing) | `REMEDIATED` — HTTP 401 | OK |

Raw per-run output: `results/pt07-001-*.json`. `python ledger.py verify` from the repo root confirms both runs are in the hash-chained log untampered.

## What this does not show

- A blocklist of five passwords is a toy stand-in for a real breached-password check; a genuine deployment needs the real thing, not this list.
- The admin account's password itself is never actually rotated by this item, the control sits in front of it, it doesn't fix it.
- Same caveats as the earlier items: one vendor image, one run, no ticket-loop integration yet.
