# pt28: Login Brute-Force With No Logging or Monitoring — OWASP Juice Shop

**Status: run live, 2026-11-04.** Closes the last gap in this repo's OWASP Top 10 2021 coverage, A09:2021 (Security Logging and Monitoring Failures).

## Target

Same container as the earlier items: `bkimminich/juice-shop:v17.3.0`, `http://localhost:3001`.

## Finding

Fifteen consecutive wrong-password attempts against one freshly registered test account, timed back to back, produced fifteen identical `HTTP 401 Invalid email or password.` responses. No slowdown between the first attempt and the fifteenth, no CAPTCHA requirement, no lockout message, nothing that looked any different from a single honest mistake. The very next request, using the correct password, logged in instantly, no delay, no extra verification step, no visible trace that fifteen wrong guesses had just happened against that account.

The login endpoint is the single most attacked surface in almost any web application, and this one has no logging, alerting, or defensive response to a sustained guessing attack against it at all.

## Classification

**CWE-778** (Insufficient Logging). **OWASP: A09:2021 - Security Logging and Monitoring Failures.** **MITRE ATT&CK: T1110.001** (Brute Force: Password Guessing).

## Corroboration against source

`routes/login.ts`'s handler:

```ts
models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, ...)
  .then((authenticatedUser) => {
    // ... on no match:
    res.status(401).send(res.__('Invalid email or password.'))
  })
```

A raw SQL lookup and a `401` on no match, nothing else: no counter, no delay, no lockout. A repo-wide check of `server.ts`, `app.ts`, and the reset-password flow (`routes/resetPassword.ts`, whose own challenge hint mentions "rate limiting" for the security-question-answer endpoint, see [pt26](../pt26-security-question-enumeration/)) turned up no rate-limiting or brute-force-detection middleware anywhere in this application. The one endpoint most worth watching has nothing watching it.

## What was run

```bash
python items/pt28-login-bruteforce-no-monitoring/scenario.py                               # pre-fix, direct to :3001
python items/pt28-login-bruteforce-no-monitoring/proxy.py                                  # separate shell, FLATLINE_ENFORCE=1 by default
python items/pt28-login-bruteforce-no-monitoring/scenario.py --target http://localhost:3029 # post-fix, through the proxy
```

## The fix

This item is specifically about the *absence* of logging and monitoring, so the compensating control adds exactly that: `proxy.py` tracks failed login attempts per account email, logs each one (the "monitoring" a real pipeline would feed into an alert), and once 5 accumulate against one account within a 60-second window, logs an `ALERT` line and blocks further attempts against that account with `429` before they ever reach the backend, the account-lockout response a real detection system would trigger. This is the one item in this repo where the fix deliberately also blocks the legitimate account owner once the threshold is crossed, that's what a real lockout does; the legitimate case this control protects is ordinary login traffic with no prior failures, which is never touched.

## Result

| Condition | Target | 15-attempt brute-force burst | Correct password after the burst | Fresh account, first-attempt login |
| --- | --- | --- | --- | --- |
| No control | `http://localhost:3001` (direct) | `VULNERABLE` — 15/15 answered, none blocked | Worked instantly | OK |
| Logging + lockout proxy | `http://localhost:3029` (proxy, enforcing) | `REMEDIATED` — 10/15 blocked after the 5th failure | Blocked (locked out) | OK |

Raw per-run output: `results/pt28-001-*.json`. `python ledger.py verify` from the repo root confirms both runs are in the hash-chained log untampered.

## Last uncovered OWASP category now covered

With this item, all ten OWASP Top 10 2021 categories (A01 through A10) have at least one item in this repo.

## What this does not show

- The lockout here is a simple in-memory per-account counter in a reverse proxy, not a real logging pipeline (no SIEM, no persistent audit trail, no human-facing alert); a production fix would integrate with actual log aggregation and alerting infrastructure, this demonstrates the detection-and-response behavior such a pipeline should produce, not the pipeline itself.
- A real attacker distributing the same attempts across many IP addresses or many accounts at once would need a different, broader detection strategy than this per-account counter.
- Same caveats as the earlier items: one vendor image, one run, no ticket-loop integration yet.
