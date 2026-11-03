# pt02: SQL Injection Login Bypass — OWASP Juice Shop

**Status: run live, 2026-11-03.**

## Target

Same container as [pt01](../pt01-idor-juice-shop/): `bkimminich/juice-shop:v17.3.0`, `http://localhost:3001`.

## Finding family

`POST /rest/user/login` builds its SQL query by string-concatenating the submitted email. `' OR 1=1--` as the email, with any password, short-circuits the `WHERE` clause and authenticates as the first row in the users table, the admin account, with no valid password at all.

## MITRE ATT&CK mapping

**T1190** (Exploit Public-Facing Application). OWASP category: **A03:2021 - Injection**.

## What was run

`scenario.py` checks three things every run, not just the exploit:

1. The attack: does `' OR 1=1--` still authenticate as `admin`? (Role is read from the JWT's own claims, not guessed from the plaintext response, since the plaintext body never names a role at all.)
2. An ordinary legitimate login (fresh random account, real password): must keep working everywhere.
3. A legitimate **edge case**: an email that legitimately contains an apostrophe (RFC 5322 allows it unquoted in the local part, e.g. a name like `O'Brien`). Reported as observed, not forced to a pass.

```bash
python items/pt02-sqli-login-bypass/scenario.py                               # pre-fix, direct to :3001
python items/pt02-sqli-login-bypass/proxy.py                                  # separate shell, FLATLINE_ENFORCE=1 by default
python items/pt02-sqli-login-bypass/scenario.py --target http://localhost:3003 # post-fix, through the proxy
```

## The fix: a naive input filter, on purpose

`proxy.py` rejects a login request outright if the email or password contains a single quote, `--`, `;`, or a block comment marker, then forwards everything else unchanged. This is deliberately the first filter most teams actually ship, not a sophisticated one, because the point of this item is partly to show what that naive version costs.

## Result

| Condition | Target | Exploit result | Ordinary legit login | Apostrophe-email legit login |
| --- | --- | --- | --- | --- |
| No control | `http://localhost:3001` (direct) | `VULNERABLE` — authenticated as `admin@juice-sh.op`, HTTP 200 | OK | **Already broken**: HTTP 500, a Sequelize/SQLite stack trace from the backend's own query |
| Compensating control | `http://localhost:3003` (proxy, enforcing) | `REMEDIATED` — HTTP 403 | OK | Still broken: HTTP 403, this time from our filter instead of the backend's crash |

Raw per-run output: [`results/pt02-001-1793733468.json`](results/pt02-001-1793733468.json) (vulnerable), [`results/pt02-001-1793733506.json`](results/pt02-001-1793733506.json) (remediated). `python ledger.py verify` from the repo root confirms both are in the hash-chained log untampered.

## What this does not show

- The apostrophe-email finding means this control cannot currently be scored as "free": it blocks the exploit, but it was never going to be the thing that fixes the backend's own pre-existing bug for that case, and a careful log diff is the only way the two 403/500 failures are distinguishable from "the proxy broke something that used to work."
- A less naive filter (e.g. detecting the injection pattern rather than any apostrophe) was not tried here; this item measures the common first-pass control, not the best possible one.
- Same caveats as pt01: one vendor image, one run, no adaptive attacker, no ticket-loop integration yet.
