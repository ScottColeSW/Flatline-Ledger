# pt21: Verbose Error Disclosure — OWASP Juice Shop

**Status: run live, 2026-11-03.** A third incidental scoreboard flip, formalized on the same request as pt19 and pt20.

## Target

Same container as the earlier items: `bkimminich/juice-shop:v17.3.0`, `http://localhost:3001`.

## Finding

Logging in with an email that legitimately contains an apostrophe (pt02's own accidental discovery) crashes `/rest/user/login`'s query construction and returns the crash directly as the HTTP response:

```
at Database.<anonymous> (/juice-shop/node_modules/sequelize/lib/dialects/sqlite/query.js:185:27)
```

Internal file paths, the ORM (Sequelize), the database engine (SQLite), exact line numbers, all in a `500` response body. This item measures the general hygiene gap, not the apostrophe-specific root cause, which belongs to pt02: whatever triggers an unhandled error, the response should never be a raw stack trace.

## Classification

**CWE-209** (Generation of Error Message Containing Sensitive Information). **OWASP: A05:2021 - Security Misconfiguration.** **MITRE ATT&CK: T1592.002** (Gather Victim Host Information: Software), the stack trace hands an attacker the exact library and database stack for free.

## What was run

```bash
python items/pt21-verbose-error-disclosure/scenario.py                               # pre-fix, direct to :3001
python items/pt21-verbose-error-disclosure/proxy.py                                  # separate shell, FLATLINE_ENFORCE=1 by default
python items/pt21-verbose-error-disclosure/scenario.py --target http://localhost:3022 # post-fix, through the proxy
```

## The fix: scrub the leak, keep the status code

`proxy.py` inspects every outbound response for the markers Juice Shop's own error template always includes (`node_modules`, the `stacktrace` block, `<file>.js:<line>` fragments) and replaces a leaking body with a generic error message, preserving the original status code so legitimate error semantics (404s, 401s) aren't disturbed.

## Result

| Condition | Target | Triggered error | Normal login |
| --- | --- | --- | --- |
| No control | `http://localhost:3001` (direct) | `VULNERABLE` — HTTP 500, full stack trace | OK |
| Leak-scrubbing proxy | `http://localhost:3022` (proxy, enforcing) | `REMEDIATED` — HTTP 500, no internal details | OK |

Raw per-run output: `results/pt21-001-*.json`. `python ledger.py verify` from the repo root confirms both runs are in the hash-chained log untampered.

## What this does not show

- Only this one trigger was tested; other unhandled errors elsewhere in the app may leak the same way and weren't individually checked.
- Same caveats as the earlier items: one vendor image, one run, no ticket-loop integration yet.
