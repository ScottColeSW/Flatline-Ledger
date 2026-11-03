# pt03: Exposed `/ftp/` Directory — OWASP Juice Shop

**Status: run live, 2026-11-03.** Prediction held exactly, including the legitimate-traffic check.

## Target

Same container as [pt01](../pt01-idor-juice-shop/) and [pt02](../pt02-sqli-login-bypass/): `bkimminich/juice-shop:v17.3.0`, `http://localhost:3001`.

## Finding family

`/ftp/` is a legacy file-drop path with directory listing (`serve-index`) left on, and no authentication required for the listing or for most of the files in it, no account, no token, nothing. The listing itself names:

```
acquisitions.md             <- explicitly says "This document is confidential! Do not distribute!"
announcement_encrypted.md
coupons_2013.md.bak         <- blocked by Juice Shop's own filename denylist (403)
eastere.gg
encrypt.pyc                 <- blocked by Juice Shop's own filename denylist (403)
incident-support.kdbx       <- a KeePass password database
legal.md                    <- no confidential marker, reads like a genuine public terms doc
package.json.bak            <- blocked by Juice Shop's own filename denylist (403)
suspicious_errors.yml       <- blocked by Juice Shop's own filename denylist (403)
```

Worth being precise about: four of those filenames are already blocked, but by Juice Shop's own hardcoded filename denylist (its anti-cheat logic for a specific built-in challenge), not by any real access control. Renaming any of those four would defeat that denylist instantly; it isn't a security boundary, it's challenge-completion bookkeeping. `acquisitions.md` and `incident-support.kdbx`, the two checked here, aren't on that denylist and are fully downloadable.

## MITRE ATT&CK mapping

**T1083** (File and Directory Discovery) for the listing itself; **T1552.001** (Unsecured Credentials: Credentials In Files) for the `.kdbx` exposure specifically. OWASP category: **A05:2021 - Security Misconfiguration**.

## What was run

`scenario.py` checks three exposure indicators and one legitimate-traffic case, all with zero `Authorization` header:

```bash
python items/pt03-exposed-ftp-directory/scenario.py                               # pre-fix, direct to :3001
python items/pt03-exposed-ftp-directory/proxy.py                                  # separate shell, FLATLINE_ENFORCE=1 by default
python items/pt03-exposed-ftp-directory/scenario.py --target http://localhost:3004 # post-fix, through the proxy
```

## The fix: default-deny, not a blanket block

`proxy.py` blocks every request under `/ftp/` except an explicit one-entry allowlist: `legal.md`. That file was checked, not assumed, before going on the allowlist, it carries no "confidential" marker and reads like an ordinary public terms document, unlike `acquisitions.md`. A fix that blocked `/ftp/` wholesale would have been simpler to write and would have scored identically on the vulnerability itself, but it would have taken a plausible public document down with it. This item's legitimate-traffic check exists specifically to catch that.

## Result

| Condition | Target | Listing | Confidential file | Credential file | `legal.md` |
| --- | --- | --- | --- | --- | --- |
| No control | `http://localhost:3001` (direct) | 200, listable | 200, downloadable | 200, downloadable (3246 bytes) | 200 |
| Default-deny + allowlist | `http://localhost:3004` (proxy, enforcing) | 403 | 403 | 403 | 200 |

Raw per-run output: `results/pt03-001-*.json`. `python ledger.py verify` from the repo root confirms both runs are in the hash-chained log untampered.

## What this does not show

- Only two files were checked for exposure (one confidential doc, one credential store) out of a longer listing; the other files weren't individually verified as sensitive or benign beyond what the denylist already blocks.
- The allowlist approach doesn't scale past a handful of known-public files; a real fix would turn directory listing off entirely and serve only files an application route explicitly names, which is a backend change, not a proxy-level compensating control.
- Same caveats as pt01/pt02: one vendor image, one run, no ticket-loop integration yet.
