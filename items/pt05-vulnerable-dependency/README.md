# pt05: Vulnerable Dependency (`jsonwebtoken@0.4.0`) — OWASP Juice Shop

**Status: run live, 2026-11-03.**

## This item is SCA, not DAST, and that changes its shape

pt01 through pt04 all follow the same arc: replay an exploit against the running app, confirm impact directly (a leaked basket, an admin token, a callback hit), apply a compensating control, replay again. This item doesn't, on purpose. "This dependency has a known CVE" and "this app is demonstrably exploitable through it" are different claims, and this item only measures the first one. Forcing it into the same replay-and-prove-impact shape as the others would overclaim something this item never checked: whether the app's actual authentication path runs through this exact `jsonwebtoken` instance, or a different JWT library entirely (both are plausible; Juice Shop's own login responses are RS256-signed, and this repo hasn't traced which code path produces them). What follows is accordingly a detection, not an exploitation.

## Target

Same container as the earlier items: `bkimminich/juice-shop:v17.3.0`. Unlike pt01-04, this item doesn't send any requests to port 3001 at all; it inspects the container's own files.

## Finding

`docker cp`'d straight out of the running container (not assumed from `package.json`'s version ranges): `package-lock.json` pins `jsonwebtoken` at `0.4.0`, an abandoned release. Checked against [osv.dev](https://osv.dev), a public, read-only vulnerability database:

| Advisory | CVE | Severity | Summary |
| --- | --- | --- | --- |
| GHSA-c7hr-j4mj-j2w6 | CVE-2015-9235 | **CRITICAL** | Verification bypass in jsonwebtoken |
| GHSA-8cf7-32gw-wr33 | CVE-2022-23539 | HIGH | Unrestricted key type could lead to legacy key usage |
| GHSA-hjrf-2m68-5959 | CVE-2022-23541 | MODERATE | Insecure key-retrieval function, RSA-to-HMAC forgery |
| GHSA-qwph-4952-7xr6 | CVE-2022-23540 | MODERATE | Signature validation bypass via insecure default algorithm |

A wider scan of all 69 direct dependencies (resolved to exact installed versions via `package-lock.json`, queried in one batch) found 17 with at least one known advisory. Only `jsonwebtoken` is tracked in detail here; the full hit list is in the raw results.

## Classification

**CWE-1104** (Use of Unmaintained Third-Party Components). **OWASP category: A06:2021 - Vulnerable and Outdated Components.** No MITRE ATT&CK technique is assigned: ATT&CK doesn't have a clean technique for "a known-vulnerable dependency is present," as distinct from a demonstrated exploitation path through it, and picking one anyway (`T1190`, say) would read as a stronger claim than this item actually checked.

## What was run

```bash
python items/pt05-vulnerable-dependency/scenario.py --mode current        # what's actually installed
python items/pt05-vulnerable-dependency/scenario.py --mode proposed-fix   # is the suggested upgrade target clean
```

`--mode proposed-fix` checks `jsonwebtoken@9.0.3` (the current published version on the npm registry) against osv.dev. It does **not** install that version into the running container; this repo doesn't fork and rebuild Juice Shop's own source. It validates the remediation target, not a remediation that was actually applied.

## Why there's no legitimate-traffic-cost measurement here

Every other item in this repo pairs "did the fix work" with "did it break something real" (a basket read, a login, a public document). A dependency bump's real-world cost is compatibility risk, whether the upgrade breaks the app that depends on it, and measuring that honestly would mean actually forking Juice Shop, bumping the dependency, and running its own test suite, which is out of scope for this item. Stating a cost figure without doing that work would be a guess dressed up as a measurement, so this item reports none rather than inventing one.

## Result

| Mode | Package checked | Result |
| --- | --- | --- |
| `current` | `jsonwebtoken@0.4.0` (as installed) | `VULNERABLE`, 4 known advisories |
| `proposed-fix` | `jsonwebtoken@9.0.3` (current npm release) | `REMEDIATED`, 0 known advisories |

Raw per-run output: `results/pt05-001-*.json`. `python ledger.py verify` from the repo root confirms both runs are in the hash-chained log untampered.

## What this does not show

- No exploitation path from these advisories through the running app was demonstrated or attempted. This item is a detection, not a pentest finding in the sense pt01-04 are.
- Only the direct dependencies were scanned (69 packages), not the full transitive tree in `package-lock.json`, which is far larger.
- The one outbound network call this repo makes to a non-local host: querying osv.dev with package name + exact version. Read-only, no credentials, no exploit payload, the same thing `npm audit`/`pip-audit`/`osv-scanner` do as routine practice. Documented here rather than left for a reader to notice on their own.
