# Flatline Ledger

A predict-then-verify range for classic penetration testing and purple team work, scored the way [Agent Defense Theater](https://github.com/ScottColeSW/Agent-Defense-Theater) scores agentic risk: every control gets two numbers together, the exploits it stops and the legitimate work it still allows. Targets are intentionally-vulnerable local lab applications, never a live client environment.

In current analyst terms, this is a **CTEM** (Continuous Threat Exposure Management) program's **AEV** (Adversarial Exposure Validation) layer: the category that replaced "breach and attack simulation" and "automated pen testing" as separate labels. Flatline Ledger builds that layer for classic AppSec findings (injection, access control, supply chain) the same way its siblings build it for agent behavior.

## Why it exists

Most pen testing deliverables are a report and a handshake: here are the findings, good luck. The remediation gap, whether a patch actually closed what was found, almost never gets re-measured, and the few tools that do re-check tend to treat "exploit payload" and "live client target" as if they belong in the same sentence. They don't. This range keeps the measurement discipline from the agentic-risk repos (predict first, score paired, log hash-chained, report misses) and applies it to lab targets that are safe to actually attack.

## Scope, stated once

- **Lab targets only.** Juice Shop, DVWA, WebGoat, and similar intentionally-vulnerable apps, run locally in containers you control. Nothing here is built to point at a URL you don't own. The one exception: an SCA item (pt05) queries a public, read-only vulnerability database (osv.dev) with a package name and version, no exploit traffic, the same kind of lookup `npm audit` makes as routine practice. Documented at the item that does it, not buried.
- **No live credentials, no production tickets.** The Jira/GitHub-Issues loop runs against a sandbox project or this repo's own issue tracker, never a real tenant with real bearer tokens.
- **Evidence, not an audit.** A finding here is a measured result against one lab target under one configuration, not a compliance claim about any organization's actual posture.
- **Early draft.** Structure first, numbers follow. See [docs/OVERLAPS.md](docs/OVERLAPS.md) for how this connects to the other two repos, and `items/*/PREREGISTRATION.md` for what's actually been run versus only planned.

## How it works

1. **Predict.** A prediction file and pass bar are committed before any run, same gate `adt.py` uses: the harness refuses a live run unless the prediction is committed, unedited, and matches the code.
2. **Find.** A finding is recorded as a blueprint: method, endpoint, payload shape, the exact signal that proves the exploit worked, and its MITRE ATT&CK technique ID. No blueprint targets anything outside the pinned lab container.
3. **Patch.** The lab target gets the real fix (a code change, a config change, a WAF rule), not a toggle.
4. **Verify.** The blueprint is replayed against the same lab target, before and after the patch, exactly like ADT's paired attack/defense conditions. A result is `VULNERABLE`, `REMEDIATED`, or `ERROR` (couldn't reach the target), never inferred from a status code alone.
5. **Record.** Every run appends to a hash-chained log (`python ledger.py verify`), and a sandboxed ticket closes or reopens based on the replay, not on a developer's say-so.

## Quick start

Python 3.10 or newer, standard library only for the ledger itself; `httpx` only if you install the `dast` extra.

```bash
python ledger.py predict items/pt01-idor-juice-shop   # commit the prediction before any run
python ledger.py verify                                # check the hash chain
python -m pytest -q
```

Lab targets are brought up with Docker and are not part of this repo; each item's `README.md` names the exact image and pinned tag it was run against (`pt01` uses `bkimminich/juice-shop:v17.3.0`).

## Where this fits next to the other repos

- [Agent Defense Theater](https://github.com/ScottColeSW/Agent-Defense-Theater): the same predict/attack/defend/score/record discipline, aimed at agent tool-use and identity risk instead of classic web vulnerabilities.
- [Project Aegis Vector](https://github.com/ScottColeSW/Project-Aegis-Vector): quantitative metrics (perplexity, cosine shift) for one family of attack, RAG/memory poisoning.
- [ai-agent-exposure-appraisal](https://github.com/ScottColeSW/ai-agent-exposure-appraisal): translates measured findings from all of the above into the questions a CISO, CTO, or CFO actually asks.

Details on specific overlaps (same infrastructure attacked from two angles, shared MITRE mappings) are in [docs/OVERLAPS.md](docs/OVERLAPS.md).

## Results so far

| Item | Finding | Result |
| --- | --- | --- |
| [pt01](items/pt01-idor-juice-shop/) Broken Access Control / IDOR (Juice Shop, T1190) | Any logged-in account's token could read any other account's basket by id; no server-side ownership check | No control: `VULNERABLE` (attacker read victim's basket, HTTP 200). A compensating-control proxy that cross-checks the JWT's caller id against the response body's owner id: `REMEDIATED` (HTTP 403), with both accounts' own basket reads still working in every condition |
| [pt02](items/pt02-sqli-login-bypass/) SQL Injection Login Bypass (Juice Shop, T1190, A03:2021) | `' OR 1=1--` as the login email authenticates as the admin account with no valid password | No control: `VULNERABLE` (authenticated as `admin@juice-sh.op`). A naive SQL-metacharacter filter: `REMEDIATED` (HTTP 403), ordinary logins unaffected. Surprise: a legitimate email containing an apostrophe already fails against the unmodified backend (HTTP 500), and the filter blocks it too, just with a cleaner error |
| [pt03](items/pt03-exposed-ftp-directory/) Exposed `/ftp/` Directory (Juice Shop, T1083 / T1552.001, A05:2021) | Unauthenticated directory listing exposing a file marked confidential and a KeePass credential database | No control: `VULNERABLE` on all three (listing, confidential doc, `.kdbx`, all HTTP 200, no auth). A default-deny proxy with a one-file allowlist for a document checked to be genuinely public: `REMEDIATED` (403 on the rest), that one legitimate document still served at 200 |
| [pt04](items/pt04-ssrf-profile-image/) SSRF via Profile Image URL (Juice Shop, T1190, A10:2021) | **pt04-001**: the server fetches an arbitrary `imageUrl` itself (`User-Agent: node` on the callback, not a browser), confirmed with an out-of-band listener. **pt04-002**, found while chasing why Juice Shop's own scoreboard didn't flag it: the same SSRF also pivots to an internal-only endpoint, a narrower but more severe variant | Both: `VULNERABLE` pre-fix. The one destination-allowlisting proxy built for pt04-001 generalizes to pt04-002 without any new rule: `REMEDIATED` on both, the one allowlisted CDN still reachable |
| [pt05](items/pt05-vulnerable-dependency/) Vulnerable Dependency (Juice Shop, CWE-1104, A06:2021) | `jsonwebtoken@0.4.0`, as actually installed (resolved from the lockfile, not guessed from a version range), carries `CVE-2015-9235` (CRITICAL) among 4 known advisories; 17 of 69 direct dependencies have at least one | SCA, not DAST, by design: no exploit attempted, see item README for why. `--mode current`: `VULNERABLE`. `--mode proposed-fix`: the current published version (`9.0.3`) checked clean, `REMEDIATED`, without installing it into the running container |
| [pt06](items/pt06-jwt-algorithm-confusion/) JWT Algorithm Confusion (Juice Shop, CWE-347, T1606.001, A02:2021) | Closes the loop with pt05: the real verification code calls `jsonwebtoken.verify()` with no algorithm restriction, so a token forged as HS256 using the RS256 **public** key as the HMAC secret authenticates as admin with zero login | No control: `VULNERABLE` (forged admin token accepted, HTTP 200). An algorithm-pinning proxy: `REMEDIATED` (HTTP 401), a real RS256 session unaffected |
| [pt07](items/pt07-weak-default-credentials/) Weak Default Admin Credentials (Juice Shop, CWE-521, T1078.001, A07:2021) | No injection, no forgery: the real admin account logs in with `admin123`. Juice Shop's own scoreboard flipped on the first try, no narrower intended-solve path to chase this time | No control: `VULNERABLE` (real admin session, HTTP 200). A password-blocklist proxy: `REMEDIATED` (HTTP 401), a legitimate account's own password unaffected |
| [pt08](items/pt08-missing-function-level-access-control/) Missing Function-Level Access Control (Juice Shop, CWE-862, T1087.001, A01:2021) | Found by checking a layer the scoreboard's own test doesn't reach: the "Admin Section" frontend guard is actually intact, but `GET /api/Users` behind it has no role check at all, any customer lists all 39 accounts and roles | No control: `VULNERABLE` (customer sees the full admin-only directory). A role-pinning proxy: `REMEDIATED` (HTTP 403), real admin access unaffected |
| [pt09](items/pt09-unauthorized-feedback-deletion/) Unauthorized Feedback Deletion (Juice Shop, CWE-862, T1485, A01:2021) | Found by reading an odd scoreboard solve condition literally (5-star feedback count must hit zero): any authenticated account can delete any other account's feedback by id | No control: `VULNERABLE` (attacker deletes victim's feedback, HTTP 200). An ownership-check proxy: `REMEDIATED` (HTTP 403), self-delete unaffected |
| [pt10](items/pt10-unsafe-config-reopens-sanitization/) Unsafe Config Reopens XSS + NoSQL Injection (Juice Shop, CWE-943/CWE-79, T1190, A05:2021) | A vendor-shipped config (`NODE_ENV=unsafe`) disables the sanitization behind `trackOrder`'s MongoDB `$where` clause, reopening reflected XSS **and** a NoSQL injection that dumped another account's order history | Default Docker config: `REMEDIATED` (already safe by default). `NODE_ENV=unsafe`: `VULNERABLE` on both, confirmed on a second container's own scoreboard |
| [pt11](items/pt11-forged-feedback-identity-spoofing/) Forged Feedback / Identity Spoofing (Juice Shop, CWE-345, T1565.001, A04:2021) | `POST /api/Feedbacks` trusts a client-supplied `UserId` outright; pt09's counterpart on deletion, this time on creation | No control: `VULNERABLE` (row saved under a victim's real id). An identity-pinning proxy that rewrites, not rejects: `REMEDIATED`, same HTTP 201, correct attribution, self-attribution unaffected |
| [pt12](items/pt12-mass-assignment-admin-registration/) Mass Assignment on Registration (Juice Shop, CWE-915, T1136.001, A04:2021) | The most severe finding here needs the least access: the fully unauthenticated public signup form accepts a `role` field and assigns it outright, `role: "admin"` creates a genuine admin account | No control: `VULNERABLE` (resulting role: `admin`). A role-stripping proxy: `REMEDIATED` (resulting role: `customer`), normal registration unaffected |
| [pt13](items/pt13-csrf-profile-update/) CSRF on Profile Username Update (Juice Shop, CWE-352, T1185, A01:2021) | `POST /profile` changes the username authenticated purely by cookie; `Origin`/`Referer` are read only for scoreboard tracking, never enforced. A forged origin with no CSRF token still succeeds | No control: `VULNERABLE` (forged origin, HTTP 302). An Origin-checking proxy: `REMEDIATED` (HTTP 403), same-origin updates unaffected |
| [pt14](items/pt14-basket-parameter-pollution/) HTTP Parameter Pollution on Basket Items (Juice Shop, CWE-235, T1565.001, A01:2021) | A check that's correct in isolation: the ownership check reads the first occurrence of a duplicated `BasketId` key, the actual insert reads the last. One repeated key writes an item into a victim's basket | No control: `VULNERABLE` (item landed in the victim's basket). A duplicate-key-rejecting proxy: `REMEDIATED` (HTTP 400), normal single-key requests unaffected |
| [pt15](items/pt15-free-deluxe-membership/) Free Deluxe Membership (Juice Shop, CWE-840, A04:2021) | A business-logic flaw, not an injection or missing check: `paymentMode` other than exactly `"wallet"` or `"card"`, including absent entirely, skips both payment branches and upgrades the account anyway | No control: `VULNERABLE` (upgraded for free, no MITRE technique assigned, same honest gap as pt05). A payment-mode allowlist: `REMEDIATED` (HTTP 400), a real paid upgrade built and verified end to end still works |
| [pt16](items/pt16-unauthenticated-product-tampering/) Unauthenticated Product Tampering (Juice Shop, CWE-306, T1565.001, A01:2021) | Found in a comment, not a bug hunt: `server.js` shows the authorization line for `PUT /api/Products/:id` commented out. No login of any kind needed to overwrite any product's public, store-wide content | No control: `VULNERABLE` (overwritten with zero auth, HTTP 200). An auth-enforcing proxy: `REMEDIATED` (HTTP 401), real admin edits unaffected. Scenario restores the real product afterward every run |

## Items

| Item | Finding family | Status |
| --- | --- | --- |
| [pt01-idor-juice-shop](items/pt01-idor-juice-shop/) | Broken access control / IDOR | Run live, 2026-11-03 |
| [pt02-sqli-login-bypass](items/pt02-sqli-login-bypass/) | SQL injection login bypass | Run live, 2026-11-03 |
| [pt03-exposed-ftp-directory](items/pt03-exposed-ftp-directory/) | Security misconfiguration / unauthenticated data exposure | Run live, 2026-11-03 |
| [pt04-ssrf-profile-image](items/pt04-ssrf-profile-image/) | Server-side request forgery | Run live, 2026-11-03 |
| [pt05-vulnerable-dependency](items/pt05-vulnerable-dependency/) | Vulnerable and outdated components (SCA) | Run live, 2026-11-03 |
| [pt06-jwt-algorithm-confusion](items/pt06-jwt-algorithm-confusion/) | Cryptographic failure / authentication bypass | Run live, 2026-11-03 |
| [pt07-weak-default-credentials](items/pt07-weak-default-credentials/) | Weak/default authentication credentials | Run live, 2026-11-03 |
| [pt08-missing-function-level-access-control](items/pt08-missing-function-level-access-control/) | Broken access control / missing authorization | Run live, 2026-11-03 |
| [pt09-unauthorized-feedback-deletion](items/pt09-unauthorized-feedback-deletion/) | Broken access control / missing authorization (delete) | Run live, 2026-11-03 |
| [pt10-unsafe-config-reopens-sanitization](items/pt10-unsafe-config-reopens-sanitization/) | Security misconfiguration / reflected XSS + NoSQL injection | Run live, 2026-11-03 |
| [pt11-forged-feedback-identity-spoofing](items/pt11-forged-feedback-identity-spoofing/) | Insecure design / identity spoofing (create) | Run live, 2026-11-03 |
| [pt12-mass-assignment-admin-registration](items/pt12-mass-assignment-admin-registration/) | Insecure design / mass assignment | Run live, 2026-11-03 |
| [pt13-csrf-profile-update](items/pt13-csrf-profile-update/) | Cross-site request forgery | Run live, 2026-11-03 |
| [pt14-basket-parameter-pollution](items/pt14-basket-parameter-pollution/) | HTTP parameter pollution / broken access control | Run live, 2026-11-03 |
| [pt15-free-deluxe-membership](items/pt15-free-deluxe-membership/) | Insecure design / business logic (payment bypass) | Run live, 2026-11-03 |
| [pt16-unauthenticated-product-tampering](items/pt16-unauthenticated-product-tampering/) | Missing authentication (public content tampering) | Run live, 2026-11-03 |

## Keeping this safe

- No blueprint or config may name a host that isn't `localhost`, `127.0.0.1`, `::1`, `host.docker.internal` (Docker's own name for "this machine," used by SSRF items so a container's callback target is still categorically local), or a Docker Compose service name resolved inside this repo's own compose file. A test enforces this before any replay runs, scanning every URL-shaped string in a committed blueprint, not just a single `target.host` field.
- No live API keys, Jira tokens, or SIEM credentials are stored in this repo. `keys.example.ini` (when added) is the committed template; real values live in `keys.ini`, which is gitignored, or in environment variables.
- Nothing here generates novel exploit code against a target it hasn't been explicitly pinned to. Blueprints are data, reviewed like any other fixture, not a general-purpose payload generator.
