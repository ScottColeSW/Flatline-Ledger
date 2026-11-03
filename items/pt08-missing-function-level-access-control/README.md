# pt08: Missing Function-Level Access Control on `/api/Users` — OWASP Juice Shop

**Status: run live, 2026-11-03.** Found by checking a layer the scoreboard's own test doesn't reach.

## Target

Same container as the earlier items: `bkimminich/juice-shop:v17.3.0`, `http://localhost:3001`.

## How this was found

Investigating the "Admin Section" challenge (difficulty 2, Broken Access Control) to find more low-hanging fruit that matches Juice Shop's own scoreboard. Its actual solve condition, pulled from `build/routes/verify.js`:

```js
challengeUtils.solveIf(challenges.adminSectionChallenge, () => { return utils.endsWith(url, '/19px.png'); });
```

`19px.png` is a hidden marker image that only loads if the Angular frontend actually renders `/#/administration`. Tested directly in the browser: an anonymous visitor gets a `403` from the Angular route itself (correct), and so does a freshly registered, logged-in customer (also correct, the guard checks role, not just login status). **The frontend guard is intact in this version.** Worth stating plainly rather than quietly moving past, not every investigation turns up a bug.

But the SPA's admin page is backed by a real API, `GET /api/Users`, and that API was never exercised by the frontend test at all. Called directly:

```bash
curl -H "Authorization: Bearer <plain customer token>" http://localhost:3001/api/Users
# -> HTTP 200, identical response an admin token gets
```

39 user accounts came back: every `id`, `email`, `role`, and `deluxeToken`, to a customer account with zero privileges. The endpoint checks that a caller is authenticated; it never checks who they are.

## Classification

**CWE-862** (Missing Authorization). **OWASP: A01:2021 - Broken Access Control.** **MITRE ATT&CK: T1087.001** (Account Discovery: Local Account), the practical impact is enumerating every account, including which real addresses are admin.

## What was run

```bash
python items/pt08-missing-function-level-access-control/scenario.py                               # pre-fix, direct to :3001
python items/pt08-missing-function-level-access-control/proxy.py                                  # separate shell, FLATLINE_ENFORCE=1 by default
python items/pt08-missing-function-level-access-control/scenario.py --target http://localhost:3010 # post-fix, through the proxy
```

Each run registers a fresh customer, confirms the exploit, then separately logs in the real admin account (the weak credential pt07 confirmed, reused here only as a read oracle) to verify the legitimate case.

## The fix: a role check at the edge

The real fix is one line added to the vendor's own route handler. The compensating control: `proxy.py` decodes the caller's JWT and rejects anything but `role: admin` on `/api/Users` before the request reaches the backend at all.

## Result

| Condition | Target | Customer access | Admin access |
| --- | --- | --- | --- |
| No control | `http://localhost:3001` (direct) | `VULNERABLE` — HTTP 200, 39 accounts exposed | OK |
| Role-pinning proxy | `http://localhost:3010` (proxy, enforcing) | `REMEDIATED` — HTTP 403 | OK |

Raw per-run output: `results/pt08-001-*.json`. `python ledger.py verify` from the repo root confirms both runs are in the hash-chained log untampered.

## What this does not show

- Only `GET /api/Users` was checked. Juice Shop auto-generates similar REST routes for several other models; whether they have the same gap wasn't tested here.
- Password hashes aren't exposed by this endpoint, Sequelize's default serialization already excludes them; this finding is account enumeration and role/identity disclosure, not credential theft.
- Same caveats as the earlier items: one vendor image, one run, no ticket-loop integration yet.
