# pt25: Complaint Enumeration — OWASP Juice Shop

**Status: run live, 2026-11-04.** Not in Juice Shop's own challenge catalog, same as pt24. A different resource, the same shape of bug as pt08.

## Target

Same container as the earlier items: `bkimminich/juice-shop:v17.3.0`, `http://localhost:3001`.

## Finding

`server.js`'s own comment states the intended rule plainly:

```js
/* Complaints: POST and GET allowed when logged in only */
app.get('/api/Complaints', security.isAuthorized());
app.post('/api/Complaints', security.isAuthorized());
```

No handler function enforces anything beyond that login check. `GET /api/Complaints` falls through to the generic Sequelize REST default, which has no `WHERE` clause scoping to the caller at all. Confirmed black-box: a victim account submitted a distinctly-marked complaint, and a completely unrelated attacker account's own `GET /api/Complaints` returned it, along with a real seeded complaint from the running container's own data (`"I'll build my own eCommerce business! With Black Jack! And Hookers!"`).

Worth naming: this is the second time in this repo a missing-scoping bug on a list endpoint has turned up through independent black-box testing (pt08 found the same shape on `/api/Users`). Same vulnerability class, two unrelated parts of the codebase, found without remembering pt08's result or looking for it on purpose.

## Classification

**CWE-862** (Missing Authorization), same CWE as pt08. **OWASP: A01:2021 - Broken Access Control.** **MITRE ATT&CK: T1213** (Data from Information Repositories), reading every user's complaint content from the application's own store, as distinct from pt08's T1087.001 (Account Discovery), since the data exposed here is complaint *content*, not account identities.

## What was run

```bash
python items/pt25-complaint-enumeration/scenario.py                               # pre-fix, direct to :3001
python items/pt25-complaint-enumeration/proxy.py                                  # separate shell, FLATLINE_ENFORCE=1 by default
python items/pt25-complaint-enumeration/scenario.py --target http://localhost:3026 # post-fix, through the proxy
```

## The fix had to add state the backend never kept

Every earlier access-control fix in this repo could lean on an ownership field the backend already had and simply failed to check. This one can't: `POST /api/Complaints` never records a submitter at all, every row comes back `UserId: null` regardless of who posted it. `proxy.py` tracks `(message, submitting caller's email)` pairs itself at POST time, in memory, then filters the GET response by that self-maintained map. This means it can only scope complaints submitted through the proxy while it's been running; the one pre-existing seeded complaint has no recorded owner under this scheme and is hidden from everyone rather than guessed at or shown to all.

## Result

| Condition | Target | Cross-account list | Own complaint visible |
| --- | --- | --- | --- |
| No control | `http://localhost:3001` (direct) | `VULNERABLE` — victim's complaint visible to the attacker | OK |
| Ownership-tracking proxy | `http://localhost:3026` (proxy, enforcing) | `REMEDIATED` — not visible | OK |

Raw per-run output: `results/pt25-001-*.json`. `python ledger.py verify` from the repo root confirms both runs are in the hash-chained log untampered.

## What this does not show

- The fix's in-memory map doesn't survive a restart and wouldn't scale across multiple proxy instances; a real fix belongs in the backend's own `WHERE UserId = :caller` clause, which first requires the backend to actually record a `UserId` at creation time, a change this repo has no path to make against a vendored image.
- The pre-existing seeded complaint is permanently invisible under this fix, not a complete solution, a honest limitation of compensating for missing data from the outside.
- Same caveats as the earlier items: one vendor image, one run, no ticket-loop integration yet.
