# pt38: SQL Injection via Product Search — Credential and Schema Dump — OWASP Juice Shop

**Status: run live, 2026-11-05.** Found white-box, two catalog challenges scored from a single route.

## Target

Same container as the earlier items: `bkimminich/juice-shop:v17.3.0`, `http://localhost:3001`.

## Finding

The public product search endpoint builds its SQL query with raw string interpolation, no parameterization anywhere:

```ts
models.sequelize.query(
  `SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`
)
```

`criteria` is the `q` query-string parameter, completely unauthenticated, no login required. This is the same SQL-concatenation pattern [pt02](../pt02-sqli-login-bypass/) exploits on login, now on a public, high-traffic endpoint that returns its results directly to the caller.

The Products table's column count (9) was determined live, before building either payload, with an incrementing `UNION SELECT NULL,NULL,...` probe: 7 and 8 columns produced a SQL "number of result columns" error, 9 succeeded. With that known, two separate `UNION SELECT` payloads were confirmed:

1. `UNION SELECT email,password,3,4,5,6,7,8,9 FROM Users-- ` — every account's email and password hash, including real seeded NPC accounts, appeared in the ordinary search-results JSON.
2. `UNION SELECT sql,2,3,4,5,6,7,8,9 FROM sqlite_master WHERE sql IS NOT NULL-- ` — the full `CREATE TABLE` definition for every table in the database, including `Users`, `Wallets`, `SecurityAnswers`, and `SecurityQuestions`.

## Classification

**CWE-89** (SQL Injection). **OWASP: A03:2021 - Injection.** **MITRE ATT&CK: T1190** (Exploit Public-Facing Application), the same mapping [pt02](../pt02-sqli-login-bypass/) uses.

## Why this one, found white-box

Read directly from `data/static/challenges.yml`: `dbSchemaChallenge` ("Database Schema") and `unionSqlInjectionChallenge` ("User Credentials"), both scored from the exact same route. `routes/search.ts` was pulled and read before a single request was sent.

## Checked the scoreboard

Both `unionSqlInjectionChallenge` and `dbSchemaChallenge` flipped solved.

## What was run

```bash
python items/pt38-sqli-search-credential-schema-dump/scenario.py                               # pre-fix, direct to :3001
python items/pt38-sqli-search-credential-schema-dump/proxy.py                                  # separate shell, FLATLINE_ENFORCE=1 by default
python items/pt38-sqli-search-credential-schema-dump/scenario.py --target http://localhost:3039 # post-fix, through the proxy
```

## The fix

The real fix belongs in `search.ts` itself (bind `q` as a parameter, never concatenate it into the query string); short of patching the vendored image, `proxy.py` rejects any search query containing the `UNION SELECT` keyword pairing, the specific technique both payloads above rely on, before the request ever reaches the backend. Ordinary search terms are never affected.

## Result

| Condition | Target | Credential dump | Schema dump | Normal search |
| --- | --- | --- | --- | --- |
| No control | `http://localhost:3001` (direct) | `VULNERABLE` — email+password leaked | `VULNERABLE` — table schema leaked | OK |
| Keyword-filter proxy | `http://localhost:3039` (proxy, enforcing) | `REMEDIATED` — `400` | `REMEDIATED` — `400` | OK |

Raw per-run output: `results/pt38-001-*.json`. `python ledger.py verify` from the repo root confirms both runs are in the hash-chained log untampered.

## What this does not show

- The proxy's fix is a keyword filter on the specific exploitation technique used here (`UNION SELECT`), not a general SQL-injection firewall; other injection techniques against the same unparameterized query (boolean-blind, time-based, stacked queries where supported) are not addressed by this fix and would need the real parameterized-query fix in `search.ts` itself.
- Same caveats as the earlier items: one vendor image, one run, no ticket-loop integration yet.
