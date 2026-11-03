# pt18: Unsigned JWT ("alg": "none") — OWASP Juice Shop

**Status: run live, 2026-11-03.** The sibling to pt06, same root cause, no new proxy written.

## Target

Same container as the earlier items: `bkimminich/juice-shop:v17.3.0`, `http://localhost:3001`.

## Finding

[pt06](../pt06-jwt-algorithm-confusion/) forged an `HS256` token signed with the RS256 public key as an HMAC secret. There's a simpler sibling attack against the exact same unrestricted `jsonwebtoken.verify()` call: a token whose header claims `alg: "none"` needs no signature segment at all.

```json
{"alg": "none", "typ": "JWT"}
```

with an empty third segment. `GET /rest/user/whoami` with that token as the `token` cookie returned the real admin account's data, HTTP 200. Confirmed by hand first, then corroborated against Juice Shop's own "Unsigned JWT" scoreboard entry, which wants the themed email pattern `jwtn3d@` and the token sent via the `Authorization` header (a check that runs in a separate global middleware from `whoami` itself, same nuance pt06 documents for its own sibling check).

## Classification

**CWE-347** (Improper Verification of Cryptographic Signature), the same CWE as pt06, since it's the same root defect. **OWASP: A02:2021 - Cryptographic Failures.** **MITRE ATT&CK: T1606.001** (Forge Web Credentials: Web Cookies).

## What was run

```bash
python items/pt18-unsigned-jwt/scenario.py                               # pre-fix, direct to :3001
python items/pt06-jwt-algorithm-confusion/proxy.py                       # pt06's EXISTING proxy, unmodified, separate shell
python items/pt18-unsigned-jwt/scenario.py --target http://localhost:3008 # post-fix, through pt06's proxy
```

No new `proxy.py` was written for this item. pt06's algorithm-pinning proxy already rejects anything that isn't exactly `RS256`, and `none` isn't `RS256`, so the claim that one fix covers both forgery variants was checked against the real running proxy, not assumed from reading the code.

## Result

| Condition | Target | Forged unsigned token | Real RS256 session |
| --- | --- | --- | --- |
| No control | `http://localhost:3001` (direct) | `VULNERABLE` — HTTP 200, `admin@juice-sh.op` | OK |
| pt06's proxy, unchanged | `http://localhost:3008` (proxy, enforcing) | `REMEDIATED` — HTTP 401 | OK |

Raw per-run output: `results/pt18-001-*.json`. `python ledger.py verify` from the repo root confirms both runs are in the hash-chained log untampered.

## What this does not show

- Only `GET /rest/user/whoami` was checked, same scope limit pt06 states for its own finding.
- Same caveats as the earlier items: one vendor image, one run, no ticket-loop integration yet.
