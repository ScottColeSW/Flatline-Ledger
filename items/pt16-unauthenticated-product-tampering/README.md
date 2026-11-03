# pt16: Unauthenticated Product Tampering — OWASP Juice Shop

**Status: run live, 2026-11-03.** Found in a comment, not a bug hunt.

## Target

Same container as the earlier items: `bkimminich/juice-shop:v17.3.0`, `http://localhost:3001`.

## Finding

`server.js`'s own route table names the bug directly:

```js
/* Products: Only GET is allowed in order to view products */
app.post('/api/Products', security.isAuthorized());
// app.put('/api/Products/:id', security.isAuthorized())   // <- commented out
app.delete('/api/Products/:id', security.denyAll());
```

The comment above the block says "only GET is allowed," but the line that would have enforced that for `PUT` was commented out. The result: `PUT /api/Products/{id}` accepts a request with no `Authorization` header, no cookie, no prior login of any kind, and overwrites the product's name, description, or price outright. This is public, store-wide content, every visitor sees it, not a per-account field like pt13's username.

## Classification

**CWE-306** (Missing Authentication for Critical Function). **OWASP: A01:2021 - Broken Access Control.** **MITRE ATT&CK: T1565.001** (Stored Data Manipulation).

## What was run

```bash
python items/pt16-unauthenticated-product-tampering/scenario.py                               # pre-fix, direct to :3001
python items/pt16-unauthenticated-product-tampering/proxy.py                                  # separate shell, FLATLINE_ENFORCE=1 by default
python items/pt16-unauthenticated-product-tampering/scenario.py --target http://localhost:3018 # post-fix, through the proxy
```

Every run reads the product's real description first, tampers it, confirms the tamper by reading it back (not trusting the PUT response alone), then restores the original description and confirms that restoration actually took, see `PREREGISTRATION.md` for why that matters here specifically.

## The fix: require what the commented-out line would have required

`proxy.py` rejects `PUT /api/Products/{id}` unless the request carries a decodable bearer token, the authorization check the vendor's own line, left commented out, was meant to add.

## Result

| Condition | Target | Unauthenticated tamper | Real admin edit |
| --- | --- | --- | --- |
| No control | `http://localhost:3001` (direct) | `VULNERABLE` — product overwritten, HTTP 200 | OK |
| Auth-enforcing proxy | `http://localhost:3018` (proxy, enforcing) | `REMEDIATED` — HTTP 401 | OK |

Raw per-run output: `results/pt16-001-*.json`. `python ledger.py verify` from the repo root confirms both runs are in the hash-chained log untampered.

## What this does not show

- Only `PUT` was checked; `POST` and `DELETE` on the same model have their own, separate rules (`isAuthorized()` and `denyAll()` respectively) and weren't re-tested here.
- The fix checks only that a token decodes, not that its holder has any particular role; a real fix should probably also require `role: admin`, same as pt08's finding on a different endpoint.
- Same caveats as the earlier items: one vendor image, one run, no ticket-loop integration yet.
