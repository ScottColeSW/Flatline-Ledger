# pt23: Forged, Unauthenticated Review Creation — OWASP Juice Shop

**Status: run live, 2026-11-04.** Found while building pt22, turned out to be two bugs stacked on one route.

## Target

Same container as the earlier items: `bkimminich/juice-shop:v17.3.0`, `http://localhost:3001`.

## Finding

`server.js`'s own route table shows the asymmetry directly:

```js
app.get('/rest/products/:id/reviews', showProductReviews())
app.put('/rest/products/:id/reviews', createProductReviews())                        // <- no isAuthorized() here
app.patch('/rest/products/reviews', security.isAuthorized(), updateProductReviews())
app.post('/rest/products/reviews', security.isAuthorized(), likeProductReviews())
```

Creating a review is the one route on this model with no authorization middleware at all. Inside the handler, `createProductReviews.js` looks up the caller optionally (`security.authenticatedUsers.from(req)`) but never rejects when none is found, and inserts whatever `author` field the client supplied regardless of who, if anyone, actually sent the request:

```bash
curl -X PUT http://localhost:3001/rest/products/1/reviews -H "Content-Type: application/json" \
  -d '{"message":"...", "product":"1", "author":"totally-fake@nobody.test"}'
# -> HTTP 201, persisted exactly as submitted, no token, no cookie, nothing
```

## Classification

**CWE-306** (Missing Authentication for Critical Function), primary, the route itself needs no login at all. **CWE-345** (Insufficient Verification of Data Authenticity), secondary, the same client-supplied-identity pattern pt11 found on feedback. **OWASP: A01:2021 - Broken Access Control.** **MITRE ATT&CK: T1565.001** (Stored Data Manipulation), primary; **T1036** (Masquerading), secondary.

## What was run

```bash
python items/pt23-forged-unauthenticated-review/scenario.py                               # pre-fix, direct to :3001
python items/pt23-forged-unauthenticated-review/proxy.py                                  # separate shell, FLATLINE_ENFORCE=1 by default
python items/pt23-forged-unauthenticated-review/scenario.py --target http://localhost:3024 # post-fix, through the proxy
```

Every run posts a review with no `Authorization` header and a fabricated `author`, reads the review list back to confirm persistence (not trusting the `201` response alone), then separately posts a real authenticated review and confirms it's attributed correctly in both conditions.

## The fix: close both gaps in one pass

`proxy.py` requires a valid, decodable bearer token before forwarding (closing the missing-auth gap), and overwrites the body's `author` field with the caller's own real email (closing the identity-forgery gap pt11 and pt12 also use this same correct-don't-reject approach for).

## Result

| Condition | Target | Unauthenticated forged review | Real authenticated review |
| --- | --- | --- | --- |
| No control | `http://localhost:3001` (direct) | `VULNERABLE` — HTTP 201, fabricated author persisted | OK |
| Auth-and-identity-pinning proxy | `http://localhost:3024` (proxy, enforcing) | `REMEDIATED` — HTTP 401 | OK |

Raw per-run output: `results/pt23-001-*.json`. `python ledger.py verify` from the repo root confirms both runs are in the hash-chained log untampered.

## What this does not show

- Only `PUT` (creation) was checked this closely; `PATCH` and `POST` on the same model already carry `isAuthorized()`, but whether they trust `author`/`UserId` fields the same way wasn't separately tested here.
- Same caveats as the earlier items: one vendor image, one run, no ticket-loop integration yet.
