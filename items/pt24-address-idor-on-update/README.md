# pt24: Address IDOR on Update (With Ownership Hijack) — OWASP Juice Shop

**Status: run live, 2026-11-04.** Not in Juice Shop's own challenge catalog at all, found purely by exploring the address book.

## Target

Same container as the earlier items: `bkimminich/juice-shop:v17.3.0`, `http://localhost:3001`.

## How this was found

Adding a real address through the UI's "Add New Address" form and watching the network traffic it generated surfaced the actual route, with a genuine vendor typo baked in: `/api/Addresss` (triple s). `GET` on another account's address correctly refused with `"Malicious activity detected."`, a real ownership check. `DELETE` refused the same way. `PUT`, tried next for completeness, didn't refuse at all, it succeeded and overwrote a different account's address outright.

Only then was `server.js`'s route table checked, and it explained everything:

```js
app.put('/api/Addresss/:id', security.appendUserId())
app.delete('/api/Addresss/:id', security.appendUserId(), address.delAddressById())
app.get('/api/Addresss/:id', security.appendUserId(), address.getAddressById())
```

`PUT` has no handler function at all after `appendUserId()`, falling through to the generic Sequelize REST default, which never checks `UserId`. `GET` and `DELETE` both have explicit handlers in `routes/address.js` that correctly scope to `{ id, UserId: req.body.UserId }`.

It's worse than a plain overwrite, though. `appendUserId()` unconditionally sets `req.body.UserId` to the **caller's own id** before the generic update runs. So a successful attack doesn't just change the victim's data, it reassigns the row's ownership to the attacker. Confirmed directly: after the attack, the victim's own `GET` for their own former address came back `"Malicious activity detected"`, the exact message that previously meant "not yours", now firing against its rightful owner.

## Classification

**CWE-639** (Authorization Bypass Through User-Controlled Key, the IDOR itself). **OWASP: A01:2021 - Broken Access Control.** **MITRE ATT&CK: T1565.001** (Stored Data Manipulation), with the ownership-hijack angle arguably reaching into account-takeover territory for that one record, worth naming even without a dedicated sub-technique for it.

## What was run

```bash
python items/pt24-address-idor-on-update/scenario.py                               # pre-fix, direct to :3001
python items/pt24-address-idor-on-update/proxy.py                                  # separate shell, FLATLINE_ENFORCE=1 by default
python items/pt24-address-idor-on-update/scenario.py --target http://localhost:3025 # post-fix, through the proxy
```

Every run creates its own victim and attacker addresses, never touches real seeded data (see `PREREGISTRATION.md` for why that matters here specifically), and checks both halves of the exploit: the attacker's own response shows the reassigned `UserId`, and the victim's own follow-up `GET` confirms they actually lost access.

## The fix: reuse the backend's own correct logic as an authorization oracle

`proxy.py` doesn't reimplement an ownership check from scratch. Before forwarding a `PUT`, it calls the backend's own `GET` for that same address id with the caller's own credentials, the one endpoint that already gets this right. If the backend's own answer is "not yours," the `PUT` never reaches it at all.

## Result

| Condition | Target | Cross-account edit | Self edit |
| --- | --- | --- | --- |
| No control | `http://localhost:3001` (direct) | `VULNERABLE` — succeeds, ownership reassigned, victim locked out | OK |
| GET-oracle proxy | `http://localhost:3025` (proxy, enforcing) | `REMEDIATED` — HTTP 403 | OK |

Raw per-run output: `results/pt24-001-*.json`. `python ledger.py verify` from the repo root confirms both runs are in the hash-chained log untampered.

## What this does not show

- Whether other Sequelize-backed models with the same "no handler for PUT" shape have the identical gap wasn't swept for; only addresses were checked.
- The proxy's oracle call doubles the request count for every `PUT`; a production fix belongs in the backend's own route table, not a compensating control that calls the backend twice.
- Same caveats as the earlier items: one vendor image, one run, no ticket-loop integration yet.
