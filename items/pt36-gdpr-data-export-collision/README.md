# pt36: GDPR Data Export Order Leak via Email Collision — OWASP Juice Shop

**Status: run live, 2026-11-04.** Found white-box, straight from Juice Shop's own challenge catalog.

## Target

Same container as the earlier items: `bkimminich/juice-shop:v17.3.0`, `http://localhost:3001`.

## Finding

The GDPR data-export endpoint looks up a user's order history by a vowel-redacted form of their email:

```ts
const updatedEmail = email.replace(/[aeiou]/gi, '*')
db.ordersCollection.find({ email: updatedEmail })
```

Orders are stored under this same redacted form when placed (`routes/order.ts`: `email.replace(/[aeiou]/gi, '*')`), apparently intended as light pseudonymization, but used here as the actual database lookup key, not just a display mask. Two different real accounts whose email local-parts redact to the identical string, the simplest case being two local-parts made entirely of vowels plus the same other characters, collide completely: an order from either account is returned to whichever one requests their own data export.

Confirmed live: a fresh account that never placed a single order of its own, registered with an email chosen only to redact identically to a victim's, requested its own GDPR data export and received the victim's real order (product, price, order ID) in the response. No injection, no IDOR parameter tampering, just a chosen registration email.

## Classification

**CWE-639** (Authorization Bypass Through User-Controlled Key). **OWASP: A01:2021 - Broken Access Control.** **MITRE ATT&CK: T1213** (Data from Information Repositories), the same mapping [pt25](../pt25-complaint-enumeration/) uses for a different data-exposure finding.

## Why this one, found white-box

Read directly from `data/static/challenges.yml`: `dataExportChallenge` ("GDPR Data Theft"), description "Steal someone else's personal data without using Injection," hint "trick the regular Data Export to give you more than actually belongs to you." `routes/dataExport.ts` was pulled and read before a single export was requested.

## Checked the scoreboard

`dataExportChallenge` flipped solved. The identical lookup pattern also exists in `routes/orderHistory.ts`'s `/rest/order-history` endpoint, unaffected by this item's fix and out of scope here.

## What was run

```bash
python items/pt36-gdpr-data-export-collision/scenario.py                               # pre-fix, direct to :3001
python items/pt36-gdpr-data-export-collision/proxy.py                                  # separate shell, FLATLINE_ENFORCE=1 by default
python items/pt36-gdpr-data-export-collision/scenario.py --target http://localhost:3037 # post-fix, through the proxy
```

## The fix

The backend has no safe endpoint to re-derive correct ownership (the order-history endpoint shares the same flaw), so `proxy.py` adds the missing, non-colliding state itself: it watches every successful checkout going through it and records `(orderId -> real caller email)`, keyed by the JWT's own email claim rather than the redacted lookup key the backend uses. On a data-export request, it filters the backend's response down to only orders its own map confirms belong to the caller.

## Result

| Condition | Target | Attacker's export (no orders of their own) | Victim's own export |
| --- | --- | --- | --- |
| No control | `http://localhost:3001` (direct) | `VULNERABLE` — includes the victim's real order | Includes own order |
| Ownership-tracking proxy | `http://localhost:3037` (proxy, enforcing) | `REMEDIATED` — victim's order excluded | Includes own order |

Raw per-run output: `results/pt36-001-*.json`. `python ledger.py verify` from the repo root confirms both runs are in the hash-chained log untampered.

## What this does not show

- Same limitation as pt25's fix: this can only protect orders placed *through the proxy* while it has been running; pre-existing orders have no recorded true owner and are hidden from everyone rather than guessed at or shown to all.
- The identical lookup bug in `/rest/order-history` is untouched by this fix; a complete remediation would need the same ownership-tracking (or a real backend fix: key order lookups on the caller's numeric user id, never a redacted, lossy email string) applied there too.
- Same caveats as the earlier items: one vendor image, one run, no ticket-loop integration yet.
