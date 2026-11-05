# pt39: Discontinued and Safety-Recalled Products Still Purchasable — OWASP Juice Shop

**Status: run live, 2026-11-05.** Found white-box, straight from Juice Shop's own challenge catalog, and reuses a technique from pt38.

## Target

Same container as the earlier items: `bkimminich/juice-shop:v17.3.0`, `http://localhost:3001`.

## Finding

`data/datacreator.ts` seeds the Christmas Special promotional product with `deletedDate = '2014-12-27 00:00:00.000 +00:00'`, soft-deleted from the moment the database is created. Every normal product listing and search query filters `AND deletedAt IS NULL`, so it never appears anywhere a real customer would look. But `routes/basketItems.ts`'s `quantityCheck`, the same function [pt30](../pt30-negative-quantity-wallet-exploit/) exploits for negative quantities, only checks `product.quantity >= quantity` (enough stock); it never checks whether the product itself is soft-deleted.

The Christmas Special's hidden product id was found using the same UNION SQL injection technique as [pt38](../pt38-sqli-search-credential-schema-dump/), querying `Products WHERE deletedAt IS NOT NULL` directly: id 10. That same query surfaced a second hidden product, id 11, seeded with the description "This item has been made unavailable because of lack of safety standards. (This product is unsafe! We plan to remove it from the stock!)", confirming this is a general gap in the basket-add path, not specific to the one named promotional item the catalog scores.

Confirmed live: both products were added to a basket via the ordinary `POST /api/BasketItems`; the Christmas Special was carried through a complete, successful checkout.

## Classification

**CWE-862** (Missing Authorization). **OWASP: A01:2021 - Broken Access Control.** **No MITRE ATT&CK technique assigned**: buying a discontinued or safety-recalled product the storefront deliberately stopped selling is a business-logic/access-control flaw, not attacker tradecraft against an enterprise network; ATT&CK has no clean mapping, the same honest gap [pt15](../pt15-free-deluxe-membership/), [pt30](../pt30-negative-quantity-wallet-exploit/), and [pt37](../pt37-chatbot-coupon-leak/) document for other business-logic findings in this app.

## Why this one, found white-box

Read directly from `data/static/challenges.yml`: `christmasSpecialChallenge` ("Christmas Special"), description "Order the Christmas special offer of 2014," hint "find out how the application handles unavailable products and try to find a loophole." `data/datacreator.ts` and `routes/basketItems.ts` were pulled and read before a single request was sent.

## Checked the scoreboard

`christmasSpecialChallenge` flipped solved.

## What was run

```bash
python items/pt39-discontinued-product-purchase/scenario.py                               # pre-fix, direct to :3001
python items/pt39-discontinued-product-purchase/proxy.py                                  # separate shell, FLATLINE_ENFORCE=1 by default
python items/pt39-discontinued-product-purchase/scenario.py --target http://localhost:3040 # post-fix, through the proxy
```

## The fix

The backend's own single-product read path, `GET /api/Products/:id`, already gets this right: Sequelize's default paranoid mode makes that endpoint `404` for a soft-deleted product automatically, no extra code needed. `proxy.py` reuses that already-correct endpoint as an authorization oracle, the same pattern [pt24](../pt24-address-idor-on-update/) uses for a different resource: before forwarding a basket-item add, it checks the backend's own `GET /api/Products/:id` for the product in question; if that isn't `200`, the add is rejected before it ever reaches the basket.

## Result

| Condition | Target | Christmas Special (id 10) | Safety-recalled product (id 11) | Normal product add |
| --- | --- | --- | --- | --- |
| No control | `http://localhost:3001` (direct) | `VULNERABLE` — added, checkout succeeds | `VULNERABLE` — added | OK |
| Oracle-check proxy | `http://localhost:3040` (proxy, enforcing) | `REMEDIATED` — `400` | `REMEDIATED` — `400` | OK |

Raw per-run output: `results/pt39-001-*.json`. `python ledger.py verify` from the repo root confirms both runs are in the hash-chained log untampered.

## What this does not show

- The real fix belongs in `basketItems.ts`'s `quantityCheck` itself (check the product's own soft-delete state, not just stock); this proxy demonstrates that fix by reusing an existing correct endpoint, not a patch to the vendored image.
- Same caveats as the earlier items: one vendor image, one run, no ticket-loop integration yet.
