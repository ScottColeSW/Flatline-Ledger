# Preregistration: pt39-discontinued-product-purchase

## Prediction

- Expected result before any fix: `VULNERABLE`. A product known to be soft-deleted (the 2014 Christmas Special, product id 10) can be added to a basket and checked out normally; a second, separately-seeded safety-recalled product (id 11) can also be added.
- Expected result after the fix (a reverse proxy that reuses the backend's own already-correct `GET /api/Products/:id` as an authorization oracle before any basket-item add): `REMEDIATED`. Both adds are rejected before reaching the basket.
- Expected cost to legitimate traffic: none. Adding a normal, currently-listed product still succeeds.

## Why this one, found white-box

Read directly from `data/static/challenges.yml`: `christmasSpecialChallenge` ("Christmas Special"), description "Order the Christmas special offer of 2014," hint "find out how the application handles unavailable products and try to find a loophole." `data/datacreator.ts` confirmed the product is seeded with `deletedDate = '2014-12-27 00:00:00.000 +00:00'`, soft-deleted from day one. `routes/basketItems.ts`'s `quantityCheck`, the same function [pt30](../pt30-negative-quantity-wallet-exploit/) exploits for negative quantities, only checks stock, never whether the product itself is soft-deleted.

## Finding the hidden product id

The Christmas Special's product id was found using the same UNION SQL injection technique as [pt38](../pt38-sqli-search-credential-schema-dump/), querying `Products WHERE deletedAt IS NOT NULL` directly through the search endpoint. That same query surfaced a second hidden product (id 11, seeded description: "made unavailable because of lack of safety standards... we plan to remove it from the stock"), confirming this is a general gap in the basket-add path, not specific to the one named product the catalog scores.

## Result

**Status: run live, 2026-11-05. Prediction held exactly.**

- Pre-fix: `VULNERABLE`. The Christmas Special (product id 10) was added to a basket and carried through a full checkout; the safety-recalled product (id 11) was also added successfully.
- Post-fix (through a proxy reusing `GET /api/Products/:id` as an authorization oracle before any basket-item add): `REMEDIATED`. Both adds were rejected `400`.
- Legitimate check: adding a normal, currently-listed product (Apple Juice, id 1) succeeded in both conditions.

## Checked the scoreboard

`christmasSpecialChallenge` flipped solved.

Raw results in `results/pt39-001-*.json`; both runs are in the repo-root hash-chained log (`python ledger.py verify`).
