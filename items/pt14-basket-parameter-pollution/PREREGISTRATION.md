# Preregistration: pt14-basket-parameter-pollution

**Status: run live, 2026-11-03. Prediction held exactly, confirmed on the real scoreboard.**

## Prediction

- Expected result before any fix: `VULNERABLE` (a duplicate `BasketId` key lets the ownership check and the actual insert disagree)
- Expected result after the fix: `REMEDIATED`
- Expected cost to legitimate traffic: none, a normal single-key request to one's own basket must keep working.

## Result

- Pre-fix: `VULNERABLE`. A request body with `BasketId` listed twice (the attacker's own id first, a victim's id second) created a basket item whose own `BasketId` was the victim's, HTTP 200. Confirmed by Juice Shop's own "Manipulate Basket" scoreboard entry, flipped on the first attempt.
- Post-fix (through a duplicate-key-rejecting proxy): `REMEDIATED`, HTTP 400.
- Legitimate check: a normal, single-key request to one's own basket worked in both conditions.

## Why this one is a parser differential, not a missing check

Every earlier access-control item in this repo was a check that was absent. This one has a check, `basketItem.BasketId && user.bid != basketItem.BasketId`, that looks correct in isolation. The bug is that the check reads `basketIds[0]` (the first occurrence of a repeated key) while the actual insert a few lines later reads `basketIds[basketIds.length - 1]` (the last). The vendor's own body parser (`clarinet`, a streaming parser) preserves duplicate keys rather than collapsing them the way `JSON.parse` would, which is what makes the two reads able to disagree at all. Confirmed by reading the exact source before writing anything.

Raw results in `results/pt14-001-*.json`; both runs are in the repo-root hash-chained log (`python ledger.py verify`).
