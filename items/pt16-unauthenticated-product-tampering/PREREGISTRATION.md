# Preregistration: pt16-unauthenticated-product-tampering

**Status: run live, 2026-11-03. Prediction held exactly, confirmed on the real scoreboard.**

## Prediction

- Expected result before any fix: `VULNERABLE` (a PUT with no auth at all overwrites a real product)
- Expected result after the fix: `REMEDIATED`
- Expected cost to legitimate traffic: none, a real admin-authenticated PUT must keep working.

## Result

- Pre-fix: `VULNERABLE`. `PUT /api/Products/1` with no `Authorization` header at all, no cookie, nothing, overwrote the product's description, HTTP 200, confirmed by reading the product back afterward. Confirmed by hand first against the themed product (`OWASP SSL Advanced Forensic Tool (O-Saft)`, id 9), which flipped Juice Shop's own "Product Tampering" scoreboard entry on the next request after the tamper.
- Post-fix (through an auth-enforcing proxy): `REMEDIATED`, HTTP 401.
- Legitimate check: a real, admin-authenticated PUT worked in both conditions.

## Test hygiene: this one mutates live shared data

Unlike reading a basket or listing users, this item's exploit genuinely changes product content every real customer sees browsing the store, on a container other items' tests also use. `scenario.py` restores the original description immediately after confirming the tamper, every run, and the result records whether that restoration actually succeeded (`original_description_restored`), not just assumed. Both products touched during manual investigation (`Apple Juice`, id 1, and the O-Saft product, id 9) were restored by hand before this item's automated scenario was even written, and the automated version restores on every subsequent run on its own.

Raw results in `results/pt16-001-*.json`; both runs are in the repo-root hash-chained log (`python ledger.py verify`).
