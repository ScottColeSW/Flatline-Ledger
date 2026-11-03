# Preregistration: pt10-unsafe-config-reopens-sanitization

**Status: run live, 2026-11-03. Prediction held exactly, confirmed on the real scoreboard of a second container.**

## Prediction

- Expected result, default Docker config (`--mode safe`): `REMEDIATED` (input stripped, injection never breaks out)
- Expected result, `NODE_ENV=unsafe` (`--mode unsafe`): `VULNERABLE` (both the XSS and the NoSQL injection reopen together)
- Expected cost to legitimate traffic: none, a real order id must still be trackable in both configurations.

## Result

- Safe config: `REMEDIATED`. The XSS payload comes back stripped to alphanumerics; the injection payload returns exactly one (not-found) result, never breaking out of the `$where` clause.
- Unsafe config: `VULNERABLE` on both counts. The XSS payload is reflected raw, byte-for-byte. The injection payload returned 3 full order records instead of 1, including another account's order history, confirmed by hand first: a masked admin email (`*dm*n@j**c*-sh.*p`) came back in a real order record belonging to someone else.
- Both of Juice Shop's own scoreboard entries ("Reflected XSS" and "NoSQL Exfiltration") flipped to `solved: true` on the unsafe-mode container, independently confirming both halves of this finding.
- Legitimate check: a real order id tracked correctly in both configurations.

## Why this item's shape is different from pt01-09

Every other item in this repo pairs a vulnerable state against a fixed state via a proxy toggle. This one pairs two of Juice Shop's own vendor-shipped configurations instead, because the actual "fix" already exists and is already the default: Docker's own `disabledEnv` guard. The thing worth measuring here is what a deployer loses by overriding it, not building a new control.

Raw results in `results/pt10-001-*.json`; both runs are in the repo-root hash-chained log (`python ledger.py verify`).
