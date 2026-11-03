# Preregistration: pt01-idor-juice-shop

**Status: run live, 2026-11-03. Prediction held exactly.**

## Prediction

- Expected result before any fix: `VULNERABLE`
- Expected result after the fix described in `README.md`: `REMEDIATED`
- Expected cost to legitimate traffic: none (a logged-in user reading their own basket must still succeed in every condition)

## Result

Both halves of the prediction held on the first live run, no hedging needed:

- Pre-fix (`http://localhost:3001`, direct to the Juice Shop container): `VULNERABLE`. The attacker account's bearer token read the victim account's basket by id, HTTP 200, with the victim's own `UserId` in the response body.
- Post-fix (`http://localhost:3002`, through the compensating-control proxy): `REMEDIATED`, HTTP 403.
- Legitimate check: both accounts could still read their own basket in both conditions. Cost: none.

Raw results in `results/pt01-001-*.json`; the run that produced them is in the repo-root hash-chained log (`python ledger.py verify`).

## Pass bar

The item is reported as a pass only if the post-fix replay returns `REMEDIATED` **and** the legitimate-request check still succeeds. A fix that blocks the exploit by also blocking legitimate same-user requests is reported as "costly," not "effective," matching the scoring convention in Agent Defense Theater.

## Commit discipline

- This file is committed before the first live replay.
- The blueprint file(s) it points to are committed, unedited, at the same commit.
- Any mismatch between this file and the code at run time fails closed (`ledger.py` refuses to run), not a warning.
