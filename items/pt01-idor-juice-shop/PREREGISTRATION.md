# Preregistration: pt01-idor-juice-shop

**Status: template only. Not yet committed as a real prediction.**

A real preregistration here must be committed, unedited, before `ledger.py verify` is allowed to run live against this item (the harness checks this, it isn't just a convention). Fill in the fields below, commit, then run.

## Prediction

- Expected result before any fix: `VULNERABLE`
- Expected result after the fix described in `README.md`: `REMEDIATED`
- Expected cost to legitimate traffic: none (a logged-in user reading their own basket must still succeed in every condition)

## Pass bar

The item is reported as a pass only if the post-fix replay returns `REMEDIATED` **and** the legitimate-request check still succeeds. A fix that blocks the exploit by also blocking legitimate same-user requests is reported as "costly," not "effective," matching the scoring convention in Agent Defense Theater.

## Commit discipline

- This file is committed before the first live replay.
- The blueprint file(s) it points to are committed, unedited, at the same commit.
- Any mismatch between this file and the code at run time fails closed (`ledger.py` refuses to run), not a warning.
