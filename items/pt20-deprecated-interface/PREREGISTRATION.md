# Preregistration: pt20-deprecated-interface

**Status: run live, 2026-11-03. Prediction held exactly.**

## Prediction

- Expected result before any fix: `VULNERABLE` (a .xml upload gets HTTP 410 with a deliberate message, not a plain 404)
- Expected result after the fix: `REMEDIATED`
- Expected cost to legitimate traffic: none, a .pdf complaint attachment must keep working.

## Result

- Pre-fix: `VULNERABLE`. An uploaded `.xml` file with no DOCTYPE at all (deliberately benign, this item measures reachability, not the XXE content pt17 exploited through the same route) got HTTP 410, "deprecated for security reasons," proving the route still executed real parsing logic before responding.
- Post-fix (through a true-decommissioning proxy): `REMEDIATED`, HTTP 404.
- Legitimate check: a `.pdf` complaint attachment, the actual still-supported path, worked in both conditions.

## Made deliberate on request, same as pt19

This item also started as an incidental scoreboard flip (triggered as a side effect of pt17's own XXE testing against the same endpoint). Formalized here on request, same reasoning as [pt19](../pt19-exposed-metrics/).

Raw results in `results/pt20-001-*.json`; both runs are in the repo-root hash-chained log (`python ledger.py verify`).
