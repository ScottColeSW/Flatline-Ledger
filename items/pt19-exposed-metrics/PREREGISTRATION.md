# Preregistration: pt19-exposed-metrics

**Status: run live, 2026-11-03. Prediction held exactly.**

## Prediction

- Expected result before any fix: `VULNERABLE` (the full Prometheus scrape reaches any caller, no auth)
- Expected result after the fix: `REMEDIATED`
- Expected cost to legitimate traffic: none, a request carrying the correct shared-secret header must keep working.

## Result

- Pre-fix: `VULNERABLE`. `GET /metrics` with no authentication of any kind returned all three tracked markers: total registered users, total wallet balance across every account, and the Node.js version. This item started as an incidental scoreboard flip from earlier curl traffic, formalized here on request rather than left untracked.
- Post-fix (through a shared-secret proxy): `REMEDIATED`, HTTP 401.
- Legitimate check: a request carrying the correct token worked in both conditions.

## Made deliberate on request, not discovered by this item's own testing

Scott asked explicitly that incidental scoreboard flips get the same predict/verify/record treatment as everything deliberately targeted, rather than being left as unexplained bonus entries. This item (and [pt20](../pt20-deprecated-interface/)) exist because of that request: the finding was real and already true before this item was written, the formal scenario/fix/result pairing is what's new.

Raw results in `results/pt19-001-*.json`; both runs are in the repo-root hash-chained log (`python ledger.py verify`).
