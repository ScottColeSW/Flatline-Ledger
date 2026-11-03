# Preregistration: pt15-free-deluxe-membership

**Status: run live, 2026-11-03. Prediction held exactly, confirmed on the real scoreboard.**

## Prediction

- Expected result before any fix: `VULNERABLE` (an unrecognized or missing `paymentMode` upgrades the account with no payment at all)
- Expected result after the fix: `REMEDIATED`
- Expected cost to legitimate traffic: none, a real wallet payment with sufficient funds must still succeed.

## Result

- Pre-fix: `VULNERABLE`. `POST /rest/deluxe-membership` with an empty body (no `paymentMode` field at all) returned a new session token decoding to `role: deluxe`. No wallet debit, no card check, nothing charged. Confirmed by Juice Shop's own "Deluxe Fraud" scoreboard entry, flipped on the first attempt.
- Post-fix (through a payment-mode-allowlist proxy): `REMEDIATED`, HTTP 400.
- Legitimate check: a real paid upgrade (card added, wallet topped up through it, then a genuine `paymentMode: "wallet"` request) worked in both conditions, built and verified end to end rather than assumed.

## No MITRE technique assigned, same honest gap as pt05

ATT&CK describes attacker tradecraft against systems; "got a $49 feature for free because an else-branch was never written" isn't a technique in that sense, it's a business-logic defect. Rather than force a loose mapping (T1548, Abuse Elevation Control Mechanism, was considered and rejected as too strong a claim for what this actually is), this item leaves the field unassigned and says why, the same choice pt05 made for a different kind of finding.

Raw results in `results/pt15-001-*.json`; both runs are in the repo-root hash-chained log (`python ledger.py verify`).
