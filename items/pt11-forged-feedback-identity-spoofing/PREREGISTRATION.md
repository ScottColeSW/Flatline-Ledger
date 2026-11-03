# Preregistration: pt11-forged-feedback-identity-spoofing

**Status: run live, 2026-11-03. Prediction held exactly.**

## Prediction

- Expected result before any fix: `VULNERABLE` (feedback is saved under a victim's id, authored by an attacker's token)
- Expected result after the fix: `REMEDIATED`
- Expected cost to legitimate traffic: none, an account must still be able to submit feedback attributed to itself.

## Result

- Pre-fix: `VULNERABLE`. An attacker's token, submitting with `UserId` set to a different, real victim account's id, got the row created with that victim's id, HTTP 201. Confirmed by Juice Shop's own "Forged Feedback" scoreboard entry flipping on the first attempt.
- Post-fix (through an identity-pinning proxy): `REMEDIATED`. The request still succeeds, HTTP 201, but the proxy silently rewrites `UserId` to the caller's own real id before forwarding, so the created row is correctly attributed regardless of what was claimed.
- Legitimate check: an account submitting feedback attributed to itself worked in both conditions.

## A fix that corrects instead of blocks, and why the status check had to change for it

Every earlier item's compensating control either lets a request through unchanged or rejects it outright; `status` was just "did it get a 4xx." This one's different: the proxy still returns `201`, the request still "succeeds," but the field that mattered is silently corrected first. `scenario.py` had to check what identity the created row actually carries, not just the HTTP status, to tell a real fix apart from a no-op. Worth being explicit about, since missing this would have called a working control `ERROR` for the wrong reason.

Raw results in `results/pt11-001-*.json`; both runs are in the repo-root hash-chained log (`python ledger.py verify`).
