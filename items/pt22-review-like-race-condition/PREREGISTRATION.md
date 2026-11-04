# Preregistration: pt22-review-like-race-condition

**Status: run live, 2026-11-04. Found black-box, corroborated against the real source afterward.**

## Prediction

- Expected result before any fix: `VULNERABLE` (concurrent like requests produce more than one entry for the same account)
- Expected result after the fix: `REMEDIATED`
- Expected cost to legitimate traffic: none, a single, non-concurrent like must still succeed.

## Result

- Pre-fix: `VULNERABLE`. 10 real concurrent requests from one account against one review produced 10 entries for that account in `likedBy`, all HTTP 200.
- Post-fix (through a request-serializing proxy): `REMEDIATED`. 1 of 10 succeeded, the other 9 correctly rejected with HTTP 403.
- Legitimate check: a single like request worked normally in both conditions.

## Found the way a real tester would, then checked the answer key

This item started differently from the rest: no source was read first. The UI showed every review as already "liked," including to a fully anonymous curl request with zero auth, an odd enough signal to chase by hand. Firing concurrent requests directly confirmed a real race before any code was consulted. Only afterward was `likeProductReviews.js` pulled from the container, and it matched exactly: a check against stale `likedBy` state, a 150ms sleep the vendor's own comment calls "artificial wait for timing attack challenge," then a write. Juice Shop's own solve condition (`count > 2`, the same account appearing more than twice) is a stricter threshold than this item's own `> 1`; both are satisfied by the same run's result (10 entries).

Raw results in `results/pt22-001-*.json`; both runs are in the repo-root hash-chained log (`python ledger.py verify`).
