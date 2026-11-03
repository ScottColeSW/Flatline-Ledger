# Preregistration: pt04-ssrf-profile-image

**Status: run live, 2026-11-03. Prediction held exactly.**

## Prediction

- Expected result before any fix: `VULNERABLE` (the server fetches an attacker-chosen URL itself)
- Expected result after the fix: `REMEDIATED`
- Expected cost to legitimate traffic: none, as long as the fix allowlists destinations rather than blocking the feature outright; a single vetted "image CDN" host must stay fetchable in every condition.

## Result

- Pre-fix: `VULNERABLE`. A throwaway local oracle, standing in for an attacker's own server, recorded the request, `User-Agent: node`, confirming the backend itself made the call, not a browser. Confirmed separately by hand before building the automated scenario.
- Post-fix (through an allowlisting proxy): `REMEDIATED`, the attacker oracle never hit; the vetted-CDN oracle still hit.
- Legitimate check: the one allowlisted destination worked in both conditions.

Raw results in `results/pt04-001-*.json`; both runs are in the repo-root hash-chained log (`python ledger.py verify`).

## pt04-002: a second, related finding

Found while investigating why Juice Shop's own scoreboard didn't mark this challenge solved. The SSRF also pivots to an internal-only endpoint (the app's own self-verification route), a narrower but more severe claim than pt04-001's. See `README.md` for the full writeup and why this item's test asymmetry (the pre-fix check uses the app's one-way scoreboard flag, the post-fix check doesn't) is deliberate, not an oversight.

- Pre-fix: `VULNERABLE`, HTTP 200, Juice Shop's own `/api/Challenges` confirms it.
- Post-fix (same proxy as pt04-001, no new rule added): `REMEDIATED`, HTTP 403.

## A safety note on how this item itself is tested

This item's own test harness makes real outbound requests, so its blueprint names two local oracle hosts (`host.docker.internal:3005` and `:3006`) in addition to the usual `target.host`. `ledger.py`'s guard was widened for this (`guard_all_urls_in`, scanning every URL-shaped string in a blueprint, not just `target.host`) rather than carved out as a one-off exception, and `host.docker.internal` was added to the allowlist explicitly because it is Docker's own name for "this machine," never a real external domain. Both changes are covered by `tests/test_ledger.py`.
