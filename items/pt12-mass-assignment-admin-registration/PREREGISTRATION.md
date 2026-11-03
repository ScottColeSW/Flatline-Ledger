# Preregistration: pt12-mass-assignment-admin-registration

**Status: run live, 2026-11-03. Prediction held exactly, confirmed on the real scoreboard immediately.**

## Prediction

- Expected result before any fix: `VULNERABLE` (a fully unauthenticated registration with `role: "admin"` in the body creates a real admin account)
- Expected result after the fix: `REMEDIATED`
- Expected cost to legitimate traffic: none, a normal registration with no role field must still default to `customer`.

## Result

- Pre-fix: `VULNERABLE`. `POST /api/Users` with `role: "admin"` alongside the normal signup fields, no authentication of any kind, created a real account whose own JWT decodes to `role: admin` on first login. Juice Shop's own "Admin Registration" scoreboard flipped on the first attempt.
- Post-fix (through a role-stripping proxy): `REMEDIATED`, the same registration resulted in `role: customer`.
- Legitimate check: a normal registration with no `role` field defaulted to `customer` in both conditions.

## The most severe finding in this repo, and why it's simple rather than clever

Every earlier item needed something: a known weak credential, a forged token, a path traversal, a sequence of requests. This one needs none of that. The registration endpoint is public by design, no login required to reach it, and it happens to also accept a field that assigns a privilege level. Nothing about this took cleverness to find, Juice Shop's own catalog names the challenge "Admin Registration" and its hint says exactly what to try. Worth stating plainly: the simplest finding in the series is also the one that needs no prior access at all.

Raw results in `results/pt12-001-*.json`; both runs are in the repo-root hash-chained log (`python ledger.py verify`).
