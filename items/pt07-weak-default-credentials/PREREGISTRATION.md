# Preregistration: pt07-weak-default-credentials

**Status: run live, 2026-11-03. Prediction held exactly, and matched Juice Shop's own scoreboard on the first try.**

## Prediction

- Expected result before any fix: `VULNERABLE` (the real admin account accepts `admin123`)
- Expected result after the fix: `REMEDIATED`
- Expected cost to legitimate traffic: none, a freshly registered account logging in with its own password must keep working.

## Result

- Pre-fix: `VULNERABLE`. `admin@juice-sh.op` / `admin123` is a real, working login for the actual admin account, not a forged token or an injection bypass. Confirmed by hand first; Juice Shop's own "Password Strength" challenge flipped to `solved: true` on the very first attempt, no narrower intended-solve path this time (unlike pt04's and pt06's own scoreboard checks).
- Post-fix (through a password-blocklist proxy): `REMEDIATED`, HTTP 401.
- Legitimate check: a freshly registered account's own, non-blocklisted password worked in both conditions.

Raw results in `results/pt07-001-*.json`; both runs are in the repo-root hash-chained log (`python ledger.py verify`).

## Low-hanging fruit, found deliberately

Scott asked to prioritize findings that satisfy Juice Shop's own scoreboard, not just this repo's independent proof, after noticing pt04's and pt06's narrower intended-solve paths didn't match ours. This item was picked specifically because its solve condition (`build/routes/login.js`) is a direct literal match: `req.body.email === 'admin@' + domain && req.body.password === 'admin123'`, no themed username, no magic query parameter, so there was no daylight between "our proof" and "their check" to chase down.
