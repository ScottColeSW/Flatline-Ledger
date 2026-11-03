# Preregistration: pt17-xxe-file-disclosure

**Status: run live, 2026-11-03. Prediction held exactly, confirmed on the real scoreboard.**

## Prediction

- Expected result before any fix: `VULNERABLE` (an uploaded XML file with an external SYSTEM entity gets that entity resolved and reflected back)
- Expected result after the fix: `REMEDIATED`
- Expected cost to legitimate traffic: none, a benign XML upload with no DOCTYPE must still reach the backend.

## Result

- Pre-fix: `VULNERABLE`. An uploaded `.xml` file defining `<!ENTITY xxe SYSTEM "file:///etc/passwd">` got that entity resolved, and the real contents of `/etc/passwd` (`root:x:0:0:root:/root:/sbin/nologin...`) came back inside the endpoint's own HTTP 410 "deprecated" error message. Confirmed by Juice Shop's own "XXE Data Access" scoreboard entry, flipped on the first attempt.
- Post-fix (through a signature-rejecting proxy): `REMEDIATED`, HTTP 403.
- Legitimate check: a benign XML upload with no DOCTYPE reached the backend unmodified in both conditions.

## A deliberate scope limit, stated up front rather than discovered the hard way

The vendor's own code carries a caution comment directly above this parser: `// XXE attacks in Docker/Heroku containers regularly cause "segfault" crashes`. This item tests only the one-shot file-disclosure variant (`SYSTEM "file:///etc/passwd"`), confirmed not to crash or destabilize the container (checked immediately after: `HTTP 200` on a normal request). The DoS/billion-laughs variant (`xxeDosChallenge`) was deliberately never attempted, this container is shared with every other item in this repo, and crashing it to chase one more scoreboard entry wasn't worth the risk to everything else already run and recorded here.

Raw results in `results/pt17-001-*.json`; both runs are in the repo-root hash-chained log (`python ledger.py verify`).
