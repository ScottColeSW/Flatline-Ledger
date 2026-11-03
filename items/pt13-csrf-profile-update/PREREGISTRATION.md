# Preregistration: pt13-csrf-profile-update

**Status: run live, 2026-11-03. Prediction held exactly, corroborated two ways.**

## Prediction

- Expected result before any fix: `VULNERABLE` (a forged, cross-origin request with no CSRF token changes the username anyway)
- Expected result after the fix: `REMEDIATED`
- Expected cost to legitimate traffic: none, a same-origin profile update must keep working.

## Result

- Pre-fix: `VULNERABLE`. A request carrying `Origin: https://evil.flatline.test`, no CSRF token, succeeded, HTTP 302, and the new session cookie's own JWT decoded to the attacker-chosen username. Separately confirmed with the exact themed origin from Juice Shop's official walkthrough (`htmledit.squarefree.com`), which also flipped the real "CSRF" scoreboard entry.
- Post-fix (through an Origin-checking proxy): `REMEDIATED`, HTTP 403 for both forged origins; the same-origin update still worked.

## A second angle chased, not confirmed, reported anyway

Scott asked directly whether there was a subtler second exploit worth mentioning, prompted by this item's username field being attacker-controlled through the CSRF. Worth answering precisely rather than letting the question drop:

- Juice Shop's own "persisted XSS" check (`persistedXssUserChallenge`) is on the **email** field, not username, and email isn't reachable through `POST /profile` at all.
- Username *is* reachable through this CSRF, and under the same `NODE_ENV=unsafe` override [pt10](../pt10-unsafe-config-reopens-sanitization/) demonstrated, the username setter does drop to a weaker, single-pass sanitizer (`sanitizeLegacy`) instead of the recursive one.
- Tested directly anyway: the flat payload `<iframe src="javascript:alert(\`xss\`)">`, pushed through the CSRF against the unsafe-mode container, still got neutralized, stored as `rc="javascript:alert(\`xss\`)">`. Defeating `sanitizeLegacy`'s single-pass regex needs a nested payload (the classic "unsanitized unsanitization" bypass), a separate investigation this item doesn't claim to have done.

Recorded here as a real, half-confirmed direction, not folded into this item's own `VULNERABLE`/`REMEDIATED` result, since that result should only reflect what was actually proven.

Raw results in `results/pt13-001-*.json`; all runs (including two that briefly failed during development, see commit history, not rewritten out of the chain) are in the repo-root hash-chained log (`python ledger.py verify`).
