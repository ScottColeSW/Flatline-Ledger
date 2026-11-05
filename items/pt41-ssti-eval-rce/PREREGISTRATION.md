# Preregistration: pt41-ssti-eval-rce

## Prediction

- Expected result in `--mode safe` (default Docker deployment, port 3001): `REMEDIATED`. A username containing `#{global.process.version}` is stored and displayed literally on the profile page; no Node.js version string appears anywhere in the response.
- Expected result in `--mode unsafe` (the same `NODE_ENV=unsafe` config pt10 and pt40 already established, port 3012): `VULNERABLE`. The real running Node.js version string appears on the account's own profile page, confirming the payload was `eval()`'d server-side.
- Expected cost to legitimate traffic: none. A normal username with no `#{...}` pattern still displays correctly as itself in both configs.

## A severity escalation from an earlier "ruled out" finding

Earlier in this project, the SSTI eval() in `routes/userProfile.ts` was investigated and set aside: `usernameXssChallenge` carries `disabledEnv: [Docker, Heroku, Gitpod]`, and in that earlier check it genuinely did not execute against the default container. Today, after [pt40](../pt40-nosql-order-exfiltration/) showed that a challenge's own `disabledEnv` flag doesn't always actually govern the code path it looks like it should, this one was re-checked against `flatline-juice-shop-unsafe`, the same container pt10 and pt40 already use, rather than left as a closed question. Unlike pt40's case, `usernameXssChallenge`'s own flag *does* correctly gate this code path, `utils.isChallengeEnabled(challenges.usernameXssChallenge)` is the exact check wrapping the `eval()` call. The escalation is one level deeper: `lib/insecurity.ts`'s `getChallengeEnablementStatus` short-circuits to fully enabled whenever `config.get('challenges.safetyMode') === 'disabled'`, and that is exactly what Juice Shop's own `unsafe.yml` sets. The flag is real and correctly checked; the config that's supposed to only affect two other, already-documented findings turns off this one too.

## Deliberately safe proof-of-concept

This is a raw, unsandboxed `eval(code)` call, not a `vm.createContext` sandbox like the YAML/XML handlers use elsewhere in this app; it runs in the same scope as the surrounding server code, with full access to Node's `process`, `require`, and other globals. The proof-of-concept used here reads exactly one piece of harmless, non-sensitive runtime information, `process.version`, and nothing else: no file access, no process spawning, no reading of credentials, keys, or other sensitive data. The point being demonstrated is that arbitrary code execution is possible at all, not how far it could be taken.

## Result

**Status: run live, 2026-11-05. Prediction held exactly.**

- Safe config (`--mode safe`, port 3001): `REMEDIATED`. The username was stored and displayed literally; no Node.js version string appeared anywhere in the response.
- Unsafe config (`--mode unsafe`, port 3012): `VULNERABLE`. The real running Node.js version (`v20.19.0`) appeared on the profile page, confirming the payload was `eval()`'d server-side.
- Legitimate check: a normal username with no `#{...}` pattern displayed correctly as itself in both configs.

## Checked the scoreboard

`usernameXssChallenge` stayed unsolved (it scores a different, narrower client-side XSS payload combined with a CSP weakness, not this). `sstiChallenge` ("SSTi") flipped solved after confirming the eval() fired and separately hitting the app's own `/solve/challenges/server-side?key=...` scoring endpoint, which checks whether the eval() branch was actually exercised during the session.

Raw results in `results/pt41-001-*.json`; both runs are in the repo-root hash-chained log (`python ledger.py verify`).
