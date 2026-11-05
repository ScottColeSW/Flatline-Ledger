# pt41: SSTI eval() RCE — a Severity Escalation From an Earlier Close Call — OWASP Juice Shop

**Status: run live, 2026-11-05.** The most severe finding in this repo: genuine, arbitrary server-side JavaScript execution, confirmed live after being set aside earlier as apparently out of reach.

## Target

Same two deployments as [pt10](../pt10-unsafe-config-reopens-sanitization/) and [pt40](../pt40-nosql-order-exfiltration/): `bkimminich/juice-shop:v17.3.0` default config (`http://localhost:3001`), and the same image started with `NODE_ENV=unsafe` as `flatline-juice-shop-unsafe` (`http://localhost:3012`).

## Finding

`routes/userProfile.ts` checks whether a user's stored username matches `/#{(.*)}/`, and if it does, passes the captured text straight to a raw `eval(code)` call:

```ts
if (username?.match(/#{(.*)}/) !== null && utils.isChallengeEnabled(challenges.usernameXssChallenge)) {
  const code = username?.substring(2, username.length - 1)
  username = eval(code) // eslint-disable-line no-eval
}
```

This is not a sandboxed `vm.createContext` call like the YAML/XML upload handlers elsewhere in this app use; it's the raw, global `eval()`, running in the same scope as the surrounding server code, with full access to Node's `process`, `require`, and every other global.

Confirmed live: a username set to `#{global.process.version}` causes the real running Node.js version (`v20.19.0`) to be rendered on the account's own profile page under the unsafe config, in place of the username, proving genuine arbitrary code execution. The default container never executes this branch at all.

## Classification

**CWE-95** (Improper Neutralization of Directives in Dynamically Evaluated Code, "Eval Injection"). **OWASP: A03:2021 - Injection.** **MITRE ATT&CK: T1059.007** (Command and Scripting Interpreter: JavaScript).

## A severity escalation from an earlier close call

Earlier in this project, this exact `eval()` was investigated and set aside: `usernameXssChallenge` carries `disabledEnv: [Docker, Heroku, Gitpod]`, and against the default container it genuinely did not fire. After [pt40](../pt40-nosql-order-exfiltration/) showed that a challenge's own `disabledEnv` flag doesn't always actually govern the code path it looks like it should, this one was re-checked against `flatline-juice-shop-unsafe` rather than left closed. Unlike pt40's case, `usernameXssChallenge`'s own flag genuinely does gate this exact branch, `utils.isChallengeEnabled(challenges.usernameXssChallenge)` wraps the `eval()` call directly. The escalation is one level deeper than pt40's: `lib/insecurity.ts`'s `getChallengeEnablementStatus` short-circuits to fully enabled whenever `config.get('challenges.safetyMode') === 'disabled'`, and that is exactly what Juice Shop's own `unsafe.yml` sets, the same config pt10 and pt40 already use to reopen their own findings.

## Deliberately safe proof-of-concept

Given this is raw, unsandboxed code execution, the proof-of-concept used here reads exactly one piece of harmless, non-sensitive runtime information (`process.version`) and nothing else: no file access, no process spawning, no reading of credentials, keys, or other sensitive data. The point being demonstrated is that arbitrary code execution is possible at all, not how far it could be taken.

## Checked the scoreboard

`usernameXssChallenge` stayed unsolved, it scores a different, narrower client-side XSS payload paired with a CSP weakness, not this `eval()` directly. `sstiChallenge` ("SSTi") flipped solved after confirming the branch fired and separately calling the app's own `/solve/challenges/server-side?key=...` scoring endpoint, which checks whether that `eval()` branch was exercised during the session.

## What was run

```bash
python items/pt41-ssti-eval-rce/scenario.py --mode safe   # port 3001
python items/pt41-ssti-eval-rce/scenario.py --mode unsafe # port 3012, flatline-juice-shop-unsafe
```

Like pt10 and pt40, there is no `proxy.py` for this item: the independent variable is which of Juice Shop's own vendor-shipped configs is running, not a toggle this repo builds.

## Result

| Condition | Target | `#{global.process.version}` payload | Normal username |
| --- | --- | --- | --- |
| Safe config | `http://localhost:3001` | `REMEDIATED` — displayed literally | OK |
| Unsafe config | `http://localhost:3012` | `VULNERABLE` — real Node.js version eval'd and rendered | OK |

Raw per-run output: `results/pt41-001-*.json`. `python ledger.py verify` from the repo root confirms both runs are in the hash-chained log untampered.

## What this does not show

- Deliberately did not push further than reading a harmless version string; a real engagement demonstrating the full severity of this finding would go further (reading environment variables, listing files, or worse), but that crosses from "proving code execution is possible" into "exercising it," which this repo's safety discipline avoids.
- The real fix is the one pt10 and pt40 already document: don't ship a config that turns off every one of these safety gates at once, or at minimum keep it strictly out of anything resembling a production or shared environment.
- Same caveats as pt10 and pt40: one vendor image, one run each, no ticket-loop integration yet.
