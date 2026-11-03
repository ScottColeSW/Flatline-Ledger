# pt10: An Unsafe Config Choice Reopens XSS and NoSQL Injection Together — OWASP Juice Shop

**Status: run live, 2026-11-03.** The first item in this repo where the "before/after" pairing is two vendor configs, not a proxy on and off.

## Targets

- Safe: the same container as every earlier item, `bkimminich/juice-shop:v17.3.0`, `http://localhost:3001`, default config.
- Unsafe: a second container, same image, started with one extra flag:

```bash
docker run -d --name flatline-juice-shop-unsafe -p 3012:3000 -e NODE_ENV=unsafe bkimminich/juice-shop:v17.3.0
```

## How this was found

Investigating the "Reflected XSS" challenge (difficulty 2) for more low-hanging fruit, its own solve condition pointed at something more interesting than plain XSS:

```js
// trackOrder.js
const id = !utils.isChallengeEnabled(challenges.reflectedXssChallenge)
  ? String(req.params.id).replace(/[^\w-]+/g, '')   // sanitized path
  : utils.trunc(req.params.id, 60);                  // raw path, "Truncate id to avoid unintentional RCE"
db.ordersCollection.find({ $where: `this.orderId === '${id}'` })
```

The sanitizing regex and the XSS-enabling flag are the same switch. Checking `challenges.yml`, that challenge is tagged `Danger Zone` and explicitly listed as `disabledEnv: ['Docker', 'Heroku', 'Gitpod']`, which is why the default container (where this repo has run everything else) returns the payload stripped to alphanumerics, not reflected. But Juice Shop itself ships `config/unsafe.yml`, which sets `challenges.safetyMode: disabled` outright, activated with nothing more than `NODE_ENV=unsafe`. No code change, one environment variable, and the switch that's off by default in every deployment this repo has used so far is off.

## What's actually at risk together

Two things reopen at once, confirmed live against the unsafe-mode container:

1. **Reflected XSS.** `<iframe src="javascript:alert(\`xss\`)">` comes back byte-for-byte unescaped in the JSON response.
2. **NoSQL injection, more severe.** The same unsanitized `id` feeds directly into a MongoDB `$where` clause (`this.orderId === '${id}'`), which runs as real JavaScript server-side. `' || '1'=='1` breaks out of the string literal and returns **every order in the database**, not just the one requested, including another account's order history. Confirmed by hand: a masked admin email (`*dm*n@j**c*-sh.*p`) came back in someone else's order record.

Juice Shop's own scoreboard agrees on both: "Reflected XSS" and "NoSQL Exfiltration" both flip to solved against the unsafe-mode container, and neither flips against the default one.

## Classification

**CWE-943** (Improper Neutralization of Special Elements in Data Query Logic) for the primary, more severe finding. **CWE-79** (XSS) for the secondary one, same root cause. **OWASP: A05:2021 - Security Misconfiguration**, the vulnerability is the configuration choice, not a code flaw needing a patch. **MITRE ATT&CK: T1190** (Exploit Public-Facing Application).

## What was run

```bash
python items/pt10-unsafe-config-reopens-sanitization/scenario.py --mode safe    # the default Docker deployment
python items/pt10-unsafe-config-reopens-sanitization/scenario.py --mode unsafe  # the NODE_ENV=unsafe container
```

## The fix: don't set the flag, which is also the default

There's no proxy to build here, the safety control already exists and is already on by default; the "fix" is simply never setting `NODE_ENV=unsafe` (or `ctf`, which ships the same override) anywhere near a real deployment. This item exists to measure what a deployer loses if they do, not to build something new to stop it.

## Result

| Config | Target | XSS payload | NoSQL injection payload | Legitimate tracking |
| --- | --- | --- | --- | --- |
| Default (safe) | `http://localhost:3001` | Stripped to alphanumerics | 1 order returned (not found) | OK |
| `NODE_ENV=unsafe` | `http://localhost:3012` | Reflected raw, unescaped | 3 orders returned, including another account's | OK |

Raw per-run output: `results/pt10-001-*.json`. `python ledger.py verify` from the repo root confirms both runs are in the hash-chained log untampered.

## What this does not show

- Only one injection payload was tried; the actual extent of what's reachable through this `$where` clause (the code comment's own words, "to avoid unintentional RCE") wasn't explored further, this item stopped at confirming cross-account data exfiltration, deliberately not pushing toward remote code execution.
- `config/ctf.yml` sets the same `safetyMode: disabled` and wasn't separately tested; it's reasonable to assume it behaves identically, but that's an assumption, not a measurement.
- Same caveats as the earlier items: one vendor image, one run, no ticket-loop integration yet.
