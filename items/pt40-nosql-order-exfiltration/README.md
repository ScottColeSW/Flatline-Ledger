# pt40: NoSQL Order Exfiltration — a disabledEnv Flag That Doesn't Mean What It Looks Like — OWASP Juice Shop

**Status: run live, 2026-11-05.** Same route and config pairing as [pt10](../pt10-unsafe-config-reopens-sanitization/), a different, more severe impact, caught by verifying a "ruled out" source flag live instead of trusting it.

## Target

Same two deployments as pt10: `bkimminich/juice-shop:v17.3.0` default config (`http://localhost:3001`), and the same image started with `NODE_ENV=unsafe` as `flatline-juice-shop-unsafe` (`http://localhost:3012`).

## Finding

`routes/trackOrder.ts` builds a MongoDB `$where` clause by string-interpolating its `id` parameter:

```ts
const id = !utils.isChallengeEnabled(challenges.reflectedXssChallenge)
  ? String(req.params.id).replace(/[^\w-]+/g, '')
  : utils.trunc(req.params.id, 60)
db.ordersCollection.find({ $where: `this.orderId === '${id}'` })
```

`data/static/challenges.yml` marks the challenge this unlocks, `noSqlOrdersChallenge` ("NoSQL Exfiltration"), as `disabledEnv: [Docker, Heroku]`, exactly the shape of flag that correctly ruled out SSTI, the zip-slip file write, Local File Read, and NoSQL DoS earlier in this project. This one turned out to be different: `lib/challengeUtils.ts`'s `solve()`/`solveIf()` never check a challenge's own `disabledEnv` before marking it solved. The vulnerable branch on this route is gated by `isChallengeEnabled(challenges.reflectedXssChallenge)`, a **different** challenge's flag, one that carries no such restriction and that pt10 already proved reachable through Juice Shop's own vendor-shipped `unsafe.yml` config.

Confirmed live, not assumed: against `flatline-juice-shop-unsafe`, a single unauthenticated `GET /rest/track-order/' || true || 'x` returned every order in the database, including two independently-placed test orders from two completely unrelated accounts. The same request against the default container returned only the endpoint's single synthetic placeholder.

## Classification

**CWE-943** (Improper Neutralization of Special Elements in Data Query Logic). **OWASP: A03:2021 - Injection.** **MITRE ATT&CK: T1190** (Exploit Public-Facing Application), the same mapping pt10 uses for the sibling finding on this route.

## Why this one, and why it almost got skipped

Scott asked specifically to go back and verify the Docker-disabled "suspected" candidates live, not just trust the source flag. Everything else checked out (SSTI, zip-slip, Local File Read, NoSQL DoS all genuinely unreachable), but this one didn't: its own `disabledEnv` entry is real, but irrelevant, because nothing in the code path ever checks it.

## Where this came from

[pt10](../pt10-unsafe-config-reopens-sanitization/)'s own existing injection payload (`' || '1'=='1`) against this same endpoint already satisfies `noSqlOrdersChallenge`'s exact solve condition (returning more than one order) when run against the unsafe config; it was just never credited or formalized as its own item. This item gives it the same full predict/verify/record treatment any deliberately-hunted finding gets, the same discipline pt19 through pt21 used for incidental scoreboard flips, and goes further than pt10's generic row count by proving the leaked rows are real orders from two specific, independently-created accounts.

## Checked the scoreboard

`noSqlOrdersChallenge` flipped solved on the unsafe container.

## What was run

```bash
python items/pt40-nosql-order-exfiltration/scenario.py --mode safe   # port 3001
python items/pt40-nosql-order-exfiltration/scenario.py --mode unsafe # port 3012, flatline-juice-shop-unsafe
```

Like pt10, there is no `proxy.py` for this item: the independent variable is which of Juice Shop's own vendor-shipped configs is running, not a toggle this repo builds.

## Result

| Condition | Target | Boolean-true injection | Own order trackable |
| --- | --- | --- | --- |
| Safe config | `http://localhost:3001` | `REMEDIATED` — 1 row, placeholder only | OK |
| Unsafe config | `http://localhost:3012` | `VULNERABLE` — 5 rows, both test orders leaked | OK |

Raw per-run output: `results/pt40-001-*.json`. `python ledger.py verify` from the repo root confirms both runs are in the hash-chained log untampered.

## What this does not show

- The real fix is the one pt10 already documents: don't ship a config that disables the sanitizing regex at all, or at minimum keep it off outside of deliberate, clearly-labeled test environments.
- Same caveats as pt10 and the other items: one vendor image, one run each, no ticket-loop integration yet.
