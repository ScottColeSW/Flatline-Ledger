# pt19: Exposed Metrics Endpoint — OWASP Juice Shop

**Status: run live, 2026-11-03.** Started as an incidental scoreboard flip from earlier curl traffic, formalized here on request.

## Target

Same container as the earlier items: `bkimminich/juice-shop:v17.3.0`, `http://localhost:3001`.

## Finding

`server.js` names it in its own comment, same pattern as pt16's:

```js
const Metrics = metrics.observeMetrics();  // vuln-code-snippet neutral-line exposedMetricsChallenge
app.get('/metrics', metrics.serveMetrics());  // vuln-code-snippet vuln-line exposedMetricsChallenge
```

No authorization middleware at all. `GET /metrics` returns a full Prometheus scrape to anyone: host fingerprinting (Node.js `v20.19.0`, process memory, CPU time, open file descriptors) and business metrics most apps would never expose publicly, `juiceshop_users_registered_total` (every registered account, ours included), `juiceshop_wallet_balance_total` (every account's wallet balance, summed), and a `juiceshop_cheat_score` gauge. Juice Shop's own solve condition for this challenge is almost comically direct: any request whose `User-Agent` doesn't contain the word `"Prometheus"` counts as proof the endpoint is reachable by something other than its intended scraper.

## Classification

**CWE-200** (Exposure of Sensitive Information to an Unauthorized Actor). **OWASP: A05:2021 - Security Misconfiguration**, an operational endpoint left open by omission, not a code-level flaw needing a patch. **MITRE ATT&CK: T1592.002** (Gather Victim Host Information: Software), the host-fingerprinting half of what's exposed; the business-metrics half (user and wallet totals) is more properly data exposure than host recon, worth naming even though it doesn't map as cleanly to a single ATT&CK sub-technique.

## What was run

```bash
python items/pt19-exposed-metrics/scenario.py                               # pre-fix, direct to :3001
python items/pt19-exposed-metrics/proxy.py                                  # separate shell, FLATLINE_ENFORCE=1 by default
python items/pt19-exposed-metrics/scenario.py --target http://localhost:3020 # post-fix, through the proxy
```

## The fix: a shared secret, the way a real deployment would gate this

`proxy.py` requires a shared-secret header (`X-Metrics-Token`) before forwarding, the same pattern real Prometheus deployments use (a bearer token or basic-auth credential configured on both the scraper and the target).

## Result

| Condition | Target | Unauthenticated scrape | Authenticated scrape |
| --- | --- | --- | --- |
| No control | `http://localhost:3001` (direct) | `VULNERABLE` — all markers present | OK |
| Shared-secret proxy | `http://localhost:3020` (proxy, enforcing) | `REMEDIATED` — HTTP 401 | OK |

Raw per-run output: `results/pt19-001-*.json`. `python ledger.py verify` from the repo root confirms both runs are in the hash-chained log untampered.

## What this does not show

- The full metric set wasn't exhaustively catalogued for sensitivity; only three representative markers were tracked.
- Same caveats as the earlier items: one vendor image, one run, no ticket-loop integration yet.
