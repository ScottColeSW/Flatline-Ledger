# pt27: YAML Bomb DoS, Concurrent-Upload Amplification — OWASP Juice Shop

**Status: run live, 2026-11-04.** First item targeting an OWASP A08 (Software and Data Integrity Failures) gap in this repo's coverage, deliberately run against `flatline-juice-shop-unsafe` (port 3012) instead of the main container everything else shares, because this one is DoS-shaped.

## Target

`bkimminich/juice-shop:v17.3.0`, started a second time as `flatline-juice-shop-unsafe` on `http://localhost:3012`, isolated from the main container every other item in this repo uses.

## Finding

The complaint page accepts a `.yml`/`.yaml` attachment with no login at all. A classic "billion laughs" YAML (nested anchors and aliases that each reference the previous layer nine times, expanding to roughly 9⁹ elements if fully resolved) takes about 2 seconds to upload and comes back `503`, confirming a server-side timeout cut it off. That single request also flips Juice Shop's own `yamlBombChallenge` ("Memory Bomb," category "Insecure Deserialization").

That per-request cap doesn't say anything about several requests at once. Firing five of these uploads in parallel from one script, while separately timing an unrelated legitimate request (`GET /rest/products/search`), showed a real, shared-resource denial of service: that request went from a 0.23s baseline to 9.94s, a 42.5x slowdown, while the bombs were parsing. The vendor's own narrow challenge only checks that a single request times out; it has no challenge at all for the concurrent-amplification angle that turns a bounded per-request cost into actual service degradation for everyone else hitting the server.

## A deliberate safety boundary

`routes/fileUpload.ts` carries its own comment noting that related code in this file "regularly cause[s] 'segfault' crashes" in Docker/Heroku containers. Before building this item, the same 5-concurrent-bomb load was run once against the main `flatline-juice-shop` container (used for every other item in this repo) to confirm the finding, then moved entirely to a fresh `flatline-juice-shop-unsafe` instance for the actual predict/verify runs, so a crash, if one happened, couldn't take down the container every other item depends on. Both containers recovered cleanly every time this was run; the test deliberately stayed at this moderate intensity (5 concurrent uploads) rather than escalating to find an actual crash point, since the goal here is demonstrating a working compensating control, not breaking the container.

## Classification

**CWE-502** (Deserialization of Untrusted Data). **OWASP: A08:2021 - Software and Data Integrity Failures.** **MITRE ATT&CK: T1499.004** (Endpoint Denial of Service: Application or System Exploitation), a crafted payload exploiting an application-level weakness to exhaust resources.

## Corroboration against source

`routes/fileUpload.ts`'s `handleYamlUpload`:

```ts
const sandbox = { yaml, data }
vm.createContext(sandbox)
const yamlString = vm.runInContext('JSON.stringify(yaml.load(data))', sandbox, { timeout: 2000 })
```

The `timeout: 2000` bounds one call's CPU cost; nothing anywhere in the request path limits how many such calls a single caller can have in flight at once. `data/static/challenges.yml` confirms `yamlBombChallenge` only requires triggering that one timeout once, nothing in the catalog measures the effect on concurrent, unrelated traffic.

## What was run

```bash
python items/pt27-yaml-bomb-dos/scenario.py                               # pre-fix, direct to :3012 (unsafe container)
python items/pt27-yaml-bomb-dos/proxy.py                                  # separate shell, FLATLINE_ENFORCE=1 by default, FLATLINE_BACKEND=http://localhost:3012
python items/pt27-yaml-bomb-dos/scenario.py --target http://localhost:3028 # post-fix, through the proxy
```

## The fix

Rejecting `.yml`/`.yaml` attachments outright isn't this proxy's call, that's a product decision about what file types the complaint form should accept, not a security one this repo can make for the vendor. `proxy.py` throttles by caller IP instead: at most 1 `.yml`/`.yaml` upload per 15-second window passes through unchanged, further ones in that same window get `429` before the backend ever starts parsing them. Every other upload (`.pdf`, `.xml`, `.zip`) is untouched regardless of the throttle.

## Result

| Condition | Target | Legitimate request under 5-concurrent-bomb load | Bomb uploads blocked | Plain `.pdf` upload |
| --- | --- | --- | --- | --- |
| No control | `http://localhost:3012` (direct) | `VULNERABLE` — 0.23s → 9.94s (42.5x) | 0/5 | OK |
| IP-throttling proxy | `http://localhost:3028` (proxy, enforcing) | `REMEDIATED` — stayed within non-significant range (1.7x) | 4/5 | OK |

Raw per-run output: `results/pt27-001-*.json`. `python ledger.py verify` from the repo root confirms both runs are in the hash-chained log untampered.

## What this does not show

- The throttle here is a simple in-memory per-IP fixed window, same limitation as pt26's; a real deployment would want this shared across proxy instances.
- This doesn't fix the underlying per-request cost, a single allowed upload (the first one in any window) still consumes up to 2 seconds of server time; it only bounds how many of those a given caller can stack concurrently.
- Only tested with a 5-bomb concurrent load, deliberately not pushed further given the known container-crash risk on this code path; a production deployment facing a genuinely larger botnet would need the throttle tuned differently.
- Same caveats as the earlier items: one vendor image, one run, no ticket-loop integration yet.
