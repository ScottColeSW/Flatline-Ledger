# pt04: SSRF via Profile Image URL — OWASP Juice Shop

**Status: run live, 2026-11-03.**

## Target

Same container as the earlier items: `bkimminich/juice-shop:v17.3.0`, `http://localhost:3001`.

## Finding family

`POST /profile/image/url` lets any logged-in user set `imageUrl` to an arbitrary address, and the server fetches it itself. Confirmed by hand before writing any automation: a throwaway listener on this host received the request with `User-Agent: node`, Juice Shop's own backend, not a browser rendering an `<img>` tag. That means the feature can be made to issue outbound requests to anything the container can reach, not just image hosts.

## MITRE ATT&CK mapping

**T1190** (Exploit Public-Facing Application). OWASP category: **A10:2021 - Server-Side Request Forgery**.

## What was run

`scenario.py` is self-contained: it spins up two throwaway local oracle servers of its own (one standing in for an attacker's callback target, one for a single vetted image CDN), fires a profile-image-url request at each with a random marker in the path, and checks which oracle actually got hit. Both oracle hosts are `host.docker.internal:<port>`, Docker's own name for "this machine," not a real external destination; see `PREREGISTRATION.md` for how the ledger's safety guard was widened to cover this honestly instead of carving out an exception.

```bash
python items/pt04-ssrf-profile-image/scenario.py                               # pre-fix, direct to :3001
python items/pt04-ssrf-profile-image/proxy.py                                  # separate shell, FLATLINE_ENFORCE=1 by default
python items/pt04-ssrf-profile-image/scenario.py --target http://localhost:3007 # post-fix, through the proxy
```

## The fix: a destination allowlist, not a feature removal

`proxy.py` intercepts `POST /profile/image/url`, parses the `imageUrl`'s host, and forwards only if that host is on a one-entry allowlist standing in for "a small set of vetted image CDNs a real deployment would actually use." Everything else, including the attacker's callback host, gets a 403 with no fetch attempted at all.

## Result

| Condition | Target | Attacker callback | Allowlisted CDN |
| --- | --- | --- | --- |
| No control | `http://localhost:3001` (direct) | Hit (SSRF confirmed) | Hit |
| Destination allowlist | `http://localhost:3007` (proxy, enforcing) | Not hit, HTTP 403 | Still hit, HTTP 200 |

Raw per-run output: `results/pt04-001-*.json`. `python ledger.py verify` from the repo root confirms both runs are in the hash-chained log untampered.

## A note on Juice Shop's own scoreboard, and why it didn't light up

Scott noticed Juice Shop's own challenge tracker didn't mark its "SSRF" challenge solved after the live run above, and asked. Worth answering properly rather than shrugging it off: pulling `build/routes/profileImageUrlUpload.js` straight out of the container shows why.

```js
if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null)
    req.app.locals.abused_ssrf_bug = true;
```

The fetch happens unconditionally once logged in; this regex check is a side channel that only flags a specific URL pattern, independent of whether a real SSRF occurred. And flipping that flag isn't enough on its own: `routes/verify.js` only calls `challengeUtils.solve(...)` when a *separate* request hits `/solve/challenges/server-side?key=tRy_H4rd3r_n0thIng_iS_Imp0ssibl3`, which `server.js` wires up as the app's own internal verification route. The challenge's intended solve path is narrower than the real vulnerability: make the SSRF target the app's *own* `/solve/challenges/server-side` endpoint with that magic key, not merely any arbitrary external host.

Confirmed by hand, once: pointing `imageUrl` at `http://localhost:3000/solve/challenges/server-side?key=tRy_H4rd3r_n0thIng_iS_Imp0ssibl3` (a self-referential SSRF) flips `GET /api/Challenges/?name=SSRF` to `"solved": true`. This corroborates the finding, it doesn't supersede it: the out-of-band callback this item's `scenario.py` uses proves the more general and more serious claim (arbitrary destination, not just the app's own verification route), which is also why it's the one the automated scenario keeps, not this narrower one.

This corroboration step is **not** wired into `scenario.py`, on purpose: Juice Shop's solved flag is one-way for the life of the container, so re-running it against the same running instance would report "corroborated" on every future run regardless of whether that run's fix actually worked, a repeatable check that always passes isn't a check. Recorded here as a one-time, by-hand finding instead.

(For [pt05](../pt05-vulnerable-dependency/): nothing comparable applies, it never sends the running app any traffic at all, which is the point, not a gap.)

## What this does not show

- The allowlist here is hostname-only; it doesn't resolve DNS and check the resulting IP, so a hostname that resolves differently at request time than at allowlist-check time (DNS rebinding) is not covered.
- Only one destination was tested as "legitimate." A real deployment's CDN allowlist would need its own review, same caveat as pt03's single-file allowlist.
- Same caveats as the earlier items: one vendor image, one run, no ticket-loop integration yet.
