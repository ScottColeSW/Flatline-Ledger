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

## What this does not show

- The allowlist here is hostname-only; it doesn't resolve DNS and check the resulting IP, so a hostname that resolves differently at request time than at allowlist-check time (DNS rebinding) is not covered.
- Only one destination was tested as "legitimate." A real deployment's CDN allowlist would need its own review, same caveat as pt03's single-file allowlist.
- Same caveats as the earlier items: one vendor image, one run, no ticket-loop integration yet.
