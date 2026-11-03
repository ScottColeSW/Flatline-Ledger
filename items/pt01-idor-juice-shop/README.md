# pt01: Broken Access Control / IDOR — OWASP Juice Shop

**Status: run live, 2026-11-03.** Prediction held exactly: vulnerable before the fix, remediated after, no cost to legitimate traffic.

## Target

[OWASP Juice Shop](https://github.com/juice-shop/juice-shop), run locally:

```bash
docker run -d --name flatline-juice-shop -p 3001:3000 bkimminich/juice-shop:v17.3.0
```

Pinned to `v17.3.0`, digest `sha256:123acb31ed8bb05ebb06934a29be83d4e11a46cae937b9ed2bf2bda29d98130a`, as pulled on 2026-11-03.

## Finding family

Insecure direct object reference on `GET /rest/basket/{id}`: Juice Shop's backend checks that the caller is authenticated, but not that the caller owns the requested basket. Any logged-in account's token can read any other account's basket by id.

## MITRE ATT&CK mapping

**T1190** (Exploit Public-Facing Application), the initial-access technique for an unauthenticated-adjacent flaw reachable over the app's own public API.

## What was run

`scenario.py` registers two fresh throwaway accounts every run (`pt01-victim-<timestamp>@flatline.test` / `pt01-attacker-<timestamp>@flatline.test`), logs both in, and:

1. Confirms each account can read its own basket (the legitimate check, must hold in every condition).
2. Has the attacker's token request the victim's basket id (the exploit attempt).

```bash
python items/pt01-idor-juice-shop/scenario.py                               # pre-fix, direct to :3001
python items/pt01-idor-juice-shop/proxy.py                                  # separate shell, FLATLINE_ENFORCE=1 by default
python items/pt01-idor-juice-shop/scenario.py --target http://localhost:3002 # post-fix, through the proxy
```

## The fix: a compensating control, not a patch to the vendor's code

Juice Shop is a vendored lab image; the realistic move when you can't touch a vendor's source is the same one most teams end up shipping: a control in front of it. `proxy.py` forwards every request unchanged except `GET /rest/basket/{id}`, where it decodes the caller's JWT to learn their user id and compares it against the `UserId` in the backend's own response. A mismatch gets a `403` instead of the leaked body. `FLATLINE_ENFORCE=0` runs the identical code path with the check disabled, so pre/post differ by one flag, not two unrelated setups.

## Result

| Condition | Target | Result | Legitimate basket reads |
| --- | --- | --- | --- |
| No control | `http://localhost:3001` (direct) | `VULNERABLE` — attacker read victim's basket, HTTP 200 | Both accounts: OK |
| Compensating control | `http://localhost:3002` (proxy, enforcing) | `REMEDIATED` — HTTP 403 | Both accounts: OK |

Raw per-run output: [`results/pt01-001-1793732349.json`](results/pt01-001-1793732349.json) (vulnerable), [`results/pt01-001-1793732374.json`](results/pt01-001-1793732374.json) (remediated). Both runs are also in the repo-root hash-chained log; `python ledger.py verify` from the repo root confirms the chain.

## A gap between our proof and Juice Shop's own scoreboard, found and fixed

Scott noticed this item's exploit wasn't showing up as solved on Juice Shop's own scoreboard, unlike pt02, pt03, pt04, and pt07. Traced it: `basketAccessChallenge`'s solve check (`routes/basket.js`) looks the attacker's token up in an in-memory cache, `authenticatedUsers.tokenMap`, populated only by middleware wired to `/rest/user/whoami` and `/profile`, never by `/rest/basket/:id` itself. The exploit genuinely works either way, the data leak is real with or without that lookup succeeding, but if the attacker's token was never used against one of those two routes first, Juice Shop's own tracking never notices.

`scenario.py` now calls `GET /rest/user/whoami` with the attacker's token right after login, before the actual exploit, purely to prime that cache. Confirmed live: with the priming call, `View Basket` flips to `solved: true`; without it, the exact same exploit leaves it `false`. This is the fourth item (after pt04, pt06, and pt08's investigation) where Juice Shop's own check turned out to depend on an incidental implementation detail narrower than the real vulnerability, worth fixing here rather than leaving as a known gap, since it cost one line and no change to what's actually being proven.

## What this does not show

- One flaw, one endpoint, one vendor image, one run. No adaptive attacker, no variation in how the ownership check could be bypassed (e.g. if the proxy's JWT decoding assumption changes).
- The "fix" is a compensating control, not a code change to Juice Shop itself; a different vendor app might not expose enough in its response body to filter on this way.
- No ticket-loop integration yet (the Jira/GitHub-Issues closure described in the top-level README's "How it works" step 5 hasn't been built for this item).
