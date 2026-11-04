# pt33: Open Redirect Allowlist Bypass — OWASP Juice Shop

**Status: run live, 2026-11-04.** Found white-box, straight from Juice Shop's own challenge catalog.

## Target

Same container as the earlier items: `bkimminich/juice-shop:v17.3.0`, `http://localhost:3001`.

## Finding

`GET /redirect?to=X` is meant to only redirect to a small set of trusted URLs. The check that enforces it:

```ts
export const isRedirectAllowed = (url: string) => {
  let allowed = false
  for (const allowedUrl of redirectAllowlist) {
    allowed = allowed || url.includes(allowedUrl)
  }
  return allowed
}
```

`.includes()` tests whether the allowlisted string appears *anywhere* in the target URL, not whether the target URL actually starts at (or is hosted at) an allowed origin. A URL on a completely different, attacker-controlled domain that merely contains an allowlisted URL as a query parameter's value passes this check just as easily as a real allowlisted URL would.

Confirmed live:

```
GET /redirect?to=https://flatline-pt33-phish.test/phish?x=https://github.com/juice-shop/juice-shop

HTTP/1.1 302 Found
Location: https://flatline-pt33-phish.test/phish?x=https://github.com/juice-shop/juice-shop
```

A real `302` to the attacker's own domain, not the trusted one.

## Classification

**CWE-601** (URL Redirection to Untrusted Site, "Open Redirect"). **OWASP: A01:2021 - Broken Access Control** (the 2021 revision folded Unvalidated Redirects and Forwards into this category). **MITRE ATT&CK: T1204.001** (User Execution: Malicious Link), the real-world impact of an open redirect is phishing links that appear to point at a trusted domain.

## Why this one, found white-box

Read directly from `data/static/challenges.yml`: `redirectChallenge` ("Allowlist Bypass"), description "Enforce a redirect to a page you are not supposed to redirect to," hint "you have to find a way to beat the allowlist of allowed redirect URLs." `lib/insecurity.ts` was pulled and read before a single request was sent.

## Checked the scoreboard

`redirectChallenge` flipped solved. `redirectCryptoCurrencyChallenge`, a separate, narrower challenge requiring the exact crypto-donation allowlist entries, stayed unsolved, as expected since this item targeted the general bypass, not those specific URLs.

## What was run

```bash
python items/pt33-open-redirect-allowlist-bypass/scenario.py                               # pre-fix, direct to :3001
python items/pt33-open-redirect-allowlist-bypass/proxy.py                                  # separate shell, FLATLINE_ENFORCE=1 by default
python items/pt33-open-redirect-allowlist-bypass/scenario.py --target http://localhost:3034 # post-fix, through the proxy
```

## The fix

`proxy.py` re-implements the same allowlist check correctly: the target URL must actually `startswith()` one of the allowlisted origins, not merely contain one somewhere in its text. A request that fails that stricter check never reaches the backend's permissive one.

## Result

| Condition | Target | Crafted attacker-host redirect | Straight allowlisted redirect |
| --- | --- | --- | --- |
| No control | `http://localhost:3001` (direct) | `VULNERABLE` — `302` to the attacker's own domain | OK |
| Prefix-check proxy | `http://localhost:3034` (proxy, enforcing) | `REMEDIATED` — `406`, rejected | OK |

Raw per-run output: `results/pt33-001-*.json`. `python ledger.py verify` from the repo root confirms both runs are in the hash-chained log untampered.

## What this does not show

- The real fix belongs in `isRedirectAllowed` itself (swap `.includes()` for a prefix or origin check); this proxy demonstrates that fix in front of the backend, not a patch to the vendored image.
- Same caveats as the earlier items: one vendor image, one run, no ticket-loop integration yet.
