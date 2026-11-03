# pt06: JWT Algorithm Confusion — OWASP Juice Shop

**Status: run live, 2026-11-03.** Closes the loop with [pt05](../pt05-vulnerable-dependency/): the vulnerable library class pt05 found present is confirmed here to be actually exploitable in the running app, not just present in the dependency tree.

## Target

Same container as the earlier items: `bkimminich/juice-shop:v17.3.0`, `http://localhost:3001`.

## Finding

Juice Shop signs real session tokens with RS256, a private key. Pulling `build/lib/insecurity.js` straight out of the running container shows the verification side:

```js
const updateAuthenticatedUsers = () => (req, res, next) => {
    const token = req.cookies.token || utils.jwtFrom(req)
    if (token) {
        jsonwebtoken.verify(token, exports.publicKey, (err, decoded) => {
            if (err === null) { /* ...cache it, trust it... */ }
```

No `algorithms` option. `jsonwebtoken.verify()` without one will happily verify whatever algorithm the token's own header claims, including `HS256`, treating the **RSA public key** as a plain HMAC shared secret instead of a signature-verification key. The public key itself is checked into Juice Shop's open-source repo and extractable from any running container at `encryptionkeys/jwt.pub`, this item's blueprint commits a copy pulled directly from the container.

A token forged as `{"alg":"HS256"}`, signed with that public key as the HMAC secret, claiming `role: admin`, authenticates completely. No login, no password, no prior session.

## Classification

**CWE-347** (Improper Verification of Cryptographic Signature). **OWASP: A02:2021 - Cryptographic Failures**, secondarily **A07:2021 - Identification and Authentication Failures** (it manifests as a full auth bypass). **MITRE ATT&CK: T1606.001** (Forge Web Credentials: Web Cookies), the forged credential is sent, and accepted, as a cookie.

## What was run

```bash
python items/pt06-jwt-algorithm-confusion/scenario.py                               # pre-fix, direct to :3001
python items/pt06-jwt-algorithm-confusion/proxy.py                                  # separate shell, FLATLINE_ENFORCE=1 by default
python items/pt06-jwt-algorithm-confusion/scenario.py --target http://localhost:3008 # post-fix, through the proxy
```

Each run forges a fresh token on the spot from the committed public key and the blueprint's claimed identity, then checks `GET /rest/user/whoami`. The legitimate check registers and logs in a real account and confirms its real, RS256-signed session still works.

## The fix: pin the algorithm, at the edge

The real fix is one line of vendor code (`jwt.verify(token, publicKey, { algorithms: ['RS256'] }, callback)`), not something this repo can patch into a vendored image. The compensating control: `proxy.py` reads the `token` cookie's own JWT header on every request and rejects anything that isn't `RS256` before it ever reaches the backend's unrestricted `verify()` call. A real login never produces anything else, so legitimate traffic passes through untouched.

## Result

| Condition | Target | Forged admin token | Real RS256 session |
| --- | --- | --- | --- |
| No control | `http://localhost:3001` (direct) | `VULNERABLE` — HTTP 200, `admin@juice-sh.op` | OK |
| Algorithm-pinning proxy | `http://localhost:3008` (proxy, enforcing) | `REMEDIATED` — HTTP 401 | OK |

Raw per-run output: `results/pt06-001-*.json`. `python ledger.py verify` from the repo root confirms both runs are in the hash-chained log untampered.

## What this does not show

- Only `GET /rest/user/whoami` was checked. The forged token almost certainly works against every other route gated by `updateAuthenticatedUsers` or `isAuthorized` (both call `verify()`/`express-jwt` the same unrestricted way), but each route wasn't individually confirmed here.
- The compensating control pins to exactly `RS256`; a real deployment with multiple valid signing algorithms would need a real allowlist, not a single hardcoded value.
- Same caveats as the earlier items: one vendor image, one run, no ticket-loop integration yet.
