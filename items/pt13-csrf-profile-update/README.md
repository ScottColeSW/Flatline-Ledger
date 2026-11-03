# pt13: CSRF on Profile Username Update — OWASP Juice Shop

**Status: run live, 2026-11-03.**

## Target

Same container as the earlier items: `bkimminich/juice-shop:v17.3.0`, `http://localhost:3001`.

## Finding

`POST /profile` changes the logged-in user's username, authenticated purely by the `token` cookie. Pulling `routes/updateUserProfile.js` out of the container shows exactly why a forged cross-site request works:

```js
const loggedInUser = security.authenticatedUsers.get(req.cookies.token);
// ...
challengeUtils.solveIf(challenges.csrfChallenge, () => {
    return (req.headers.origin?.includes('://htmledit.squarefree.com') ?? req.headers.referer?.includes(...))
        && req.body.username !== user.username;
});
const savedUser = await user.update({ username: req.body.username });
```

The `Origin`/`Referer` check only feeds the scoreboard's own tracking, it never gates the actual update. A request carrying any Origin, forged to anything at all, still succeeds as long as the cookie is present, exactly what a victim's browser sends automatically to a malicious cross-site form with no interaction beyond loading the page.

## Classification

**CWE-352** (Cross-Site Request Forgery). **OWASP: A01:2021 - Broken Access Control.** **MITRE ATT&CK: T1185** (Browser Session Hijacking), the practical effect of riding an authenticated session the victim never consciously extended to the attacker's page.

## What was run

```bash
python items/pt13-csrf-profile-update/scenario.py                               # pre-fix, direct to :3001
python items/pt13-csrf-profile-update/proxy.py                                  # separate shell, FLATLINE_ENFORCE=1 by default
python items/pt13-csrf-profile-update/scenario.py --target http://localhost:3015 # post-fix, through the proxy
```

Each run forges the generic case (any cross-origin value) as the primary result, then separately confirms the themed origin from Juice Shop's own official walkthrough for corroboration against the real scoreboard, the same two-tier pattern pt04 and pt06 established.

## A note on a second angle that was chased, not confirmed

The username field this CSRF reaches is attacker-controlled; worth asking whether it chains into stored XSS. It mostly doesn't, at least not cleanly: Juice Shop's own persisted-XSS check is on the **email** field, unreachable through this endpoint, and testing the weaker sanitizer username falls back to under the `NODE_ENV=unsafe` override (from [pt10](../pt10-unsafe-config-reopens-sanitization/)) directly, the specific flat payload tried still got neutralized. Full account in `PREREGISTRATION.md`, kept there deliberately rather than inflating this item's own result with something only half-proven.

## The fix: check the Origin, same as a real anti-CSRF defense would

`proxy.py` rejects `POST /profile` unless its `Origin` header matches the proxy's own address, the application-layer equivalent of an Origin-checking CSRF defense. A real fix would also add a synchronizer token; this compensating control approximates the cheaper, still-effective half of that defense.

## Result

| Condition | Target | Forged-origin update | Same-origin update |
| --- | --- | --- | --- |
| No control | `http://localhost:3001` (direct) | `VULNERABLE` — succeeds, HTTP 302 | OK |
| Origin-checking proxy | `http://localhost:3015` (proxy, enforcing) | `REMEDIATED` — HTTP 403 | OK |

Raw per-run output: `results/pt13-001-*.json`. `python ledger.py verify` from the repo root confirms the hash-chained log is untampered.

## What this does not show

- Only the username field was tested; whether other state-changing endpoints authenticated purely by cookie have the same gap wasn't checked here.
- No synchronizer token was added; an Origin check alone is weaker than a full CSRF-token defense, though still a real improvement over nothing.
- Same caveats as the earlier items: one vendor image, one run, no ticket-loop integration yet.
