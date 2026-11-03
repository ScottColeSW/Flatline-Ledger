# pt12: Mass Assignment on Registration — OWASP Juice Shop

**Status: run live, 2026-11-03.** The only item in this repo that needs zero prior access of any kind.

## Target

Same container as the earlier items: `bkimminich/juice-shop:v17.3.0`, `http://localhost:3001`.

## Finding

`POST /api/Users`, the public signup form, no authentication required to reach it at all, accepts a `role` field in the request body and assigns it outright:

```bash
curl -X POST http://localhost:3001/api/Users -H "Content-Type: application/json" \
  -d '{"email":"anyone@flatline.test","password":"...","passwordRepeat":"...","role":"admin"}'
```

The account that comes back is a genuine admin: logging in immediately after returns a JWT whose `data.role` is `admin`, same `defaultAdmin.png` profile image the real admin account uses. Confirmed in Juice Shop's own solve condition (`build/routes/verify.js`):

```js
challengeUtils.solveIf(challenges.registerAdminChallenge, () => { return req.body && req.body.role === security.roles.admin; });
```

## Classification

**CWE-915** (Improperly Controlled Modification of Dynamically-Determined Object Attributes, mass assignment). **OWASP: A04:2021 - Insecure Design**, the registration handler trusting whichever fields a client includes is a design choice, not a single missing check. **MITRE ATT&CK: T1136.001** (Create Account: Local Account), with the immediate privilege already attached at creation, no escalation step needed afterward.

## What was run

```bash
python items/pt12-mass-assignment-admin-registration/scenario.py                               # pre-fix, direct to :3001
python items/pt12-mass-assignment-admin-registration/proxy.py                                  # separate shell, FLATLINE_ENFORCE=1 by default
python items/pt12-mass-assignment-admin-registration/scenario.py --target http://localhost:3014 # post-fix, through the proxy
```

Each run registers a fresh throwaway account with `role: admin` in the body, logs in, and decodes the resulting JWT's own claim rather than trusting the registration response alone.

## The fix: strip the field, same as pt11's approach

`proxy.py` deletes `role` from the registration body entirely before forwarding, rather than rejecting requests that include it, consistent with pt11's "correct, don't reject" compensating control. Registration still succeeds; it just can no longer self-assign a privilege level.

## Result

| Condition | Target | Exploit registration | Normal registration |
| --- | --- | --- | --- |
| No control | `http://localhost:3001` (direct) | `VULNERABLE` — resulting role: `admin` | role: `customer` |
| Role-stripping proxy | `http://localhost:3014` (proxy, enforcing) | `REMEDIATED` — resulting role: `customer` | role: `customer` |

Raw per-run output: `results/pt12-001-*.json`. `python ledger.py verify` from the repo root confirms both runs are in the hash-chained log untampered.

## What this does not show

- Only the `role` field was tested; other privileged fields on the same model (`deluxeToken`, for instance) weren't checked for the same mass-assignment pattern.
- Same caveats as the earlier items: one vendor image, one run, no ticket-loop integration yet.
