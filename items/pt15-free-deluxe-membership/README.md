# pt15: Free Deluxe Membership — OWASP Juice Shop

**Status: run live, 2026-11-03.** A business-logic flaw this time, not an injection, a forgery, or a missing access check.

## Target

Same container as the earlier items: `bkimminich/juice-shop:v17.3.0`, `http://localhost:3001`.

## Finding

`POST /rest/deluxe-membership` is supposed to charge $49 and upgrade an account. Pulling `routes/deluxe.js` out of the container shows the actual control flow:

```js
if (req.body.paymentMode === 'wallet') {
    // check wallet balance, decrement it
}
if (req.body.paymentMode === 'card') {
    // validate the card
}
// ...upgrade the account regardless, no matter what happened above
const updatedUser = await user.update({ role: security.roles.deluxe, deluxeToken: ... });
```

Both payment checks are `if` statements with no matching `else`. A `paymentMode` that is neither exactly `"wallet"` nor `"card"`, including the field being absent entirely, satisfies neither condition, so neither block ever runs, and the upgrade happens anyway. `POST /rest/deluxe-membership` with an empty body (`{}`) returned a new session token decoding to `role: deluxe`. No wallet debit, no card check, nothing charged. Confirmed by Juice Shop's own "Deluxe Fraud" scoreboard entry flipping on the first attempt.

## Classification

**CWE-840** (Business Logic Errors), primary. **CWE-20** (Improper Input Validation), secondary, matching the official catalog's own categorization of this challenge. **OWASP: A04:2021 - Insecure Design**, a default-deny branch for an unrecognized payment mode was never written, a design gap, not a single missing guard. **No MITRE ATT&CK technique is assigned**, see `PREREGISTRATION.md` for why, the same kind of honest gap pt05 documents.

## What was run

```bash
python items/pt15-free-deluxe-membership/scenario.py                               # pre-fix, direct to :3001
python items/pt15-free-deluxe-membership/proxy.py                                  # separate shell, FLATLINE_ENFORCE=1 by default
python items/pt15-free-deluxe-membership/scenario.py --target http://localhost:3017 # post-fix, through the proxy
```

The legitimate check here is a full real payment, not a stand-in: `scenario.py` registers an account, adds a real card (`expYear` must satisfy the model's own validation, `2080`-`2099`), tops up the wallet through that card via `PUT /rest/wallet/balance`, then performs a genuine `paymentMode: "wallet"` upgrade and confirms it succeeds, built and verified end to end rather than assumed to work.

## The fix: an allowlist where the vendor's code had none

`proxy.py` rejects `POST /rest/deluxe-membership` outright unless `paymentMode` is exactly `"wallet"` or `"card"`, the default-deny branch missing from the original code.

## Result

| Condition | Target | Unrecognized payment mode | Real paid upgrade |
| --- | --- | --- | --- |
| No control | `http://localhost:3001` (direct) | `VULNERABLE` — upgraded for free | OK |
| Payment-mode allowlist | `http://localhost:3017` (proxy, enforcing) | `REMEDIATED` — HTTP 400 | OK |

Raw per-run output: `results/pt15-001-*.json`. `python ledger.py verify` from the repo root confirms both runs are in the hash-chained log untampered.

## What this does not show

- Whether the card-mode payment branch has its own equivalent gap (an expired or malformed card that still slips through) wasn't separately tested here, only the no-mode and real-wallet cases were.
- Same caveats as the earlier items: one vendor image, one run, no ticket-loop integration yet.
