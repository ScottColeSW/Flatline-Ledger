# pt32: Forged Discount Coupon — OWASP Juice Shop

**Status: run live, 2026-11-04.** Found white-box, straight from Juice Shop's own challenge catalog.

## Target

Same container as the earlier items: `bkimminich/juice-shop:v17.3.0`, `http://localhost:3001`.

## Finding

```ts
export const generateCoupon = (discount: number, date = new Date()) => {
  const coupon = utils.toMMMYY(date) + '-' + discount
  return z85.encode(coupon)
}

export const discountFromCoupon = (coupon?: string) => {
  const decoded = z85.decode(coupon)
  // ...checks decoded format and current month, returns the discount
}
```

Z85 is a public, documented, reversible encoding (the ZeroMQ Base85 variant used for binary-safe text), not encryption and not a keyed signature. There is no secret anywhere in this scheme: anyone who knows the current month and year can compute a valid coupon for any discount percentage, entirely offline, with no account and no server interaction at all.

Confirmed live: a 90%-off coupon built this way, for the current month (`NOV26`), was accepted by the server, applied to a basket, and used to complete a real checkout.

## Classification

**CWE-345** (Insufficient Verification of Data Authenticity). **OWASP: A02:2021 - Cryptographic Failures.** **No MITRE ATT&CK technique assigned**: this is a cryptographic-design/business-logic flaw (a reversible encoding used where a keyed signature belongs), not attacker tradecraft against an enterprise network; ATT&CK has no clean mapping for "forge a promotional discount code," the same honest gap [pt15](../pt15-free-deluxe-membership/) documents for a different payment-bypass flaw.

## Why this one, found white-box

Read directly from `data/static/challenges.yml`: `forgedCouponChallenge` ("Forged Coupon"), description "Forge a coupon code that gives you a discount of at least 80%." `lib/insecurity.ts` was pulled and read before a single coupon was sent. The Z85 implementation used to forge the coupon was written against the public spec and verified against the spec's own test vector (`[0x86,0x4F,0xD2,0x6F,0xB5,0x59,0xF7,0x5B]` decodes to `"HelloWorld"`) before being pointed at the real app.

## Checked the scoreboard

`forgedCouponChallenge` only flipped after completing a full checkout with the coupon applied; `order.ts` checks `discount >= 80` at order-placement time, not when the coupon is first applied to the basket. Applying the coupon alone confirmed the server accepted it (`{"discount":90}`), but didn't flip the challenge until checkout completed.

## What was run

```bash
python items/pt32-forged-discount-coupon/scenario.py                               # pre-fix, direct to :3001
python items/pt32-forged-discount-coupon/proxy.py                                  # separate shell, FLATLINE_ENFORCE=1 by default
python items/pt32-forged-discount-coupon/scenario.py --target http://localhost:3033 # post-fix, through the proxy
```

## The fix

The proxy becomes the real issuing authority the backend never had: it exposes its own `GET /rest/coupon/issue/{discount}`, which returns a coupon HMAC-signed with a secret the backend (and any attacker) never sees. On `PUT .../coupon/{coupon}`, the proxy verifies that signature itself, and only on success reconstructs the backend's own native z85 format and forwards *that* (never the attacker-supplied value) to the backend. Anything without a valid signature, including a perfectly well-formed forged z85 coupon, is rejected before the backend's decode step ever runs.

## Result

| Condition | Target | Offline-forged 90% coupon | Checkout with it applied | Signed-issuance coupon |
| --- | --- | --- | --- | --- |
| No control | `http://localhost:3001` (direct) | `VULNERABLE` — accepted, `{"discount":90}` | Succeeded | OK (native scheme, no fix yet) |
| Signed-issuance proxy | `http://localhost:3033` (proxy, enforcing) | `REMEDIATED` — `403`, rejected | Never reached | OK (via proxy's own issuance) |

Raw per-run output: `results/pt32-001-*.json`. `python ledger.py verify` from the repo root confirms both runs are in the hash-chained log untampered.

## What this does not show

- The real fix belongs in the vendored `generateCoupon`/`discountFromCoupon` pair itself (an HMAC or similar keyed signature instead of plain Z85); this proxy demonstrates the shape of that fix in front of the backend, not a patch to the vendored image.
- The proxy's signed-issuance endpoint is a stand-in for whatever real out-of-band channel (email newsletter, social media promo) a production shop would use to distribute real coupons; it doesn't model that distribution mechanism itself.
- Same caveats as the earlier items: one vendor image, one run, no ticket-loop integration yet.
