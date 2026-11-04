# Preregistration: pt32-forged-discount-coupon

## Prediction

- Expected result before any fix: `VULNERABLE`. A coupon computed entirely offline, for 90% off, for the current month, with no account and no server interaction to generate it, is accepted and applied to a basket.
- Expected result after the fix (a reverse proxy that issues and verifies HMAC-signed coupons itself, translating only valid ones into the backend's native format): `REMEDIATED`. The same forged coupon is rejected with `403` before the backend ever decodes it.
- Expected cost to legitimate traffic: none. A coupon obtained through the proxy's own signed-issuance endpoint, standing in for the shop's real promotional channel, still applies correctly.

## Why this one, found white-box

Read directly from `data/static/challenges.yml`: `forgedCouponChallenge` ("Forged Coupon"), description "Forge a coupon code that gives you a discount of at least 80%." `lib/insecurity.ts` was pulled and read before a single coupon was ever sent: `generateCoupon` is `z85.encode(MMMYY + '-' + discount)`, `discountFromCoupon` just reverses it. Z85 is a public, documented, reversible encoding (the ZeroMQ Base85 variant), not encryption, not a signature. The z85 implementation used here was written against the public spec and verified against the spec's own test vector (`[0x86,0x4F,0xD2,0x6F,0xB5,0x59,0xF7,0x5B]` -> `"HelloWorld"`) before being used against the real app.

## Result

(Filled in after the live run.)
