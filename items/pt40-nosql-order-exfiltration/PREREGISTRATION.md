# Preregistration: pt40-nosql-order-exfiltration

## Prediction

- Expected result in `--mode safe` (default Docker deployment, port 3001): `REMEDIATED`. A boolean-true `$where` injection against the order-tracking endpoint returns at most the single synthetic placeholder result; neither of two independently-placed test orders is leaked.
- Expected result in `--mode unsafe` (the same `NODE_ENV=unsafe` config pt10 already established, port 3012): `VULNERABLE`. The same unauthenticated request returns both test orders, placed by two completely unrelated accounts, in one response.
- Expected cost to legitimate traffic: none. Tracking a real order by its own exact order id still works in both configs.

## A flag that doesn't mean what it looks like it means

`data/static/challenges.yml` marks `noSqlOrdersChallenge` ("NoSQL Exfiltration") as `disabledEnv: [Docker, Heroku]`, the same shape of flag that correctly ruled out SSTI, zip-slip, Local File Read, and NoSQL DoS earlier in this project. This one is different: `lib/challengeUtils.ts`'s `solve()`/`solveIf()` never check a challenge's own `disabledEnv` before marking it solved. `routes/trackOrder.ts`'s actual vulnerable branch is gated by `utils.isChallengeEnabled(challenges.reflectedXssChallenge)`, a **different** challenge's flag, one that carries no Docker restriction at all. Verified live, not assumed from the source read alone: `flatline-juice-shop-unsafe` (the exact container [pt10](../pt10-unsafe-config-reopens-sanitization/) already uses) returns real cross-account order data to this payload; the main container does not.

## Where this came from

[pt10](../pt10-unsafe-config-reopens-sanitization/)'s own existing exploit payload (`' || '1'=='1`) against this same endpoint already satisfies `noSqlOrdersChallenge`'s exact solve condition (returning more than one order) when run against the unsafe config, it just was never credited or formalized as its own item. This item gives it the same full predict/verify/record treatment as any deliberately-hunted finding, consistent with how pt19-pt21 formalized incidental scoreboard flips earlier in this project, and goes further than pt10's generic row count by proving the leaked rows are real orders from two specific, independently-created accounts.

## Result

(Filled in after the live run.)
