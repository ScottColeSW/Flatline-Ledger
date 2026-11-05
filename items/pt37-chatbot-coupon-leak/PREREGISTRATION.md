# Preregistration: pt37-chatbot-coupon-leak

## Prediction

- Expected result before any fix: `VULNERABLE`. A fresh account repeating a coupon-related chatbot question (bounded to 20 attempts) eventually receives a real, working 10% discount coupon, verified by applying it to a basket.
- Expected result after the fix (a reverse proxy that replaces the coupon-issuing response with a safe refusal before it reaches the client): `REMEDIATED`. No real coupon is ever received in 20 attempts.
- Expected cost to legitimate traffic: none. An unrelated chatbot question still gets a sensible response.

## Why this one, found white-box

Read directly from `data/static/challenges.yml`: `bullyChatbotChallenge` ("Bully Chatbot"), description "Receive a coupon code from the support chatbot," hint "Just keep asking." `lib/botUtils.ts`'s `couponCode()` was pulled and read before a single chat message was sent: it unconditionally returns `security.generateCoupon(10)`, the same unkeyed z85 scheme [pt32](../pt32-forged-discount-coupon/) forges directly, with nothing gating it. `data/static/botDefaultTrainingData.json` shows this function is one of several answers rotated through for the `queries.couponCode` intent; most are refusal lines, but nothing stops the rotation from reaching the one that actually calls the function.

## A real hang, found and worked around during discovery

An early manual test sent a chatbot message with no `action` field in the body. `routes/chatbot.ts`'s `process()` only handles `req.body.action === 'query'` or `'setname'`; neither branch matches, and the handler returns without ever calling `res.send()`/`res.json()`, so the request hangs until the client times out. Confirmed this doesn't block other traffic (a concurrent request to an unrelated endpoint during the hang answered normally in 30ms), so it is not a shared-container availability risk like pt31's crash, just a client-side mistake in early testing, not a server vulnerability worth its own item: the fix here is sending a well-formed request, not a compensating control.

## Result

**Status: run live, 2026-11-05. Prediction held exactly.**

- Pre-fix: `VULNERABLE`. A real, working 10% coupon (`pes[Chz3Tq`) was received after 5 repeated requests, verified valid by applying it to a basket (`{"discount":10}`).
- Post-fix (through a proxy that replaces the coupon-issuing response with a safe refusal): `REMEDIATED`. No real coupon was received across 20 attempts; the bot never produced the function-triggered response to the client.
- Legitimate check: an unrelated chatbot question ("how much is apple juice") still got a sensible response in both conditions.

## Checked the scoreboard

`bullyChatbotChallenge` ("Bully Chatbot") flipped solved.

Raw results in `results/pt37-001-*.json`; both runs are in the repo-root hash-chained log (`python ledger.py verify`).
