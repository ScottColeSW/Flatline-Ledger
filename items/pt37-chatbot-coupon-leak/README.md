# pt37: Chatbot Hands Out a Real Coupon If You Keep Asking — OWASP Juice Shop

**Status: run live, 2026-11-05.** Found white-box, straight from Juice Shop's own challenge catalog.

## Target

Same container as the earlier items: `bkimminich/juice-shop:v17.3.0`, `http://localhost:3001`.

## Finding

```ts
export function couponCode (query: string, user: string) {
  challengeUtils.solveIf(challenges.bullyChatbotChallenge, () => { return true })
  return {
    action: 'response',
    body: `Oooookay, if you promise to stop nagging me here's a 10% coupon code for you: ${security.generateCoupon(10)}`
  }
}
```

No authorization check, no rate limit, no record of who's already received one, nothing. This function is one of several answers the bot can give for its `queries.couponCode` intent, most of the others are canned refusal lines, but the bot's answer-rotation logic cycles through them, and nothing stops it from eventually landing on the one that's a real function call. Repeating a coupon-related question a handful of times reaches it.

Confirmed live: a fresh test account received a real, working 10% coupon after 5 repeated requests. The coupon was verified genuinely valid by applying it to a basket, which returned `{"discount":10}`, the same discount-generation scheme [pt32](../pt32-forged-discount-coupon/) forges directly by computing the encoding offline.

## Classification

**CWE-840** (Business Logic Errors), the same CWE [pt15](../pt15-free-deluxe-membership/) uses for a different payment-adjacent business-logic flaw. **OWASP: A04:2021 - Insecure Design.** **No MITRE ATT&CK technique assigned**: social-engineering a chatbot into handing out a real coupon is not attacker tradecraft against an enterprise network; ATT&CK has no clean mapping, same honest gap pt32 documents for the cryptographic side of this exact coupon scheme.

## Why this one, found white-box

Read directly from `data/static/challenges.yml`: `bullyChatbotChallenge` ("Bully Chatbot"), description "Receive a coupon code from the support chatbot," hint "Just keep asking." `lib/botUtils.ts` was pulled and read before a single chat message was sent.

## A real hang, found and worked around during discovery

An early manual test sent a chatbot message with no `action` field in the request body. `routes/chatbot.ts`'s `process()` only branches on `req.body.action === 'query'` or `'setname'`; neither matched, and the handler returned without ever sending a response, so the request hung until the client timed out. Checked whether this blocks the whole server: a concurrent request to an unrelated endpoint during the hang answered normally in 30ms, so it's isolated to the one malformed request, not a shared-container availability risk like [pt31](../pt31-wallet-checkout-crash/)'s crash. This was a mistake in early manual testing (missing a required field), not a server vulnerability worth its own item; the actual exploit scripted below always sends a well-formed `action`.

## Checked the scoreboard

`bullyChatbotChallenge` flipped solved.

## What was run

```bash
python items/pt37-chatbot-coupon-leak/scenario.py                               # pre-fix, direct to :3001
python items/pt37-chatbot-coupon-leak/proxy.py                                  # separate shell, FLATLINE_ENFORCE=1 by default
python items/pt37-chatbot-coupon-leak/scenario.py --target http://localhost:3038 # post-fix, through the proxy
```

## The fix

`proxy.py` inspects every chatbot response before it reaches the client: if it matches the coupon-issuing pattern, it's swapped for one of the bot's own legitimate refusal lines instead, so a real coupon is never handed out through this channel at all. Every other chatbot interaction (naming, product-price lookups, ordinary conversation) is untouched.

## Result

| Condition | Target | Repeated coupon requests | Unrelated chatbot question |
| --- | --- | --- | --- |
| No control | `http://localhost:3001` (direct) | `VULNERABLE` — real coupon received in 5 attempts | OK |
| Response-filtering proxy | `http://localhost:3038` (proxy, enforcing) | `REMEDIATED` — no coupon in 20 attempts | OK |

Raw per-run output: `results/pt37-001-*.json`. `python ledger.py verify` from the repo root confirms both runs are in the hash-chained log untampered.

## What this does not show

- The real fix belongs in `botUtils.ts`'s `couponCode()` itself (remove the function entirely, or gate it behind a real promotional-eligibility check); this proxy demonstrates that fix at the response layer, not a patch to the vendored image.
- The underlying coupon scheme is the same weak, unkeyed encoding pt32 already covers in depth; this item is about the chatbot being an additional, even less-protected way to reach it, not a second analysis of the encoding itself.
- Same caveats as the earlier items: one vendor image, one run, no ticket-loop integration yet.
