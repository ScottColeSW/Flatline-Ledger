# pt31: Insufficient-Funds Checkout Crashes the Whole Server — OWASP Juice Shop

**Status: run live, 2026-11-04.** The most severe finding in this repo so far: not a crafted exploit, the single most ordinary checkout failure a web shop can have. Found by accident while building [pt30](../pt30-negative-quantity-wallet-exploit/), run safely in isolation here.

## Target

`bkimminich/juice-shop:v17.3.0`, started a second time as `flatline-juice-shop-unsafe` on `http://localhost:3012`, deliberately isolated from the main container every other item in this repo uses, because this item's pre-fix run crashes its target by design.

## Finding

Order checkout generates a PDF receipt on a write stream, and separately checks the caller's wallet balance when `paymentId` is `"wallet"`:

```ts
fileWriter.on('finish', async () => {
  // ...eventually: res.json({ orderConfirmation: orderId })
})
// ...later, independently:
if ((wallet != null) && wallet.balance >= totalPrice) {
  WalletModel.decrement({ balance: totalPrice }, ...)
} else {
  next(new Error('Insufficient wallet balance.'))
}
```

Both paths can independently try to send a response to the same request. Nothing coordinates which one runs first; whichever runs second throws `ERR_HTTP_HEADERS_SENT`, uncaught anywhere in the call chain, which terminates the entire Node process. Not a race that needs careful timing to trigger, every single insufficient-balance checkout hits it.

Confirmed live: an account with a $0 wallet added one item to its basket, checked out with `paymentId: "wallet"`, got `HTTP 500`, and the container was completely unreachable on a follow-up request one second later.

## Where this came from

Discovered by accident. The shared `flatline-juice-shop` container crashed twice while building and testing pt30, each time traced in its own logs to `Insufficient wallet balance` at `order.js:160` immediately followed by the uncaught exception. Rather than leave that as an incidental footnote in pt30's writeup, it was isolated and reproduced deliberately, on the `-unsafe` container, with the smallest possible trigger.

## Classification

**CWE-248** (Uncaught Exception). **OWASP: A04:2021 - Insecure Design**, two independent response paths with no coordination is an architectural flaw, not a missing input check. **MITRE ATT&CK: T1499.004** (Endpoint Denial of Service: Application or System Exploitation).

## Not in Juice Shop's own challenge catalog

Checked `data/static/challenges.yml` for anything matching wallet or checkout crashes; nothing is tracked. Fifth item now (after [pt24](../pt24-address-idor-on-update/), [pt25](../pt25-complaint-enumeration/), [pt26](../pt26-security-question-enumeration/), [pt28](../pt28-login-bruteforce-no-monitoring/)) found outside Juice Shop's own 109-item catalog, and the most severe of the five.

## What was run

```bash
python items/pt31-wallet-checkout-crash/scenario.py                               # pre-fix, direct to :3012 (unsafe container)
python items/pt31-wallet-checkout-crash/proxy.py                                  # separate shell, FLATLINE_ENFORCE=1 by default, FLATLINE_BACKEND=http://localhost:3012
python items/pt31-wallet-checkout-crash/scenario.py --target http://localhost:3032 # post-fix, through the proxy
```

After the pre-fix (`VULNERABLE`) run, `docker start flatline-juice-shop-unsafe` was run and the container's health verified before anything else touched it.

## The fix

The proxy re-implements the same balance check the backend does, in front of it, where a failure returns a clean error instead of crashing anything: on a wallet-paid checkout, it reads the caller's own basket contents and wallet balance (using the caller's own Authorization header) and estimates the order total (`price × quantity` per item, deliberately not replicating delivery fees or coupon discounts, so it's conservative, never blocking a legitimate sufficiently-funded order). If that estimate exceeds the balance, the checkout is rejected with `402` before it ever reaches the crash-prone backend path.

## Result

| Condition | Target | Insufficient-funds checkout | Server reachable after | Funded ($50 wallet) checkout |
| --- | --- | --- | --- | --- |
| No control | `http://localhost:3012` (direct) | `VULNERABLE` — `500`, then unreachable | No | N/A (server down) |
| Pre-check proxy | `http://localhost:3032` (proxy, enforcing) | `REMEDIATED` — `402`, clean | Yes | Succeeded (`200`) |

Raw per-run output: `results/pt31-001-*.json`. `python ledger.py verify` from the repo root confirms both runs are in the hash-chained log untampered.

## What this does not show

- The real fix belongs in `order.ts` itself (coordinate the two response paths, e.g. check the balance before starting the PDF stream at all); this proxy is a front-of-backend mitigation, not a patch to the vendored image.
- The proxy's total estimate is intentionally conservative (ignores delivery fees and discounts); a basket whose true total, including those, exceeds the balance by less than the item-only estimate suggests could still reach the backend and crash it. A production fix would need the real pricing logic, not an approximation.
- Same caveats as the earlier items: one vendor image, one run, no ticket-loop integration yet.
