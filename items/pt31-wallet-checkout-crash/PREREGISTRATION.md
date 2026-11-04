# Preregistration: pt31-wallet-checkout-crash

## Prediction

- Expected result before any fix: `VULNERABLE`. A single, completely ordinary checkout (one basket item, no delivery method, a $0 wallet, `paymentId: "wallet"`) returns HTTP 500, and the entire backend process becomes unreachable immediately afterward.
- Expected result after the fix (a reverse proxy that re-implements the same wallet-balance check in front of the backend, rejecting cleanly instead): `REMEDIATED`. The same checkout is rejected with `402` before it ever reaches the crash-prone code path, and the server stays reachable.
- Expected cost to legitimate traffic: none. A checkout whose wallet balance covers the order total still succeeds in both conditions.

## Run only against the isolated container

This item's pre-fix run crashes its target by design. Both `scenario.py` and `proxy.py` default to `flatline-juice-shop-unsafe` (port 3012), not the shared `flatline-juice-shop` container every other item in this repo uses. After any `VULNERABLE` result, restart the target with `docker start flatline-juice-shop-unsafe` before running anything else against it.

## Where this came from

Discovered by accident while building [pt30](../pt30-negative-quantity-wallet-exploit/): the shared `flatline-juice-shop` container crashed twice during that item's own testing, each time traced in its logs to `Insufficient wallet balance` at `order.js:160` immediately followed by an uncaught `ERR_HTTP_HEADERS_SENT`. Rather than leave that as an incidental footnote, it was isolated and reproduced on its own, deliberately on the `-unsafe` container, with the smallest possible trigger: a normal checkout failure, not a crafted payload.

## Corroboration against source

`routes/order.ts` writes the order's PDF receipt to a stream and, separately, checks the wallet balance:

```ts
fileWriter.on('finish', async () => {
  // ... eventually: res.json({ orderConfirmation: orderId })
})
// ... later, independently:
if ((wallet != null) && wallet.balance >= totalPrice) {
  WalletModel.decrement({ balance: totalPrice }, ...)
} else {
  next(new Error('Insufficient wallet balance.'))
}
```

Both paths can independently try to send a response to the same request, with nothing coordinating which one runs first. Whichever runs second throws `ERR_HTTP_HEADERS_SENT`, uncaught anywhere in the call chain, which terminates the Node process.

## Not in Juice Shop's own challenge catalog

Checked `data/static/challenges.yml` for anything matching wallet or checkout crashes; nothing is tracked. Fifth item now (after pt24, pt25, pt26, pt28) found outside Juice Shop's own 109-item catalog, and the most severe of the five: a complete denial of service, triggerable by any logged-in account with no special privileges, from the single most ordinary failure mode a checkout flow can have.

## Result

(Filled in after the live run.)
