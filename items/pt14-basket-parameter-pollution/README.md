# pt14: HTTP Parameter Pollution on Basket Items — OWASP Juice Shop

**Status: run live, 2026-11-03.** The most structurally interesting bug in this repo, a check that's correct in isolation but reads the wrong copy of a duplicated value.

## Target

Same container as the earlier items: `bkimminich/juice-shop:v17.3.0`, `http://localhost:3001`.

## Finding

`POST /api/BasketItems` builds its basket item from a flat list of key/value pairs produced by a streaming JSON parser (`clarinet`), not `JSON.parse`. Pulling `routes/basketItems.js` straight out of the container shows why that choice matters:

```js
const basketItem = {
    ProductId: productIds[productIds.length - 1],
    BasketId: basketIds[basketIds.length - 1],   // <- LAST occurrence
    quantity: quantities[quantities.length - 1]
};
challengeUtils.solveIf(challenges.basketManipulateChallenge, () => {
    return user && basketItem.BasketId && user.bid != basketItem.BasketId;
});
```

...but the ownership check a few lines earlier reads `basketIds[0]`, the **first** occurrence:

```js
if (user && basketIds[0] && basketIds[0] !== 'undefined' && Number(user.bid) != Number(basketIds[0])) {
    res.status(401).send(...)
}
```

A body with `BasketId` repeated, the attacker's own id first, a victim's id second, satisfies the check against the first value and inserts against the last:

```bash
{"BasketId": <attacker's own id>, "ProductId": 1, "quantity": 1, "BasketId": <victim's id>}
```

The created row's own `BasketId` came back as the victim's, confirmed by Juice Shop's own "Manipulate Basket" scoreboard entry flipping on the first attempt.

## Classification

**CWE-235** (Improper Handling of Extra Parameters, HTTP Parameter Pollution). **OWASP: A01:2021 - Broken Access Control**, the practical effect. **MITRE ATT&CK: T1565.001** (Stored Data Manipulation), the impact of landing attacker-controlled rows in another account's data.

## What was run

```bash
python items/pt14-basket-parameter-pollution/scenario.py                               # pre-fix, direct to :3001
python items/pt14-basket-parameter-pollution/proxy.py                                  # separate shell, FLATLINE_ENFORCE=1 by default
python items/pt14-basket-parameter-pollution/scenario.py --target http://localhost:3016 # post-fix, through the proxy
```

The duplicate-key body can't be built from a Python `dict` (keys are unique by construction); `scenario.py` writes it as a literal string, matching exactly what the vendor's own parser receives. It also primes the attacker's token into the `authenticatedUsers` cache first, the same quirk pt01, pt09, and pt11 document (the middleware ahead of this route requires it).

## The fix: reject the pollution itself, not just this one consequence

`proxy.py` doesn't try to replicate the vendor's parser or guess which occurrence of a duplicated key is "real." It rejects any request body that names the same top-level key more than once at all, closing the HTTP Parameter Pollution directly rather than patching around one symptom of it. This is a flat-JSON-specific check (a regex over top-level `"key":` occurrences), not a general nested-JSON duplicate-key detector, stated plainly rather than overclaimed.

## Result

| Condition | Target | Duplicate-key attack | Normal request |
| --- | --- | --- | --- |
| No control | `http://localhost:3001` (direct) | `VULNERABLE` — item landed in the victim's basket | OK |
| Duplicate-key-rejecting proxy | `http://localhost:3016` (proxy, enforcing) | `REMEDIATED` — HTTP 400 | OK |

Raw per-run output: `results/pt14-001-*.json`. `python ledger.py verify` from the repo root confirms both runs are in the hash-chained log untampered.

## What this does not show

- Only `POST /api/BasketItems` was tested. `PUT /api/BasketItems/{id}` has a near-identical check in the same file and likely the same shape of bug; it wasn't separately confirmed here.
- The proxy's duplicate-key detector is a flat-JSON regex, not a real parser; a sufficiently nested or escaped body could defeat it in ways this item didn't test for.
- Same caveats as the earlier items: one vendor image, one run, no ticket-loop integration yet.
