# pt29: NoSQL Injection on Product Review Updates — OWASP Juice Shop

**Status: run live, 2026-11-04.** Found white-box: after surveying Juice Shop's full 109-item challenge catalog against this app's own source, instead of continuing to guess black-box.

## Target

Same container as the earlier items: `bkimminich/juice-shop:v17.3.0`, `http://localhost:3001`.

## Finding

`PATCH /rest/products/reviews` passes `req.body.id` straight into a marsdb (NoSQL) filter with no type check and no ownership check against the caller:

```ts
db.reviewsCollection.update(
  { _id: req.body.id },
  { $set: { message: req.body.message } },
  { multi: true }
)
```

A plain string `id` targets one review, as the real frontend always sends. A MongoDB-style query operator in its place reaches however many documents that operator matches, regardless of who owns them, in a single authenticated request.

## A real mistake made and corrected during discovery

The scripted scenario below deliberately targets exactly two self-created test reviews by their own `_id` values via the `$in` operator. That restraint exists because the first, manual confirmation of this bug didn't have it: sending `id: {"$ne": null}` matched and overwrote the `message` field of **all 38 reviews in the running container**, every product, every account, including real vendor-seeded content and reviews from earlier items. That response happened to include an `original` array with every document's pre-update state, which was used immediately to restore all 38 reviews to their real values, verified by re-fetching several products' review lists afterward. Same discipline pt16 and pt24 document for their own mistakes: a filter's actual reach should be confirmed with the narrowest payload first, not the broadest, before running anything live against shared data.

## Classification

**CWE-943** (Improper Neutralization of Special Elements in Data Query Logic). **OWASP: A03:2021 - Injection.** **MITRE ATT&CK: T1565.001** (Stored Data Manipulation).

## Why this one, found white-box

Scott suggested surveying the full challenge catalog against source first, rather than continuing ad hoc black-box exploration (which had just spent real time chasing an SSTI challenge, [see below](#a-related-dead-end-this-session-ssti)). Reading `data/static/challenges.yml`'s unsolved list against `routes/updateProductReviews.ts` directly showed the missing type check before any request was ever sent.

## Checked the scoreboard

`noSqlReviewsChallenge` ("NoSQL Manipulation") flipped solved, so this one is in Juice Shop's own catalog, unlike pt24, pt25, pt26, and pt28. Its description, "update multiple product reviews at the same time," only requires `modified > 1`; it doesn't capture that the same mechanism reaches the *entire* collection with the right operator, which the manual discovery run confirmed directly.

## What was run

```bash
python items/pt29-nosql-review-injection/scenario.py                               # pre-fix, direct to :3001
python items/pt29-nosql-review-injection/proxy.py                                  # separate shell, FLATLINE_ENFORCE=1 by default
python items/pt29-nosql-review-injection/scenario.py --target http://localhost:3030 # post-fix, through the proxy
```

## The fix

The real frontend only ever sends a plain string `id` for the one review being edited. `proxy.py` rejects any request to this endpoint whose `id` field is not a string, `400`, before it ever reaches the backend. A normal single-review update by its exact `_id` is completely unaffected.

## Result

| Condition | Target | `$in`-scoped injection (2 self-created reviews) | Own-review update by exact `_id` |
| --- | --- | --- | --- |
| No control | `http://localhost:3001` (direct) | `VULNERABLE` — both updated, 1 belonging to a different account | OK |
| Type-check proxy | `http://localhost:3030` (proxy, enforcing) | `REMEDIATED` — `400`, nothing touched | OK |

Raw per-run output: `results/pt29-001-*.json`. `python ledger.py verify` from the repo root confirms both runs are in the hash-chained log untampered.

## A related dead end this session: SSTI

Before this item, the same catalog survey turned up a server-side `eval()` call in `routes/userProfile.ts` triggered by a username containing `#{...}` (the real mechanism behind Juice Shop's "CSP Bypass" / `usernameXssChallenge`). Checking `challenges.yml` for that challenge showed `disabledEnv: [Docker, Heroku, Gitpod]`, the same gate that blocked pt24's zip-slip attempt; the vulnerability is real in source but unreachable in this environment, so no live item was built for it. Checking that flag *before* spending time building a payload, rather than after black-box testing failed to reproduce it, is the whole point of white-boxing first.

## What this does not show

- This fix only addresses the type-confusion angle (object vs. string). The underlying lack of any ownership check on single-`_id` updates is a separate, already-present gap in this endpoint that this item doesn't attempt to close.
- Same caveats as the earlier items: one vendor image, one run, no ticket-loop integration yet.
