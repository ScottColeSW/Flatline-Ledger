# Preregistration: pt29-nosql-review-injection

## Prediction

- Expected result before any fix: `VULNERABLE`. A single authenticated `PATCH /rest/products/reviews` using a MongoDB `$in` operator in `id` instead of a plain string overwrites a review belonging to a different account, with `modified: 2` confirming both targeted documents changed in one call.
- Expected result after the fix (a reverse proxy rejecting any non-string `id` on this endpoint): `REMEDIATED`. The same request comes back `400` before reaching the backend.
- Expected cost to legitimate traffic: none. A normal update to one's own review by its real, exact string `_id` still succeeds in both conditions.

## A real mistake made and corrected during initial discovery

The scripted scenario above deliberately scopes its proof to two self-created test reviews. That restraint exists because the first, manual black-box confirmation did not have it: sending `{"id": {"$ne": null}, "message": "PWNED-BY-PT29-..."}` as an authenticated `PATCH` matched `_id: {$ne: null}` against the **entire reviews collection**, not just the caller's own data, and overwrote the `message` field of all 38 reviews in the running container, every product, every account, including real seeded content from the vendor's own fixtures and reviews created by earlier items (pt22, pt23).

The backend's own response included an `original` array with every document's pre-update state (message, author, product, likesCount, likedBy, and `_id`). That response was used immediately to write a one-off restoration script (`scratch/pt29-restore-reviews.py`, not committed, gitignored scratch) that replayed a normal single-`_id` `PATCH` for each of the 38 reviews, putting its real message back. Restoration was verified by re-fetching several products' review lists afterward and confirming the original text, including one review with emoji content, matched exactly. 38/38 restored.

The lesson, consistent with pt16's and pt24's own prior mistakes: when a vulnerability's blast radius is "every row this filter can match," confirm the filter's actual reach black-box with the narrowest possible payload first (or capture full before/after state, as happened here by luck of the response shape), rather than the broadest operator, before running anything live against a shared container.

## Why this one, found white-box

Rather than guessing black-box, this item came from reading the full OWASP Juice Shop challenge catalog's unsolved list against this app's own source, after Scott suggested white-boxing the remaining work: pulling `routes/updateProductReviews.ts` directly showed `db.reviewsCollection.update({ _id: req.body.id }, ...)` with no type check on `id` and no ownership check against the caller, before any request was sent.

## Corroboration against source

```ts
db.reviewsCollection.update(
  { _id: req.body.id },
  { $set: { message: req.body.message } },
  { multi: true }
)
```

No validation that `req.body.id` is a string, no check that `security.authenticatedUsers.from(req)` (captured only for an unrelated challenge check) owns the targeted review(s). Juice Shop's own `noSqlReviewsChallenge` ("NoSQL Manipulation") only requires `result.modified > 1`, satisfied by the same `$in`-over-two-ids proof this item's scripted scenario uses; it says nothing about the unscoped `$ne: null` blast radius confirmed by hand.

## Result

(Filled in after the live run.)
