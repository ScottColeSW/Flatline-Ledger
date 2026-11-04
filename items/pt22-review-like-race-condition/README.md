# pt22: Review Like Race Condition — OWASP Juice Shop

**Status: run live, 2026-11-04.** The first item found black-box first, source read only afterward to corroborate.

## Target

Same container as the earlier items: `bkimminich/juice-shop:v17.3.0`, `http://localhost:3001`.

## How this was found

Through the actual UI, clicking a product's reviews open showed every review's like button already lit green, as if already liked, for a brand-new account that had never touched any of them. A plain, fully anonymous `curl` request to `GET /rest/products/1/reviews` showed the same thing: `"liked": true` on every review, no auth at all. Odd enough to chase directly: firing 10 real concurrent requests (OS threads, not a sequential loop) from one account against one review produced **10 successful likes** from that single account, confirmed by reading `likedBy` back afterward, not by trusting the responses alone.

Only then was the source pulled to see why:

```js
const likedBy = review.likedBy;
if (likedBy.includes(user.data.email)) {
    return res.status(403).json({ error: 'Not allowed' });
}
await db.reviewsCollection.update({ _id: id }, { $inc: { likesCount: 1 } });
// Artificial wait for timing attack challenge
await sleep(150);
// ...only now does it push user.data.email into likedBy and write it back
```

A classic check-then-act race: the "already liked" check reads `likedBy` before the sleep, every concurrent request sees the same stale array and passes, and the actual write happens 150ms later for each. The vendor's own comment admits the delay is deliberate, built for exactly this challenge.

## Classification

**CWE-362** (Concurrent Execution using Shared Resource with Improper Synchronization, "Race Condition"). **OWASP: A04:2021 - Insecure Design**; Juice Shop's own catalog files this under "Broken Anti Automation," not a 2021 Top 10 category on its own, A04 is the closest real match for a TOCTOU design flaw. **No MITRE ATT&CK technique assigned**, race-condition exploitation to inflate a counter has no clean mapping, the same honest gap pt05, pt15, and pt20 document.

## What was run

```bash
python items/pt22-review-like-race-condition/scenario.py                               # pre-fix, direct to :3001
python items/pt22-review-like-race-condition/proxy.py                                  # separate shell, FLATLINE_ENFORCE=1 by default
python items/pt22-review-like-race-condition/scenario.py --target http://localhost:3023 # post-fix, through the proxy
```

Each run creates a fresh review, fires 10 real concurrent like requests from one attacker account (`threading`, not sequential calls, since the whole point is overlapping requests), then reads `likedBy` back from the server to count that account's actual entries, never trusting the per-request response alone.

## The fix: close the window at the edge, since the backend's own race can't be patched from outside

`proxy.py` can't fix the backend's check-then-sleep-then-write sequence from the outside, so it closes the race a layer earlier instead: a lock-guarded in-memory set tracks `(caller_email, review_id)` pairs currently in flight or already completed, and any request for a pair already in that set is rejected immediately, before it ever reaches the backend to race its own sleep.

## Result

| Condition | Target | 10 concurrent likes | Single like |
| --- | --- | --- | --- |
| No control | `http://localhost:3001` (direct) | `VULNERABLE` — 10/10 succeeded | OK |
| Request-serializing proxy | `http://localhost:3023` (proxy, enforcing) | `REMEDIATED` — 1/10 succeeded, 9 rejected (403) | OK |

Raw per-run output: `results/pt22-001-*.json`. `python ledger.py verify` from the repo root confirms both runs are in the hash-chained log untampered.

## What this does not show

- 10 concurrent requests was enough to demonstrate the race reliably on this machine; a slower or faster environment might need a different count to reproduce consistently.
- The proxy's own in-memory lock doesn't survive a restart and wouldn't scale across multiple proxy instances; a real fix belongs in the backend's own atomic update (e.g. a single `findOneAndUpdate` with the "not already liked" condition baked into the query), not a compensating control.
- Same caveats as the earlier items: one vendor image, one run, no ticket-loop integration yet.
