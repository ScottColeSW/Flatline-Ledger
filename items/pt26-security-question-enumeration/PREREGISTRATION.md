# Preregistration: pt26-security-question-enumeration

## Prediction

- Expected result before any fix: `VULNERABLE`. A 10-request burst of unauthenticated calls to `GET /rest/user/security-question?email=X`, mixing one real registered test account among nine fabricated emails, all answer with HTTP 200 and no throttling, including a successful leak of the real account's security question.
- Expected result after the fix (a reverse proxy throttling by caller IP, 3 requests per 10-second window): `REMEDIATED`. Some of the 10 burst requests come back HTTP 429 instead of an answer.
- Expected cost to legitimate traffic: none. A single isolated query for one's own email, the shape of the real forgot-password page (one request per page load), still succeeds in both conditions.

## Why this one, found black-box

The "Forgot Password" page calls `GET /rest/user/security-question?email=X` with no login before it shows the security-question field. Typing a known account's email (`admin@juice-sh.op`) returned its real question. Typing a made-up email returned `{}`. Registering a brand-new throwaway test account through the real UI and then querying this same endpoint for its email returned that account's question too, proving the oracle works for any registered account, not only the small set of named NPCs (Bjoern, Bender, Jim, Morty, Uvogin) Juice Shop's own challenge catalog is built around social-engineering.

## Corroboration against source

`routes/securityQuestion.ts` has no auth middleware and no rate limiting at all: a Sequelize lookup keyed on the raw query-string email, `res.json({question})` on a hit, `res.json({})` on a miss. `data/static/challenges.yml` confirms the catalog only scores resetting the six named NPC accounts by guessing *the answer* to a question you already know; nothing in it checks whether the oracle that reveals *which question to even ask* can be hammered against arbitrary accounts.

## Checked the scoreboard

No entry flipped from running the burst against a fresh, non-NPC test account; this is a genuine gap, the same shape as pt24 and pt25: a real, broader vulnerability outside anything Juice Shop itself tracks.

## Result

**Status: run live, 2026-11-04. Prediction held exactly.**

- Pre-fix: `VULNERABLE`. All 10 burst requests (1 real registered test account + 9 fabricated emails) answered HTTP 200, no throttling, including a successful leak of the real account's security question.
- Post-fix (through a proxy throttling by caller IP, 3 requests / 10s window): `REMEDIATED`, 7 of 10 burst requests came back HTTP 429.
- Legitimate check: a single isolated query for the victim's own email, run after the throttle window reset, still returned HTTP 200 with the correct security question in both conditions.

## Not in Juice Shop's own challenge catalog, third item in a row

Checked the live scoreboard after confirming this. No new entry flipped. Three items in a row now (pt24, pt25, pt26) found purely by black-box testing that aren't among Juice Shop's 109 tracked challenges at all.

Raw results in `results/pt26-001-*.json`; both runs are in the repo-root hash-chained log (`python ledger.py verify`).
