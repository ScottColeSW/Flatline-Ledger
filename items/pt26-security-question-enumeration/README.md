# pt26: Security Question Enumeration — OWASP Juice Shop

**Status: run live, 2026-11-04.** Third item in a row not in Juice Shop's own challenge catalog, a different resource and a different bug shape than pt24/pt25.

## Target

Same container as the earlier items: `bkimminich/juice-shop:v17.3.0`, `http://localhost:3001`.

## Finding

The real "Forgot Password" page calls `GET /rest/user/security-question?email=X` before it ever shows a security-question field, with no login required at any point. Typing `admin@juice-sh.op` into the real form returned its actual question (`Mother's maiden name?`); typing a made-up address returned an empty object. Registering a brand-new throwaway test account through the real UI, never touched by any Juice Shop challenge, and then querying this same endpoint for its email returned that account's exact question too, confirming the oracle isn't scoped to the handful of named NPC accounts (Bjoern, Bender, Jim, Morty, Uvogin, John, Emma) that Juice Shop's own challenges are built around.

The real problem isn't that the endpoint exists, forgot-password mechanisms have to work for someone who can't log in, it's that it has no rate limiting of any kind. A rapid burst of 10 unauthenticated requests, mixing one real test account among nine fabricated emails, all came back HTTP 200 with no throttling at all.

## Classification

**CWE-307** (Improper Restriction of Excessive Authentication Attempts). **OWASP: A07:2021 - Identification and Authentication Failures.** **MITRE ATT&CK: T1087.001** (Account Discovery), the same mapping used for pt08's enumeration finding, since the attacker is confirming which arbitrary accounts exist.

## Corroboration against source

`routes/securityQuestion.ts`:

```ts
export function securityQuestion () {
  return ({ query }: Request, res: Response, next: NextFunction) => {
    const email = query.email
    SecurityAnswerModel.findOne({
      include: [{ model: UserModel, where: { email: email?.toString() } }]
    }).then((answer) => {
      if (answer != null) {
        SecurityQuestionModel.findByPk(answer.SecurityQuestionId).then((question) => {
          res.json({ question })
        })
      } else {
        res.json({})
      }
    })
  }
}
```

No auth middleware, no rate limiting, a plain Sequelize lookup keyed on the raw query-string email. `data/static/challenges.yml` confirms the catalog's own reset-password challenges (`resetPasswordJimChallenge`, `resetPasswordBenderChallenge`, `resetPasswordBjoernChallenge`, `resetPasswordMortyChallenge`, `resetPasswordUvoginChallenge`, plus two Photo-Wall OSINT variants for John and Emma) all score *answering the question correctly for a specific named NPC*, by social-engineering their actual answer. None of them check whether the oracle that reveals *which question to even ask* can be hammered against arbitrary, non-NPC accounts. Checked the scoreboard after confirming this black-box, nothing flipped, same gap as pt24 and pt25.

## What was run

```bash
python items/pt26-security-question-enumeration/scenario.py                               # pre-fix, direct to :3001
python items/pt26-security-question-enumeration/proxy.py                                  # separate shell, FLATLINE_ENFORCE=1 by default
python items/pt26-security-question-enumeration/scenario.py --target http://localhost:3027 # post-fix, through the proxy
```

## The fix

Rejecting unauthenticated calls outright isn't an option, that's the entire point of a forgot-password flow: it has to work for someone who cannot log in. `proxy.py` throttles by caller IP instead: at most 3 requests to this endpoint per 10-second window pass through unchanged, further requests in that same window get HTTP 429 rather than an answer. A real person recovering their own forgotten account, one request per page load, is never affected; an automated sweep across many emails gets cut off after three.

## Result

| Condition | Target | 10-request burst (1 real + 9 fabricated emails) | Own forgotten-password check |
| --- | --- | --- | --- |
| No control | `http://localhost:3001` (direct) | `VULNERABLE` — all 10 answered, HTTP 200 | OK |
| IP-throttling proxy | `http://localhost:3027` (proxy, enforcing) | `REMEDIATED` — 7/10 throttled, HTTP 429 | OK |

Raw per-run output: `results/pt26-001-*.json`. `python ledger.py verify` from the repo root confirms both runs are in the hash-chained log untampered.

## What this does not show

- The throttle here is a simple in-memory per-IP fixed window; a real deployment would want this centralized (shared across proxy instances) and would likely pair it with a CAPTCHA on repeated misses, per the OWASP Forgot Password Cheat Sheet.
- This doesn't change the underlying information disclosure (an existing account vs. a nonexistent one is still distinguishable per-request), only how fast it can be swept at scale. A more complete fix would also look at making the miss/hit response shapes harder to distinguish, which this repo didn't attempt here.
- Same caveats as the earlier items: one vendor image, one run, no ticket-loop integration yet.
