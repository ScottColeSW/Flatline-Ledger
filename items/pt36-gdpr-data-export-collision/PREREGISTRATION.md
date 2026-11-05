# Preregistration: pt36-gdpr-data-export-collision

## Prediction

- Expected result before any fix: `VULNERABLE`. An account that has placed no orders of its own, registered with an email chosen to vowel-redact identically to a victim's, requests its own GDPR data export and receives the victim's real order in the response.
- Expected result after the fix (a reverse proxy that tracks real order ownership itself, by caller email, as orders are placed through it, and filters the export down to only those): `REMEDIATED`. The same export no longer includes the victim's order.
- Expected cost to legitimate traffic: none. An account's own export still includes its own real orders.

## Why this one, found white-box

Read directly from `data/static/challenges.yml`: `dataExportChallenge` ("GDPR Data Theft"), description "Steal someone else's personal data without using Injection," hint "trick the regular Data Export to give you more than actually belongs to you." `routes/dataExport.ts` was pulled and read before a single export was requested:

```ts
const updatedEmail = email.replace(/[aeiou]/gi, '*')
db.ordersCollection.find({ email: updatedEmail })
```

`routes/order.ts` stores orders under this same redacted form. Two accounts whose email local-parts redact identically, two all-vowel local parts sharing the same other characters are the simplest case, collide completely in this lookup.

## Result

**Status: run live, 2026-11-04. Prediction held exactly.**

- Pre-fix: `VULNERABLE`. An attacker account with no orders of its own, email chosen to redact identically to a victim's, received the victim's real order in its own export.
- Post-fix (through a proxy tracking real order ownership by caller email as orders are placed through it): `REMEDIATED`. The same export no longer included the victim's order.
- Legitimate check: the victim's own export still included their own real order in both conditions.

## Checked the scoreboard

`dataExportChallenge` ("GDPR Data Theft") flipped solved.

Raw results in `results/pt36-001-*.json`; both runs are in the repo-root hash-chained log (`python ledger.py verify`).
