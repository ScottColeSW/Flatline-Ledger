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

(Filled in after the live run.)
