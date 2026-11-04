# Preregistration: pt25-complaint-enumeration

**Status: run live, 2026-11-04. Prediction held exactly.**

## Prediction

- Expected result before any fix: `VULNERABLE` (any authenticated account's complaint list includes everyone's)
- Expected result after the fix: `REMEDIATED`
- Expected cost to legitimate traffic: none, an account must still see its own complaint.

## Result

- Pre-fix: `VULNERABLE`. A victim account's distinctly-marked complaint showed up in a completely unrelated attacker account's own `GET /api/Complaints` list, alongside a real seeded complaint from the running container's own data.
- Post-fix (through a proxy that tracks ownership the backend never recorded): `REMEDIATED`, the attacker's list no longer included it.
- Legitimate check: the victim's own list still included their own complaint in both conditions.

## Not in Juice Shop's own challenge catalog, same as pt24

Checked the live scoreboard after confirming this. No new entry flipped. Two items in a row now (pt24, pt25) found purely by black-box testing that aren't among Juice Shop's 109 tracked challenges at all.

## A fix shaped differently than any before it

Every earlier access-control fix in this repo could lean on an ownership field the backend already had and simply failed to check (`UserId`, `author`, and so on). This one can't: `POST /api/Complaints` never records who submitted a complaint at all (`UserId` comes back `null` regardless of caller). The compensating control had to add state the backend never kept, tracking `(message, submitter)` pairs itself at POST time, then filtering GET by that self-maintained map. This means the fix can only scope complaints submitted *through the proxy* while it has been running; the one real seeded complaint, submitted before the proxy ever existed, has no recorded owner and is hidden from everyone under the fix rather than guessed at or left visible to all. Stated plainly in the item's own README rather than left for a reader to notice.

Raw results in `results/pt25-001-*.json`; both runs are in the repo-root hash-chained log (`python ledger.py verify`).
