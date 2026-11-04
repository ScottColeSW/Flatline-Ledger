# Preregistration: pt24-address-idor-on-update

**Status: run live, 2026-11-04. Prediction held exactly.**

## Prediction

- Expected result before any fix: `VULNERABLE` (editing another account's address succeeds and reassigns ownership)
- Expected result after the fix: `REMEDIATED`
- Expected cost to legitimate traffic: none, an account editing its own address must keep working.

## Result

- Pre-fix: `VULNERABLE`. An attacker account's `PUT` to a victim's address id succeeded, HTTP 200, the response's own `UserId` field showed it reassigned to the attacker, and the victim's own subsequent `GET` for that same address id came back as "Malicious activity detected", the backend's own ownership-check failure message, now firing against the address's rightful original owner.
- Post-fix (through a GET-oracle proxy): `REMEDIATED`, HTTP 403.
- Legitimate check: an account editing its own address worked in both conditions.

## Not in Juice Shop's own challenge catalog at all

Checked the live scoreboard after confirming this finding: no new entry flipped. This isn't one of Juice Shop's 109 tracked challenges, unlike every item before it in this repo. Found purely by exploring the address book through the actual UI, not by chasing a known challenge, which is exactly the value of testing black-box rather than only ever confirming things the vendor already expects to be found.

## A real mistake made and corrected mid-investigation

The first live confirmation of this bug used a real seeded address (`id=1`, the admin account's), not test data, before the severity (permanent ownership reassignment) was understood. Its field-level data (`fullName`, `streetAddress`, etc.) was restored by hand from the original values in `data/static/users.yml`. Its **ownership** (`UserId`) could not be restored through this same API, since the same `appendUserId()` middleware that caused the bug also blocks any further PUT from reassigning it back without the caller already owning it. This is now a permanent, honestly-disclosed side effect of the investigation on this shared container, not a hidden one. `scenario.py` itself only ever touches data it creates.

Raw results in `results/pt24-001-*.json`; both runs are in the repo-root hash-chained log (`python ledger.py verify`).
