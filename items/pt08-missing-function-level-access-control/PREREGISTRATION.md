# Preregistration: pt08-missing-function-level-access-control

**Status: run live, 2026-11-03. Prediction held exactly.**

## Prediction

- Expected result before any fix: `VULNERABLE` (a plain customer lists the full admin-only user directory)
- Expected result after the fix: `REMEDIATED`
- Expected cost to legitimate traffic: none, the real admin account must keep listing users.

## Result

- Pre-fix: `VULNERABLE`. A freshly registered customer, authenticated via the `Authorization` header, got `GET /api/Users` back in full, 39 user accounts, every email and role, including which real addresses hold `admin`. No password hash was exposed, but full account enumeration was.
- Post-fix (through a role-pinning proxy): `REMEDIATED`, HTTP 403.
- Legitimate check: the real admin account (the weak credential confirmed in pt07) still listed users in both conditions.

## How this item was found: a scoreboard mismatch pointed at the real bug

Checking whether pt04's and pt06's pattern (our proof being more general than Juice Shop's own narrow scoreboard check) applied here too, pt08 was investigated starting from the "Admin Section" challenge. That challenge's own solve condition is a frontend-only pixel-tracking marker (`19px.png`, loaded only if the Angular SPA actually renders `/#/administration`). Testing it directly: the frontend route guard turned out to be intact, a plain customer gets a `403` page from the Angular router itself. That's a negative result worth stating plainly, not every narrow scoreboard check is hiding a broader real bug.

But the backend API behind that same feature was never checked by that frontend test at all. `GET /api/Users` called directly, bypassing the SPA, turned out to have no role check whatsoever, only an authentication check. This is a different, more serious bug than the one the "Admin Section" challenge measures, found by checking the layer underneath it rather than stopping at "the frontend guard works."

Raw results in `results/pt08-001-*.json`; both runs are in the repo-root hash-chained log (`python ledger.py verify`).
