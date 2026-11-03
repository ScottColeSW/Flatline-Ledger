# Preregistration: pt03-exposed-ftp-directory

**Status: run live, 2026-11-03. Prediction held exactly.**

## Prediction

- Expected result before any fix: `VULNERABLE` (directory listing and confidential files reachable with no authentication)
- Expected result after the fix: `REMEDIATED`
- Expected cost to legitimate traffic: none, *if* the fix allowlists `legal.md` specifically rather than blocking `/ftp/` wholesale. This was checked, not assumed.

## Result

- Pre-fix: `VULNERABLE` on all three checks. `/ftp/` served a full directory listing with no login; `acquisitions.md` (explicitly marked "confidential" in its own text) was downloadable; `incident-support.kdbx`, a KeePass credential database, was downloadable (3246 bytes).
- Post-fix (default-deny proxy with a one-file allowlist): `REMEDIATED`, all three blocked at HTTP 403.
- Legitimate check: `legal.md` still returned HTTP 200 through the proxy, because it was explicitly allowlisted after being checked (no "confidential" marker, reads like a genuine public terms document), not assumed safe by default.

Raw results in `results/pt03-001-*.json`; both runs are in the repo-root hash-chained log (`python ledger.py verify`).
