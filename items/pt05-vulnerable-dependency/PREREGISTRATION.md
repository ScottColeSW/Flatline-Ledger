# Preregistration: pt05-vulnerable-dependency

**Status: run live, 2026-11-03. Prediction held exactly.**

## Prediction

- Expected result, `--mode current`: `VULNERABLE` (the installed `jsonwebtoken@0.4.0` carries known advisories)
- Expected result, `--mode proposed-fix`: `REMEDIATED` (the current published version, `9.0.3`, carries none)
- No legitimate-traffic cost prediction, by design, see README for why this item doesn't have one.

## Result

- `--mode current`: `VULNERABLE`. `jsonwebtoken@0.4.0`, as actually installed in the running container (resolved from `package-lock.json`, not guessed from `package.json`'s version range), carries 4 known advisories per osv.dev, including `CVE-2015-9235` (CRITICAL, JWT verification bypass).
- `--mode proposed-fix`: `REMEDIATED`. `jsonwebtoken@9.0.3`, the current published version on the npm registry, carries zero known advisories per osv.dev.
- Wider scan: 17 of the 69 direct dependencies have at least one known advisory. Only `jsonwebtoken` is tracked as this item's headline finding; the full hit list is in the raw result files for the record.

Raw results in `results/pt05-001-*.json`; both runs are in the repo-root hash-chained log (`python ledger.py verify`).
