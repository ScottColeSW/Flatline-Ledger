# pt01: Broken Access Control / IDOR — OWASP Juice Shop

**Status: planned, not yet run.** This item's prediction has not been committed and no blueprint has been replayed. Numbers below are placeholders until `ledger.py predict` runs for real.

## Target

[OWASP Juice Shop](https://github.com/juice-shop/juice-shop), run locally:

```bash
docker run --rm -p 3000:3000 bkimminich/juice-shop:v17.3.0
```

Pinned image tag will be recorded here once a run actually happens; `v17.3.0` is a placeholder for "pin it, don't float on `:latest`."

## Finding family

Insecure direct object reference on an authenticated user's own order/basket endpoints: whether one logged-in user can read or modify another user's basket by changing an identifier, with no server-side ownership check.

## MITRE ATT&CK mapping

- **T1190** (Exploit Public-Facing Application) for the initial access vector.
- Mapped at the technique level only; sub-technique and tactic framing will be filled in once the blueprint is written, not guessed in advance.

## Plan

1. Write the blueprint (`blueprints/pt01-001.json`) against the running local container only.
2. Commit the prediction (`PREREGISTRATION.md`) before any replay.
3. Run `ledger.py verify` before and after a fix is applied to a forked copy of the target, score `VULNERABLE` vs `REMEDIATED`, record legitimate-request cost alongside it.
4. Report the result here, misses included.
