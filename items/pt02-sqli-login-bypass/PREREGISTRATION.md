# Preregistration: pt02-sqli-login-bypass

**Status: run live, 2026-11-03. Core prediction held; one honest surprise.**

## Prediction

- Expected result before any fix: `VULNERABLE` (the injection authenticates as admin)
- Expected result after the fix: `REMEDIATED`
- Expected cost to legitimate traffic: a normal email/password login must keep working in every condition

## Result

- Pre-fix: `VULNERABLE`. `' OR 1=1--` as the email, any password, returned a valid token with `role: admin` for `admin@juice-sh.op`.
- Post-fix (through the compensating-control proxy): `REMEDIATED`, HTTP 403.
- Ordinary legitimate login: worked in both conditions.

## The surprise, reported rather than edited out

This item also tested a legitimate email that happens to contain an apostrophe (e.g. a name like `O'Brien`, a syntactically valid RFC 5322 address). That login **fails in every condition tested**, including the unmodified backend with no control in front of it at all:

- Against the raw backend: HTTP 500, a Sequelize/SQLite stack trace. The same string-concatenated query that makes the injection possible also breaks on an ordinary apostrophe.
- Through the compensating-control proxy: HTTP 403, blocked by our own filter before it ever reaches the backend's bug.

Neither of these counts as something the fix "cost," since the baseline was already broken for this case before any control existed. It's recorded here because a report that only measured "did our control add a new cost" would have missed that the vendor's own code already fails real users with apostrophes in their email, independent of anything in this repo.
