# pt20: Deprecated Interface Not Properly Shut Down — OWASP Juice Shop

**Status: run live, 2026-11-03.** The same route [pt17](../pt17-xxe-file-disclosure/) exploited, a different and earlier finding: the route should never have still been running at all.

## Target

Same container as the earlier items: `bkimminich/juice-shop:v17.3.0`, `http://localhost:3001`.

## Finding

Juice Shop's own challenge description names this plainly: "use a deprecated B2B interface that was not properly shut down." A real decommissioning makes a route behave as if it never existed, `404`. Instead, `POST /file-upload` with a `.xml` file, no exploit payload at all, just a benign complaint, gets:

```
HTTP/1.1 410 Gone
"B2B customer complaints via file upload have been deprecated for security reasons: ..."
```

That `410` with a message means the parser ran, the XML got read, and only then did the handler decide to say "deprecated." A route that's actually been removed doesn't get far enough to say anything at all. This half-measure, live code dressed up as a dead end, is exactly what gave pt17 a parser to attack in the first place.

## Classification

**CWE-16** (Configuration), the closest broad parent; no CWE maps "marked deprecated but never removed" precisely, the same kind of honest, imprecise-but-stated mapping pt15 uses CWE-840 for. **OWASP: A05:2021 - Security Misconfiguration.** **No MITRE ATT&CK technique assigned**: this is a decommissioning-hygiene gap, not attacker tradecraft, the same honest gap pt05 and pt15 document for their own reasons.

## What was run

```bash
python items/pt20-deprecated-interface/scenario.py                               # pre-fix, direct to :3001
python items/pt20-deprecated-interface/proxy.py                                  # separate shell, FLATLINE_ENFORCE=1 by default
python items/pt20-deprecated-interface/scenario.py --target http://localhost:3021 # post-fix, through the proxy
```

Confirmed first that `.pdf` complaint attachments are a genuinely separate, still-supported path (`HTTP 204`, no deprecation message at all), before treating it as this item's legitimate-traffic baseline.

## The fix: actual decommissioning, not a polite error message

`proxy.py` inspects the uploaded filename's extension and returns a plain `404` for `.xml`/`.yml`/`.yaml` before the request ever reaches the backend's parser, no logic runs, no message is composed, the route behaves as if it isn't there. `.pdf` uploads pass through untouched.

## Result

| Condition | Target | Deprecated-extension upload | PDF attachment |
| --- | --- | --- | --- |
| No control | `http://localhost:3001` (direct) | `VULNERABLE` — HTTP 410, logic ran first | OK (204) |
| True-decommissioning proxy | `http://localhost:3021` (proxy, enforcing) | `REMEDIATED` — HTTP 404 | OK (204) |

Raw per-run output: `results/pt20-001-*.json`. `python ledger.py verify` from the repo root confirms both runs are in the hash-chained log untampered.

## What this does not show

- This item deliberately uses a benign upload; pt17 covers the actual exploit through the same reachability gap.
- Same caveats as the earlier items: one vendor image, one run, no ticket-loop integration yet.
