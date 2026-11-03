# pt17: XXE File Disclosure via Unauthenticated Upload — OWASP Juice Shop

**Status: run live, 2026-11-03.** The first item in this repo where the vendor's own code explicitly warns the parser can crash the container, and the test was scoped around that warning on purpose.

## Target

Same container as the earlier items: `bkimminich/juice-shop:v17.3.0`, `http://localhost:3001`.

## Finding

`POST /file-upload` needs no authentication at all. Pulling `routes/fileUpload.js` out of the container shows exactly what happens to an uploaded `.xml` file:

```js
// XXE attacks in Docker/Heroku containers regularly cause "segfault" crashes
const xmlDoc = vm.runInContext('libxml.parseXml(data, { noblanks: true, noent: true, nocdata: true })', sandbox, { timeout: 2000 });
```

`noent: true` means external entities get resolved. A file containing:

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY> <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<foo>&xxe;</foo>
```

got that entity resolved, and the real contents of `/etc/passwd` came back inside the endpoint's own `HTTP 410` "this interface is deprecated" error message, the irony being that the "deprecated" response is the thing that leaks the file. Confirmed by Juice Shop's own "XXE Data Access" scoreboard entry, flipped on the first attempt.

## Classification

**CWE-611** (Improper Restriction of XML External Entity Reference). **OWASP: A05:2021 - Security Misconfiguration**, matching the official catalog's own category for the underlying "deprecated interface" this rides on. **MITRE ATT&CK: T1190** (Exploit Public-Facing Application) for the vector, **T1005** (Data from Local System) for the impact.

## What was run

```bash
python items/pt17-xxe-file-disclosure/scenario.py                               # pre-fix, direct to :3001
python items/pt17-xxe-file-disclosure/proxy.py                                  # separate shell, FLATLINE_ENFORCE=1 by default
python items/pt17-xxe-file-disclosure/scenario.py --target http://localhost:3019 # post-fix, through the proxy
```

`scenario.py` builds the `multipart/form-data` upload by hand (`urllib` has no high-level multipart support in the standard library).

## A deliberate scope limit

The vendor's caution comment above the parser is specific: XXE in this exact setup "regularly causes segfault crashes." This item tests only the one-shot file-disclosure variant, confirmed afterward not to have destabilized the container (a plain `GET /` still returned `HTTP 200` immediately after). The DoS/billion-laughs variant (Juice Shop's own `xxeDosChallenge`) was never attempted here, the container is shared with every other item in this repo, and the risk of taking it down to chase one more scoreboard entry wasn't worth it. Stated here rather than left for a reader to wonder why that one wasn't chased too.

## The fix: reject the DOCTYPE itself before it reaches the parser

`proxy.py` scans the raw upload for the `<!DOCTYPE`, `<!ENTITY`, and `SYSTEM` signature an XXE payload needs and rejects the whole request before it ever reaches the backend's vulnerable parser. A benign XML file with no DOCTYPE at all passes through untouched.

## Result

| Condition | Target | XXE upload | Benign upload |
| --- | --- | --- | --- |
| No control | `http://localhost:3001` (direct) | `VULNERABLE` — `/etc/passwd` disclosed | Reached backend (410, "deprecated") |
| Signature-rejecting proxy | `http://localhost:3019` (proxy, enforcing) | `REMEDIATED` — HTTP 403 | Reached backend (410, "deprecated") |

Raw per-run output: `results/pt17-001-*.json`. `python ledger.py verify` from the repo root confirms both runs are in the hash-chained log untampered.

## What this does not show

- The DoS/billion-laughs variant wasn't attempted, on purpose, see above.
- The proxy's detection is a flat signature match on three substrings, not a real XML parser; a sufficiently obfuscated or encoded DOCTYPE could defeat it in ways this item didn't test for.
- Same caveats as the earlier items: one vendor image, one run, no ticket-loop integration yet.
