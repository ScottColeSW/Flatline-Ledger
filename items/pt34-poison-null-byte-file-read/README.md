# pt34: Poison Null Byte File Read (and the Easter Egg) — OWASP Juice Shop

**Status: run live, 2026-11-04.** Found white-box, straight from Juice Shop's own challenge catalog. Also the Easter Egg item, for fun, Scott asked to work into this stretch.

## Target

Same container as the earlier items: `bkimminich/juice-shop:v17.3.0`, `http://localhost:3001`.

## Finding

`GET /ftp/{file}` is meant to only serve `.md` and `.pdf` files from the `ftp/` directory. The check that enforces it runs in the wrong order:

```ts
if (file && (endsWithAllowlistedFileType(file) || file === 'incident-support.kdbx')) {
  file = security.cutOffPoisonNullByte(file)
  // ...res.sendFile(path.resolve('ftp/', file))
}
```

`endsWithAllowlistedFileType` checks the **raw** requested filename. Only afterward does `cutOffPoisonNullByte` truncate the filename at the first literal `%00`. A request for `eastere.gg%2500.md` (which Express decodes once into a literal `%00.md` tail) passes the `.md` check on the full string, but the file actually opened and streamed is everything before the null byte: `eastere.gg`, any extension, any name.

Confirmed live two ways: `GET /ftp/eastere.gg%2500.md` returned a hidden text file never linked anywhere in the UI (a real easter egg, a short joke from the Juice Shop developers plus a base64-encoded hint toward a second, nested one), and `GET /ftp/package.json.bak%2500.md` returned a real old `package.json` backup, confirming this is a general file-read primitive, not a one-off against a single filename.

## Classification

**CWE-158** (Improper Neutralization of Null Byte or NUL Character). **OWASP: A05:2021 - Security Misconfiguration.** **MITRE ATT&CK: T1005** (Data from Local System).

## Why this one, found white-box, and the owed Easter Egg

Read directly from `data/static/challenges.yml`: `nullByteChallenge` ("Poison Null Byte") and `easterEggLevelOneChallenge` ("Easter Egg"), whose own hint says "if you solved one of the three file access challenges, you already know where to find the easter egg." `routes/fileServer.ts` was pulled and read before a single request was sent. This single bug underlies five separate catalog challenges that only differ by target filename; this item demonstrates two of them and serves as this repo's one deliberately "for fun" item, Scott's ask to throw an Easter Egg into this stretch of otherwise serious white-box work.

## Checked the scoreboard

`easterEggLevelOneChallenge`, `nullByteChallenge`, and `forgottenDevBackupChallenge` ("Forgotten Developer Backup," the `package.json.bak` request) all flipped solved. `forgottenBackupChallenge` and `misplacedSignatureFileChallenge` stayed unsolved; each needs this same technique against its own specific filename (`coupons_2013.md.bak`, `suspicious_errors.yml`), neither of which this item targeted.

## What was run

```bash
python items/pt34-poison-null-byte-file-read/scenario.py                               # pre-fix, direct to :3001
python items/pt34-poison-null-byte-file-read/proxy.py                                  # separate shell, FLATLINE_ENFORCE=1 by default
python items/pt34-poison-null-byte-file-read/scenario.py --target http://localhost:3035 # post-fix, through the proxy
```

## The fix

`proxy.py` performs the same truncation itself, first: it splits the requested filename at `%00`, then only allows the request through if the *truncated* name is what actually ends in `.md` or `.pdf`. A real `.md`/`.pdf` file requested normally is untouched.

## Result

| Condition | Target | Hidden easter-egg file | Unrelated backup file | Real `.md` download |
| --- | --- | --- | --- | --- |
| No control | `http://localhost:3001` (direct) | `VULNERABLE` — served | `VULNERABLE` — served | OK |
| Truncate-first proxy | `http://localhost:3035` (proxy, enforcing) | `REMEDIATED` — `403` | `REMEDIATED` — `403` | OK |

Raw per-run output: `results/pt34-001-*.json`. `python ledger.py verify` from the repo root confirms both runs are in the hash-chained log untampered.

## What this does not show

- The real fix belongs in `fileServer.ts` itself (check the extension after truncation, not before); this proxy demonstrates that fix in front of the backend, not a patch to the vendored image.
- This item deliberately scripted only two of the five filenames this same bug reaches; the mechanism generalizes to any file in `ftp/`, not just the two demonstrated.
- Same caveats as the earlier items: one vendor image, one run, no ticket-loop integration yet.
