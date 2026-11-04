# Preregistration: pt34-poison-null-byte-file-read

## Prediction

- Expected result before any fix: `VULNERABLE`. `GET /ftp/eastere.gg%2500.md` returns the real content of a hidden `eastere.gg` file never linked anywhere in the UI, and `GET /ftp/package.json.bak%2500.md` returns the real content of an old `package.json` backup, both via the identical null-byte technique.
- Expected result after the fix (a reverse proxy that checks the extension against the *truncated* filename, matching the order the backend should use): `REMEDIATED`. Both requests are rejected `403`.
- Expected cost to legitimate traffic: none. A real `.md` file requested normally still downloads.

## Why this one, found white-box, also the owed Easter Egg item

Read directly from `data/static/challenges.yml`: `nullByteChallenge` ("Poison Null Byte") and `easterEggLevelOneChallenge` ("Easter Egg"), whose own hint says "if you solved one of the three file access challenges, you already know where to find the easter egg." `routes/fileServer.ts` was pulled and read before a single request was sent:

```ts
if (file && (endsWithAllowlistedFileType(file) || file === 'incident-support.kdbx')) {
  file = security.cutOffPoisonNullByte(file)
  // ...serves ftp/ + file
}
```

The extension check runs on the raw filename, truncation happens only after. `security.cutOffPoisonNullByte` truncates at the first literal `%00`; Express decodes a client-sent `%2500` into exactly that. This single bug underlies five separate catalog challenges that all just differ by which filename is targeted (the easter egg, a dev backup, a sales backup, a misplaced signature file, and the general null-byte challenge itself).

This serves as this repo's Easter Egg item too, Scott's one ask for something "for fun" in this stretch of white-box work: the file retrieved really is a hidden joke from the Juice Shop developers, not a serious secret, which is exactly what makes it a fitting low-stakes proof of a real, more broadly dangerous primitive (arbitrary file read regardless of extension allowlist).

## Result

**Status: run live, 2026-11-04. Prediction held exactly.**

- Pre-fix: `VULNERABLE`. Both `GET /ftp/eastere.gg%2500.md` and `GET /ftp/package.json.bak%2500.md` returned `200` with the real target file's content.
- Post-fix (through a proxy checking the extension against the truncated filename): `REMEDIATED`. Both came back `403`.
- Legitimate check: `GET /ftp/legal.md` (a real `.md` file, no null byte) succeeded in both conditions.

## Checked the scoreboard

`easterEggLevelOneChallenge`, `nullByteChallenge`, and `forgottenDevBackupChallenge` all flipped solved, from the `eastere.gg` and `package.json.bak` requests respectively. `forgottenBackupChallenge` and `misplacedSignatureFileChallenge` stayed unsolved; each requires the same technique against its own specific filename (`coupons_2013.md.bak`, `suspicious_errors.yml`), neither of which this item targeted, to keep the proof focused on two files. The easter-egg content itself was a real easter egg: a short joke message from the Juice Shop developers, then a base64-encoded hint pointing toward `easterEggLevelTwoChallenge` ("Nested Easter Egg"), left unsolved here, out of scope for this item.

Raw results in `results/pt34-001-*.json`; both runs are in the repo-root hash-chained log (`python ledger.py verify`).
