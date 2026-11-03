#!/usr/bin/env python3
"""pt03: unauthenticated directory listing and confidential-file exposure
under Juice Shop's /ftp/ path.

Checks, all with zero Authorization header (nothing here needs an
account, which is the point):

1. Is the directory itself listable?
2. Is a file whose own content says "confidential" downloadable?
3. Is the KeePass credential database (incident-support.kdbx) downloadable?
4. Legitimate check: does legal.md (no confidential marker, reads like a
   genuine public terms doc) still work? A fix that also blocks this is
   a real cost, not assumed away.

Standard library only (urllib). Refuses to run against anything but a
localhost target -- see ledger.guard_target_host.
"""

from __future__ import annotations

import argparse
import http.client
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
import ledger  # noqa: E402

DEFAULT_BLUEPRINT = Path(__file__).resolve().parent / "blueprints" / "pt03-001.json"


def _get(url: str):
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            try:
                return resp.status, resp.read()
            except http.client.IncompleteRead as exc:
                # serve-index sends a Content-Length that doesn't quite
                # match on some responses; the partial body is still
                # enough for the substring checks this item does.
                return resp.status, exc.partial
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def run(target: str, vuln_id: str, mitre_technique: str, checks: dict, legitimate_path: str) -> dict:
    ledger.guard_target_host(target)

    listing_status, listing_body = _get(f"{target}{checks['directory_listing']}")
    listing_exposed = listing_status == 200 and b"href=" in listing_body

    confidential_status, confidential_body = _get(f"{target}{checks['confidential_file']}")
    confidential_exposed = confidential_status == 200 and b"confidential" in confidential_body.lower()

    kdbx_status, kdbx_body = _get(f"{target}{checks['credential_store_file']}")
    kdbx_exposed = kdbx_status == 200 and len(kdbx_body) > 0

    if listing_exposed or confidential_exposed or kdbx_exposed:
        status = "VULNERABLE"
        parts = []
        if listing_exposed:
            parts.append("directory listing")
        if confidential_exposed:
            parts.append("confidential-marked file")
        if kdbx_exposed:
            parts.append(f"credential store file ({len(kdbx_body)} bytes)")
        summary = f"Exposed with no authentication: {', '.join(parts)}."
    elif listing_status in (401, 403, 404) and confidential_status in (401, 403, 404) and kdbx_status in (401, 403, 404):
        status = "REMEDIATED"
        summary = "Listing and all checked files blocked without authentication."
    else:
        status = "ERROR"
        summary = f"Inconclusive: listing={listing_status}, confidential={confidential_status}, kdbx={kdbx_status}."

    legit_status, legit_body = _get(f"{target}{legitimate_path}")
    legitimate_legal_doc_ok = legit_status == 200 and len(legit_body) > 0

    result = {
        "vulnerability_id": vuln_id,
        "mitre_technique": mitre_technique,
        "target": target,
        "status": status,
        "directory_listing_http_status": listing_status,
        "confidential_file_http_status": confidential_status,
        "credential_store_http_status": kdbx_status,
        "summary": summary,
        "legitimate_legal_doc_ok": legitimate_legal_doc_ok,
        "legitimate_legal_doc_http_status": legit_status,
    }
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--blueprint", default=str(DEFAULT_BLUEPRINT))
    parser.add_argument("--target", default=None, help="Overrides the blueprint's target.host, e.g. to point at the proxy instead.")
    args = parser.parse_args()

    blueprint = json.loads(Path(args.blueprint).read_text())
    target = args.target or blueprint["target"]["host"]

    result = run(
        target,
        blueprint["vulnerability_id"],
        blueprint["mitre_technique"],
        blueprint["attack_checks"],
        blueprint["legitimate_check"]["path"],
    )
    print(json.dumps(result, indent=2))

    results_dir = Path(__file__).resolve().parent / "results"
    results_dir.mkdir(exist_ok=True)
    out_path = results_dir / f"{result['vulnerability_id']}-{int(time.time())}.json"
    out_path.write_text(json.dumps(result, indent=2))

    ledger._append_log({"event": "replay_run", "item": "pt03-exposed-ftp-directory", **result})

    if result["status"] == "ERROR":
        sys.exit(2)


if __name__ == "__main__":
    main()
