#!/usr/bin/env python3
"""pt20: a "deprecated" B2B interface that was never actually removed.

Juice Shop's own challenge catalog names this exactly: "a deprecated
B2B interface that was not properly shut down." A true decommissioning
would make the route 404. Instead, uploading a .xml or .yml file gets
HTTP 410 with a "deprecated for security reasons" message, which means
the route still ran real parsing logic before saying so, the same
half-measure pt17 was able to exploit for XXE. This item measures the
reachability gap itself, not the XXE content exploited through it.

Standard library only (urllib, json); builds the multipart/form-data
body by hand, same as pt17.
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

DEFAULT_BLUEPRINT = Path(__file__).resolve().parent / "blueprints" / "pt20-001.json"
BOUNDARY = "flatline-pt20-boundary"


def _multipart_body(filename: str, content: str) -> bytes:
    parts = [
        f"--{BOUNDARY}",
        f'Content-Disposition: form-data; name="file"; filename="{filename}"',
        "Content-Type: application/octet-stream",
        "",
        content,
        f"--{BOUNDARY}--",
        "",
    ]
    return "\r\n".join(parts).encode()


def _upload(target: str, filename: str, content: str) -> int:
    body = _multipart_body(filename, content)
    req = urllib.request.Request(f"{target}/file-upload", data=body, method="POST")
    req.add_header("Content-Type", f"multipart/form-data; boundary={BOUNDARY}")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code


def run(target: str, blueprint: dict) -> dict:
    ledger.guard_target_host(target)

    benign_xml = '<?xml version="1.0"?><complaint><text>pt20 reachability probe, no DOCTYPE</text></complaint>'
    exploit_status = _upload(target, f"complaint.{blueprint['deprecated_file_extensions'][0]}", benign_xml)

    if exploit_status == 404:
        status = "REMEDIATED"
        summary = "The deprecated interface now returns 404, as if it never existed."
    elif exploit_status != 404:
        # 410 ("deprecated for security reasons") still means the route ran
        # real logic before responding, exactly the reachability this item
        # measures; any non-404 response counts as "still alive."
        status = "VULNERABLE"
        summary = f"The 'deprecated' interface is still live and executed logic before responding, HTTP {exploit_status} (not 404)."
    else:
        status = "ERROR"
        summary = f"Inconclusive: HTTP {exploit_status}."

    legit_status = _upload(target, f"complaint.{blueprint['legitimate_file_extension']}", "%PDF-1.4 pt20 legitimate attachment")
    legitimate_pdf_upload_ok = legit_status == 204

    return {
        "vulnerability_id": blueprint["vulnerability_id"],
        "mitre_technique": blueprint["mitre_technique"],
        "target": target,
        "status": status,
        "exploit_http_status": exploit_status,
        "summary": summary,
        "legitimate_pdf_upload_ok": legitimate_pdf_upload_ok,
        "legitimate_pdf_upload_http_status": legit_status,
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

    ledger._append_log({"event": "replay_run", "item": "pt20-deprecated-interface", **result})

    if result["status"] == "ERROR":
        sys.exit(2)


if __name__ == "__main__":
    main()
