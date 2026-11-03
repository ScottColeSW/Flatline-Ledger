#!/usr/bin/env python3
"""pt19: the /metrics endpoint leaks business and host data with no auth.

server.js names it directly in its own comment: the authorization
middleware was never added to this route at all. The response is a
full Prometheus scrape including host fingerprinting (Node.js version,
process memory/CPU) and business metrics most apps would never expose
publicly (total registered users, total wallet balance across every
account).

Standard library only (urllib, json).
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

DEFAULT_BLUEPRINT = Path(__file__).resolve().parent / "blueprints" / "pt19-001.json"
METRICS_TOKEN_HEADER = "X-Metrics-Token"
METRICS_TOKEN_VALUE = "flatline-pt19-shared-secret"  # the fix's own stand-in credential, not a real secret


def _get(url: str, token: str | None = None) -> tuple[int, str]:
    req = urllib.request.Request(url, method="GET")
    if token:
        req.add_header(METRICS_TOKEN_HEADER, token)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode(errors="replace")


def run(target: str, blueprint: dict) -> dict:
    ledger.guard_target_host(target)

    exploit_status, exploit_body = _get(f"{target}{blueprint['endpoint']}")
    markers_present = [m for m in blueprint["sensitive_metric_markers"] if m in exploit_body]

    if exploit_status in (401, 403):
        status = "REMEDIATED"
        summary = f"Blocked with HTTP {exploit_status}."
    elif exploit_status == 200 and len(markers_present) == len(blueprint["sensitive_metric_markers"]):
        status = "VULNERABLE"
        summary = f"All {len(markers_present)} sensitive metric markers present with no authentication at all."
    else:
        status = "ERROR"
        summary = f"Inconclusive: HTTP {exploit_status}, markers_present={markers_present}."

    legit_status, legit_body = _get(f"{target}{blueprint['endpoint']}", token=METRICS_TOKEN_VALUE)
    legitimate_scrape_ok = legit_status == 200 and all(m in legit_body for m in blueprint["sensitive_metric_markers"])

    return {
        "vulnerability_id": blueprint["vulnerability_id"],
        "mitre_technique": blueprint["mitre_technique"],
        "target": target,
        "status": status,
        "exploit_http_status": exploit_status,
        "summary": summary,
        "legitimate_scrape_ok": legitimate_scrape_ok,
        "legitimate_scrape_http_status": legit_status,
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

    ledger._append_log({"event": "replay_run", "item": "pt19-exposed-metrics", **result})

    if result["status"] == "ERROR":
        sys.exit(2)


if __name__ == "__main__":
    main()
