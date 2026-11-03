#!/usr/bin/env python3
"""pt10: an unsafe config choice reopens both reflected XSS and a NoSQL
injection in the same code path.

Unlike pt01-09, the independent variable here isn't a proxy toggle,
it's which of Juice Shop's own vendor-shipped configs is running.
trackOrder.js builds a MongoDB $where clause by string-interpolating
its id parameter. A regex strips the id to [\\w-]+ first, UNLESS the
"Reflected XSS" challenge is enabled, in which case the id is only
length-truncated, never sanitized, reopening both the XSS and the
$where injection together. That challenge is disabled by default
inside Docker, but Juice Shop itself ships config/unsafe.yml, which
disables the whole safety switch, activated with nothing more than
NODE_ENV=unsafe.

--mode safe checks the default Docker deployment (port 3001 in this
repo). --mode unsafe checks a second container started explicitly with
NODE_ENV=unsafe (port 3012); see README for how to start it.

Standard library only (urllib, json).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
import ledger  # noqa: E402

DEFAULT_BLUEPRINT = Path(__file__).resolve().parent / "blueprints" / "pt10-001.json"


def _track_order(target: str, order_id: str) -> dict:
    url = f"{target}/rest/track-order/{urllib.parse.quote(order_id, safe='')}"
    with urllib.request.urlopen(url, timeout=10) as resp:
        return json.loads(resp.read())


def run(target: str, blueprint: dict) -> dict:
    ledger.guard_target_host(target)

    xss_body = _track_order(target, blueprint["xss_payload"])
    xss_reflected_raw = xss_body["data"][0].get("orderId") == blueprint["xss_payload"]

    injection_body = _track_order(target, blueprint["nosql_injection_payload"])
    orders_returned = len(injection_body.get("data", []))
    injection_broke_out = orders_returned > 1

    legit_body = _track_order(target, "pt10-nonexistent-order-id")
    legitimate_tracking_ok = legit_body.get("status") == "success" and len(legit_body.get("data", [])) == 1

    if xss_reflected_raw or injection_broke_out:
        status = "VULNERABLE"
        parts = []
        if xss_reflected_raw:
            parts.append("XSS payload reflected raw and unescaped")
        if injection_broke_out:
            parts.append(f"NoSQL injection returned {orders_returned} orders instead of one")
        summary = "; ".join(parts) + "."
    elif not xss_reflected_raw and not injection_broke_out:
        status = "REMEDIATED"
        summary = "XSS payload stripped to alphanumerics; injection payload never broke out of the $where clause."
    else:
        status = "ERROR"
        summary = "Inconclusive."

    return {
        "vulnerability_id": blueprint["vulnerability_id"],
        "mitre_technique": blueprint["mitre_technique"],
        "target": target,
        "status": status,
        "summary": summary,
        "xss_reflected_raw": xss_reflected_raw,
        "nosql_injection_orders_returned": orders_returned,
        "legitimate_tracking_ok": legitimate_tracking_ok,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--blueprint", default=str(DEFAULT_BLUEPRINT))
    parser.add_argument("--mode", choices=["safe", "unsafe"], default="safe")
    args = parser.parse_args()

    blueprint = json.loads(Path(args.blueprint).read_text())
    target = blueprint["safe_target"]["host"] if args.mode == "safe" else blueprint["unsafe_target"]["host"]

    result = run(target, blueprint)
    print(json.dumps(result, indent=2))

    results_dir = Path(__file__).resolve().parent / "results"
    results_dir.mkdir(exist_ok=True)
    out_path = results_dir / f"{result['vulnerability_id']}-{args.mode}-{int(time.time())}.json"
    out_path.write_text(json.dumps(result, indent=2))

    ledger._append_log({"event": "replay_run", "item": "pt10-unsafe-config-reopens-sanitization", "mode": args.mode, **result})

    if result["status"] == "ERROR":
        sys.exit(2)


if __name__ == "__main__":
    main()
