#!/usr/bin/env python3
"""pt05: a known-vulnerable dependency pinned in Juice Shop's own lockfile.

This item works differently from pt01-04, on purpose: it's SCA, not
DAST. There's no HTTP replay against the running app, and no
compensating-control proxy, because "the server has a vulnerable
dependency" isn't exploited here, it's detected. Conflating "this
library has a known CVE" with "this app is demonstrably exploitable
through it" would overclaim, so this item measures only the former and
says so plainly in its own result.

What it does:

1. `docker cp`s package.json and package-lock.json out of the running
   container (named in the blueprint), so the scan is against what's
   actually installed, not just what package.json's version ranges say.
2. Resolves every direct dependency to its exact installed version.
3. Queries osv.dev (a public, read-only vulnerability database) in one
   batch call. No exploit traffic goes anywhere; this is the same kind
   of lookup `npm audit`/`pip-audit`/`osv-scanner` make as a matter of
   course.
4. Reports the tracked package's status under one of two modes:
   - --mode current: is the version actually installed vulnerable?
     (expected: yes)
   - --mode proposed-fix: is the suggested upgrade target clean?
     (expected: yes, i.e. REMEDIATED -- this does NOT install the
     upgrade into the running container, it only validates that the
     proposed fix version itself carries no known advisories)

Standard library only (urllib, subprocess, json).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
import ledger  # noqa: E402

DEFAULT_BLUEPRINT = Path(__file__).resolve().parent / "blueprints" / "pt05-001.json"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_SINGLE_URL = "https://api.osv.dev/v1/query"


def _docker_cp(container: str, container_path: str, dest: Path) -> None:
    result = subprocess.run(
        ["docker", "cp", f"{container}:{container_path}", str(dest)],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"docker cp failed for {container_path}: {result.stderr.strip()}")


def _resolve_direct_deps(package_json: Path, package_lock: Path) -> dict[str, str]:
    pkg = json.loads(package_json.read_text())
    lock = json.loads(package_lock.read_text())
    packages = lock.get("packages", {})
    resolved = {}
    for name in pkg.get("dependencies", {}):
        entry = packages.get(f"node_modules/{name}")
        if entry:
            resolved[name] = entry.get("version")
    return resolved


def _osv_batch_query(resolved: dict[str, str]) -> dict[str, list[str]]:
    queries = [{"package": {"name": n, "ecosystem": "npm"}, "version": v} for n, v in resolved.items()]
    req = urllib.request.Request(
        OSV_BATCH_URL, data=json.dumps({"queries": queries}).encode(), method="POST"
    )
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=30) as resp:
        result = json.loads(resp.read())
    hits = {}
    for name, r in zip(resolved.keys(), result["results"]):
        vulns = r.get("vulns", [])
        if vulns:
            hits[name] = [v["id"] for v in vulns]
    return hits


def _osv_single_query(name: str, version: str) -> list[str]:
    req = urllib.request.Request(
        OSV_SINGLE_URL,
        data=json.dumps({"package": {"name": name, "ecosystem": "npm"}, "version": version}).encode(),
        method="POST",
    )
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=15) as resp:
        result = json.loads(resp.read())
    return [v["id"] for v in result.get("vulns", [])]


def run(blueprint: dict, mode: str) -> dict:
    ledger.guard_target_host(blueprint["target"]["host"])
    container = blueprint["target"]["container_name"]
    tracked = blueprint["tracked_package"]

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        _docker_cp(container, "/juice-shop/package.json", tmp_path / "package.json")
        _docker_cp(container, "/juice-shop/package-lock.json", tmp_path / "package-lock.json")
        resolved = _resolve_direct_deps(tmp_path / "package.json", tmp_path / "package-lock.json")

    scan_hits = _osv_batch_query(resolved)
    installed_version = resolved.get(tracked["name"])

    if mode == "current":
        tracked_vulns = scan_hits.get(tracked["name"], [])
        status = "VULNERABLE" if tracked_vulns else "ERROR"
        summary = (
            f"{tracked['name']}@{installed_version} carries {len(tracked_vulns)} known advisory/advisories: {tracked_vulns}."
            if tracked_vulns else
            f"{tracked['name']}@{installed_version} unexpectedly reported clean; prediction did not hold."
        )
    else:  # proposed-fix
        fix_version = tracked["proposed_fix_version"]
        fix_vulns = _osv_single_query(tracked["name"], fix_version)
        status = "REMEDIATED" if not fix_vulns else "VULNERABLE"
        summary = (
            f"{tracked['name']}@{fix_version} (proposed fix, not installed into the running container) "
            + ("carries no known advisories." if not fix_vulns else f"still carries: {fix_vulns}.")
        )
        tracked_vulns = fix_vulns

    return {
        "vulnerability_id": blueprint["vulnerability_id"],
        "mitre_technique": blueprint["mitre_technique"],
        "cwe": blueprint["cwe"],
        "mode": mode,
        "status": status,
        "summary": summary,
        "tracked_package": tracked["name"],
        "tracked_package_version_checked": installed_version if mode == "current" else tracked["proposed_fix_version"],
        "tracked_package_known_vulns": tracked_vulns,
        "direct_deps_scanned": len(resolved),
        "direct_deps_with_known_vulns": len(scan_hits),
        "all_hits": scan_hits if mode == "current" else None,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--blueprint", default=str(DEFAULT_BLUEPRINT))
    parser.add_argument("--mode", choices=["current", "proposed-fix"], default="current")
    args = parser.parse_args()

    blueprint = json.loads(Path(args.blueprint).read_text())
    result = run(blueprint, args.mode)
    print(json.dumps(result, indent=2))

    results_dir = Path(__file__).resolve().parent / "results"
    results_dir.mkdir(exist_ok=True)
    out_path = results_dir / f"{result['vulnerability_id']}-{args.mode}-{int(time.time())}.json"
    out_path.write_text(json.dumps(result, indent=2))

    ledger._append_log({"event": "replay_run", "item": "pt05-vulnerable-dependency", **result})

    if result["status"] == "ERROR":
        sys.exit(2)


if __name__ == "__main__":
    main()
