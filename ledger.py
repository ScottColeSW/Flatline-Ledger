#!/usr/bin/env python3
"""Flatline Ledger: a predict-then-verify harness for pen test / purple team items.

Standard library only. Mirrors the discipline in Agent Defense Theater's
adt.py: a prediction must be committed, unedited, before a live replay is
allowed to run, and every run appends to a hash-chained log instead of
overwriting a report.

This file deliberately does not contain any attack/replay logic yet. It
enforces the gate (predict before run, localhost-only targets, hash-chained
record) that the real replay engine will have to pass through once it's
built against an actual running lab target.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

REPO_ROOT = Path(__file__).resolve().parent
LOG_PATH = REPO_ROOT / "results" / "ledger_log.jsonl"

# Any target host that isn't one of these fails closed. This is the one
# rule the README promises is enforced, not just stated.
ALLOWED_HOSTNAMES = {
    "localhost",
    "127.0.0.1",
    "::1",
    # Docker's own name for "the machine this container is running on,"
    # never a real external domain. Used by SSRF items (pt04) so the
    # oracle a container calls back to is still categorically local.
    "host.docker.internal",
}


class GuardError(RuntimeError):
    """Raised when a safety or commit-discipline check fails."""


def _git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=REPO_ROOT, capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        raise GuardError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def _is_committed_and_unedited(path: Path) -> bool:
    """True if `path` is tracked, has no uncommitted changes, and matches HEAD."""
    rel = path.relative_to(REPO_ROOT).as_posix()
    status = _git("status", "--porcelain", "--", rel)
    if status.strip():
        return False
    tracked = _git("ls-files", "--error-unmatch", rel)
    return bool(tracked.strip())


def guard_target_host(host: str) -> None:
    """Fail closed unless `host` is localhost, 127.0.0.1, ::1,
    host.docker.internal, or a bare docker-compose service name (no
    scheme, no dot)."""
    parsed = urlparse(host if "://" in host else f"//{host}")
    hostname = (parsed.hostname or "").lower()
    if hostname in ALLOWED_HOSTNAMES:
        return
    if "://" not in host and "." not in host:
        # bare service name, e.g. "juice-shop" inside this repo's own
        # docker-compose network -- allowed, but only here, never a FQDN.
        return
    raise GuardError(
        f"Refusing target host '{host}': only localhost/127.0.0.1/::1, "
        "host.docker.internal, or a bare compose service name is allowed. "
        "This harness does not run against anything that looks like a real domain."
    )


def guard_all_urls_in(data) -> None:
    """Recursively check every http(s)-looking string value in a parsed
    JSON structure, not just a top-level target.host field. Anything a
    blueprint tells a target to call out to has to pass the same guard
    as the target itself."""
    if isinstance(data, dict):
        for value in data.values():
            guard_all_urls_in(value)
    elif isinstance(data, list):
        for item in data:
            guard_all_urls_in(item)
    elif isinstance(data, str) and data.startswith(("http://", "https://")):
        guard_target_host(data)


def cmd_predict(item_dir: str) -> None:
    item_path = (REPO_ROOT / item_dir).resolve()
    prereg = item_path / "PREREGISTRATION.md"
    if not prereg.exists():
        raise GuardError(f"No PREREGISTRATION.md found at {prereg}")
    if not _is_committed_and_unedited(prereg):
        raise GuardError(
            f"{prereg} must be committed with no uncommitted changes before "
            "a live run is permitted. Commit it first, then run predict again."
        )
    blueprints_dir = item_path / "blueprints"
    live_blueprints = [
        p for p in blueprints_dir.glob("*.json") if not p.name.endswith(".example.json")
    ] if blueprints_dir.exists() else []
    if not live_blueprints:
        raise GuardError(
            f"No committed blueprint files found under {blueprints_dir} "
            "(only .example.json files, which never count). Copy an example "
            "to a real filename, fill it in, and commit it first."
        )
    for bp in live_blueprints:
        if not _is_committed_and_unedited(bp):
            raise GuardError(f"{bp} has uncommitted changes; commit before predicting.")
        data = json.loads(bp.read_text())
        guard_all_urls_in(data)

    _append_log(
        {
            "event": "predict_committed",
            "item": item_dir,
            "prereg_sha256": hashlib.sha256(prereg.read_bytes()).hexdigest(),
            "blueprints": sorted(p.name for p in live_blueprints),
        }
    )
    print(f"Prediction gate passed for {item_dir}: {len(live_blueprints)} blueprint(s) ready to run.")


def _append_log(data: dict) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    prev_hash = ""
    if LOG_PATH.exists() and LOG_PATH.stat().st_size > 0:
        last_line = LOG_PATH.read_text().strip().splitlines()[-1]
        prev_hash = json.loads(last_line)["hash"]
    entry = {"ts": time.time(), "prev_hash": prev_hash, **data}
    entry_bytes = json.dumps(entry, sort_keys=True).encode()
    entry["hash"] = hashlib.sha256(prev_hash.encode() + entry_bytes).hexdigest()
    with LOG_PATH.open("a") as f:
        f.write(json.dumps(entry, sort_keys=True) + "\n")


def cmd_verify() -> None:
    if not LOG_PATH.exists():
        print("No log yet (nothing has been predicted or run).")
        return
    prev_hash = ""
    for i, line in enumerate(LOG_PATH.read_text().strip().splitlines(), start=1):
        entry = json.loads(line)
        claimed_hash = entry.pop("hash")
        if entry["prev_hash"] != prev_hash:
            raise GuardError(f"Chain broken at line {i}: prev_hash mismatch.")
        recomputed = hashlib.sha256(
            prev_hash.encode() + json.dumps(entry, sort_keys=True).encode()
        ).hexdigest()
        if recomputed != claimed_hash:
            raise GuardError(f"Chain broken at line {i}: hash mismatch (tampered?).")
        prev_hash = claimed_hash
    print(f"Chain verified: {i} entr{'y' if i == 1 else 'ies'}, no tampering detected.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    predict_p = sub.add_parser("predict", help="Check an item's commit/prediction gate.")
    predict_p.add_argument("item_dir", help="e.g. items/pt01-idor-juice-shop")

    sub.add_parser("verify", help="Verify the hash-chained log hasn't been tampered with.")

    args = parser.parse_args()
    try:
        if args.command == "predict":
            cmd_predict(args.item_dir)
        elif args.command == "verify":
            cmd_verify()
    except GuardError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
