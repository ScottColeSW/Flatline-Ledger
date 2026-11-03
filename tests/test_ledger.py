import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ledger  # noqa: E402


def test_guard_accepts_localhost_variants():
    for host in (
        "http://localhost:3000",
        "https://127.0.0.1:8443",
        "http://[::1]:3000",
    ):
        ledger.guard_target_host(host)  # must not raise


def test_guard_accepts_bare_compose_service_name():
    ledger.guard_target_host("juice-shop")  # must not raise


def test_guard_accepts_host_docker_internal():
    ledger.guard_target_host("http://host.docker.internal:3005")  # must not raise


def test_guard_rejects_real_domain():
    for host in ("https://example.com", "http://my-companys-staging.net", "https://10.0.0.5"):
        try:
            ledger.guard_target_host(host)
        except ledger.GuardError:
            continue
        raise AssertionError(f"expected GuardError for host={host!r}")


def test_no_blueprint_anywhere_in_the_repo_names_a_disallowed_host():
    """Mirrors ADT's key-leak test: scan every committed, non-example blueprint
    and fail the build if any URL-shaped string anywhere in it (not just
    target.host) points outside the localhost allowlist."""
    repo_root = Path(__file__).resolve().parent.parent
    for bp in repo_root.rglob("*.json"):
        if bp.name.endswith(".example.json"):
            continue
        if "blueprints" not in bp.parts:
            continue
        data = json.loads(bp.read_text())
        ledger.guard_all_urls_in(data)  # raises GuardError -> fails this test


def test_hash_chain_round_trip(tmp_path, monkeypatch):
    log_path = tmp_path / "ledger_log.jsonl"
    monkeypatch.setattr(ledger, "LOG_PATH", log_path)
    ledger._append_log({"event": "a"})
    ledger._append_log({"event": "b"})
    ledger.cmd_verify()  # must not raise


def test_hash_chain_detects_tampering(tmp_path, monkeypatch):
    log_path = tmp_path / "ledger_log.jsonl"
    monkeypatch.setattr(ledger, "LOG_PATH", log_path)
    ledger._append_log({"event": "a"})
    lines = log_path.read_text().splitlines()
    entry = json.loads(lines[0])
    entry["event"] = "tampered"
    log_path.write_text(json.dumps(entry, sort_keys=True) + "\n")
    try:
        ledger.cmd_verify()
    except ledger.GuardError:
        return
    raise AssertionError("expected tampering to be detected")
