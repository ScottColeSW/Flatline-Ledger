"""
Episode script for the Flatline Ledger "Black Hat vs White Hat" player.

Each episode is one real item from this repo: a real exploit run against the
real OWASP Juice Shop container, and the real compensating-control fix that
stops it. Every line of narration here is a restatement of that item's own
blueprints/*.json and README.md, already verified, predicted, and committed;
nothing here is invented for the player. REPLAY shows the most recent saved
results/*.json pair for the item (a real run, just not from this exact
moment). RUN LIVE actually invokes that item's own scenario.py and proxy.py
against the real running container right now.

Standard library only, except FastAPI/uvicorn for server.py (not this file).
"""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ITEMS_DIR = ROOT / "items"
PYTHON = sys.executable

MAIN_HEALTH_URL = "http://localhost:3001/"
UNSAFE_HEALTH_URL = "http://localhost:3012/"

# (number, item dir, title, narration, which container, which port the item's
#  own proxy.py listens on (None for the two config-pairing items that have
#  no proxy.py: pt41 uses --mode safe/unsafe instead))
SCRIPT = [
    {
        "number": 1,
        "item": "pt32-forged-discount-coupon",
        "title": "The Forged Coupon",
        "mechanism": "crypto",
        "black": "Black Hat computes a 90%-off coupon entirely offline: the current month, a discount percentage, and a public, unkeyed encoding. No account needed to generate it, no server interaction at all.",
        "white": "White Hat becomes the real issuing authority instead: an HMAC-signed coupon only it can produce, verified before anything is translated and forwarded.",
        "container": "main",
        "proxy_port": 3033,
    },
    {
        "number": 2,
        "item": "pt37-chatbot-coupon-leak",
        "title": "Just Keep Asking",
        "mechanism": "social",
        "black": "Black Hat asks the support chatbot for a coupon code. Refused. Asks again. And again.",
        "white": "White Hat watches every chatbot reply for the one canned answer that's actually a function call handing out a real coupon, and swaps it for a refusal before it ever reaches the browser.",
        "container": "main",
        "proxy_port": 3038,
    },
    {
        "number": 3,
        "item": "pt38-sqli-search-credential-schema-dump",
        "title": "The Search Box That Knew Too Much",
        "mechanism": "injection",
        "black": "Black Hat types a UNION SELECT into the product search box. No login, no special access, just the same public search field every customer uses.",
        "white": "White Hat watches for the one keyword pairing that makes this specific technique possible and blocks it before the database ever sees it.",
        "container": "main",
        "proxy_port": 3039,
    },
    {
        "number": 4,
        "item": "pt27-yaml-bomb-dos",
        "title": "Death by a Thousand Laughs",
        "mechanism": "dos",
        "black": "Black Hat attaches a YAML file to a complaint. Nothing dramatic in it, just nested references that multiply into millions of entries the moment the server tries to read them, five at once.",
        "white": "White Hat counts how many of these one caller sends and cuts them off after the first, before the server ever starts parsing a second.",
        "container": "unsafe",
        "proxy_port": 3028,
    },
    {
        "number": 5,
        "item": "pt31-wallet-checkout-crash",
        "title": "The Checkout That Took Everyone Down",
        "mechanism": "crash",
        "black": "Black Hat does something every real customer eventually does by accident: tries to check out with less in the wallet than the order costs.",
        "white": "White Hat checks the balance itself, in front of the real checkout, and answers politely instead of letting the request reach the code that crashes the whole server.",
        "container": "unsafe",
        "proxy_port": 3032,
    },
    {
        "number": 6,
        "item": "pt41-ssti-eval-rce",
        "title": "What's in a Name",
        "mechanism": "rce",
        "black": "Black Hat sets a username. Not a name: a snippet of real JavaScript, wrapped in a pattern that looks harmless.",
        "white": "White Hat never ships the setting that makes this reachable outside a sealed test environment in the first place.",
        "container": "unsafe-config",  # pt41 has no proxy.py; the "fix" is the default config vs. config/unsafe.yml
        "proxy_port": None,
    },
]


def _extract_section(readme_text: str, heading: str) -> str:
    pattern = re.compile(rf"^## {re.escape(heading)}\s*$(.*?)(?=^## |\Z)", re.MULTILINE | re.DOTALL)
    match = pattern.search(readme_text)
    return match.group(1).strip() if match else ""


def _latest_result(item: str, status: str, mode: str | None = None):
    results_dir = ITEMS_DIR / item / "results"
    if not results_dir.exists():
        return None
    candidates = sorted(results_dir.glob("*.json"), key=lambda p: p.stat().st_mtime)
    for path in reversed(candidates):
        if mode and f"-{mode}-" not in path.name:
            continue
        try:
            data = json.loads(path.read_text())
        except Exception:
            continue
        if data.get("status") == status:
            return data
    return None


def build_episodes() -> dict:
    episodes = []
    for ep in SCRIPT:
        item = ep["item"]
        readme_path = ITEMS_DIR / item / "README.md"
        readme_text = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""
        # Config-pairing items (no proxy.py: pt10, pt40, pt41) don't have a
        # "## The fix" section since there's no proxy to describe; their real
        # fix is documented in "What this does not show" instead.
        fix_narration = _extract_section(readme_text, "The fix") or _extract_section(readme_text, "What this does not show")

        if ep["container"] == "unsafe-config":
            vulnerable = _latest_result(item, "VULNERABLE", mode="unsafe")
            remediated = _latest_result(item, "REMEDIATED", mode="safe")
        else:
            vulnerable = _latest_result(item, "VULNERABLE")
            remediated = _latest_result(item, "REMEDIATED")

        episodes.append({
            **ep,
            "id": str(ep["number"]),
            "fix_narration": fix_narration,
            "vulnerable_result": vulnerable,
            "remediated_result": remediated,
        })
    return {"episodes": episodes, "battery": battery_tally(episodes)}


def battery_tally(episodes: list[dict]) -> dict:
    scored = [e for e in episodes if e.get("vulnerable_result") and e.get("remediated_result")]
    return {
        "total": len(episodes),
        "scored": len(scored),
        "black_wins_blocked": len(scored),  # every pilot episode here has a confirmed fix
    }


# -- live runs --------------------------------------------------------------

LIVE_LOG = ROOT / "episodes" / "results" / "live" / "live_runs.jsonl"


def _get(url: str, timeout: float = 5.0) -> int | None:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.status
    except Exception:
        return None


def _wait_for_health(url: str, attempts: int = 10, delay: float = 1.5) -> bool:
    for _ in range(attempts):
        if _get(url) == 200:
            return True
        time.sleep(delay)
    return False


def _port_open(port: int, host: str = "127.0.0.1") -> bool:
    try:
        with socket.create_connection((host, port), timeout=1.0):
            return True
    except OSError:
        return False


def _wait_for_port(port: int, attempts: int = 10, delay: float = 0.75) -> bool:
    """Waits for something to be listening on a port, without assuming it
    answers GET / with 200: some of this repo's proxy.py scripts only ever
    implement do_POST (their exploit is POST-only), and would otherwise
    answer a GET health check with a 501 forever."""
    for _ in range(attempts):
        if _port_open(port):
            return True
        time.sleep(delay)
    return False


def _restart_unsafe_container() -> bool:
    subprocess.run(["docker", "start", "flatline-juice-shop-unsafe"], capture_output=True, timeout=30)
    return _wait_for_health(UNSAFE_HEALTH_URL)


def _run_scenario(item: str, extra_args: list[str], timeout: float = 90.0) -> dict:
    """Runs an item's real scenario.py and parses its one pretty-printed JSON
    result from stdout (the whole of stdout is that one json.dumps(..., indent=2)
    call; nothing else is printed before it)."""
    scenario_path = ITEMS_DIR / item / "scenario.py"
    try:
        proc = subprocess.run(
            [PYTHON, str(scenario_path), *extra_args],
            capture_output=True, text=True, timeout=timeout, cwd=str(ROOT),
        )
    except subprocess.TimeoutExpired:
        return {"status": "ERROR", "summary": f"scenario.py timed out after {timeout}s"}

    if not proc.stdout.strip():
        return {"status": "ERROR", "summary": (proc.stderr or "no output")[-500:]}
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"status": "ERROR", "summary": proc.stdout[-500:] or proc.stderr[-500:]}


def run_live(number: int) -> dict:
    """Runs one episode's real exploit, then its real fix, live, right now.
    Returns {"vulnerable": <result>, "remediated": <result>}."""
    ep = next((e for e in SCRIPT if e["number"] == number), None)
    if ep is None:
        return {"error": f"no episode #{number}"}

    item = ep["item"]
    container = ep["container"]

    if container == "unsafe":
        if not _wait_for_health(UNSAFE_HEALTH_URL, attempts=3, delay=1.0):
            if not _restart_unsafe_container():
                return {"error": "flatline-juice-shop-unsafe did not come up in time"}

    if container == "unsafe-config":
        vulnerable = _run_scenario(item, ["--mode", "unsafe"])
        remediated = _run_scenario(item, ["--mode", "safe"])
        _record_live(number, ep["title"], vulnerable, remediated)
        return {"vulnerable": vulnerable, "remediated": remediated}

    # main or unsafe container, proxy.py-based items
    vulnerable = _run_scenario(item, [])

    if container == "unsafe":
        # the exploit may have crashed the container (pt27, pt31 by design);
        # restart it before starting the proxy and running the fix.
        if not _wait_for_health(UNSAFE_HEALTH_URL, attempts=2, delay=1.0):
            _restart_unsafe_container()

    proxy_path = ITEMS_DIR / item / "proxy.py"
    proxy_port = ep["proxy_port"]
    backend = UNSAFE_HEALTH_URL.rstrip("/") if container == "unsafe" else None
    env = {**os.environ}
    if backend:
        env["FLATLINE_BACKEND"] = backend
    proxy_proc = subprocess.Popen(
        [PYTHON, str(proxy_path)], cwd=str(ROOT), env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        if not _wait_for_port(proxy_port, attempts=8, delay=0.75):
            remediated = {"status": "ERROR", "summary": "proxy did not come up in time"}
        else:
            remediated = _run_scenario(item, ["--target", f"http://localhost:{proxy_port}"])
    finally:
        proxy_proc.terminate()
        try:
            proxy_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy_proc.kill()

    if container == "unsafe":
        if not _wait_for_health(UNSAFE_HEALTH_URL, attempts=2, delay=1.0):
            _restart_unsafe_container()

    _record_live(number, ep["title"], vulnerable, remediated)
    return {"vulnerable": vulnerable, "remediated": remediated}


def _record_live(number: int, title: str, vulnerable: dict, remediated: dict) -> None:
    LIVE_LOG.parent.mkdir(parents=True, exist_ok=True)
    row = {
        "at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "number": number, "title": title,
        "vulnerable_status": vulnerable.get("status"),
        "remediated_status": remediated.get("status"),
    }
    with LIVE_LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row) + "\n")


def live_summary(limit: int = 200) -> dict:
    if not LIVE_LOG.exists():
        return {"runs": []}
    lines = LIVE_LOG.read_text(encoding="utf-8").splitlines()[-limit:]
    runs = [json.loads(line) for line in lines if line.strip()]
    runs.reverse()
    return {"runs": runs, "count": len(runs)}
