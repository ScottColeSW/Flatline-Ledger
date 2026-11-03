# Flatline Ledger

A predict-then-verify range for classic penetration testing and purple team work, scored the way [Agent Defense Theater](https://github.com/ScottColeSW/Agent-Defense-Theater) scores agentic risk: every control gets two numbers together, the exploits it stops and the legitimate work it still allows. Targets are intentionally-vulnerable local lab applications, never a live client environment.

In current analyst terms, this is a **CTEM** (Continuous Threat Exposure Management) program's **AEV** (Adversarial Exposure Validation) layer: the category that replaced "breach and attack simulation" and "automated pen testing" as separate labels. Flatline Ledger builds that layer for classic AppSec findings (injection, access control, supply chain) the same way its siblings build it for agent behavior.

## Why it exists

Most pen testing deliverables are a report and a handshake: here are the findings, good luck. The remediation gap, whether a patch actually closed what was found, almost never gets re-measured, and the few tools that do re-check tend to treat "exploit payload" and "live client target" as if they belong in the same sentence. They don't. This range keeps the measurement discipline from the agentic-risk repos (predict first, score paired, log hash-chained, report misses) and applies it to lab targets that are safe to actually attack.

## Scope, stated once

- **Lab targets only.** Juice Shop, DVWA, WebGoat, and similar intentionally-vulnerable apps, run locally in containers you control. Nothing here is built to point at a URL you don't own.
- **No live credentials, no production tickets.** The Jira/GitHub-Issues loop runs against a sandbox project or this repo's own issue tracker, never a real tenant with real bearer tokens.
- **Evidence, not an audit.** A finding here is a measured result against one lab target under one configuration, not a compliance claim about any organization's actual posture.
- **Early draft.** Structure first, numbers follow. See [docs/OVERLAPS.md](docs/OVERLAPS.md) for how this connects to the other two repos, and `items/*/PREREGISTRATION.md` for what's actually been run versus only planned.

## How it works

1. **Predict.** A prediction file and pass bar are committed before any run, same gate `adt.py` uses: the harness refuses a live run unless the prediction is committed, unedited, and matches the code.
2. **Find.** A finding is recorded as a blueprint: method, endpoint, payload shape, the exact signal that proves the exploit worked, and its MITRE ATT&CK technique ID. No blueprint targets anything outside the pinned lab container.
3. **Patch.** The lab target gets the real fix (a code change, a config change, a WAF rule), not a toggle.
4. **Verify.** The blueprint is replayed against the same lab target, before and after the patch, exactly like ADT's paired attack/defense conditions. A result is `VULNERABLE`, `REMEDIATED`, or `ERROR` (couldn't reach the target), never inferred from a status code alone.
5. **Record.** Every run appends to a hash-chained log (`python ledger.py verify`), and a sandboxed ticket closes or reopens based on the replay, not on a developer's say-so.

## Quick start

Python 3.10 or newer, standard library only for the ledger itself; `httpx` only if you install the `dast` extra.

```bash
python ledger.py predict items/pt01-idor-juice-shop   # commit the prediction before any run
python ledger.py verify                                # check the hash chain
python -m pytest -q
```

Lab targets are brought up with Docker and are not part of this repo; each item's `README.md` names the exact image and pinned tag it was run against (`pt01` uses `bkimminich/juice-shop:v17.3.0`).

## Where this fits next to the other repos

- [Agent Defense Theater](https://github.com/ScottColeSW/Agent-Defense-Theater): the same predict/attack/defend/score/record discipline, aimed at agent tool-use and identity risk instead of classic web vulnerabilities.
- [Project Aegis Vector](https://github.com/ScottColeSW/Project-Aegis-Vector): quantitative metrics (perplexity, cosine shift) for one family of attack, RAG/memory poisoning.
- [ai-agent-exposure-appraisal](https://github.com/ScottColeSW/ai-agent-exposure-appraisal): translates measured findings from all of the above into the questions a CISO, CTO, or CFO actually asks.

Details on specific overlaps (same infrastructure attacked from two angles, shared MITRE mappings) are in [docs/OVERLAPS.md](docs/OVERLAPS.md).

## Results so far

| Item | Finding | Result |
| --- | --- | --- |
| [pt01](items/pt01-idor-juice-shop/) Broken Access Control / IDOR (Juice Shop, T1190) | Any logged-in account's token could read any other account's basket by id; no server-side ownership check | No control: `VULNERABLE` (attacker read victim's basket, HTTP 200). A compensating-control proxy that cross-checks the JWT's caller id against the response body's owner id: `REMEDIATED` (HTTP 403), with both accounts' own basket reads still working in every condition |

## Items

| Item | Finding family | Status |
| --- | --- | --- |
| [pt01-idor-juice-shop](items/pt01-idor-juice-shop/) | Broken access control / IDOR | Run live, 2026-11-03 |

## Keeping this safe

- No blueprint or config may name a host that isn't `localhost`, `127.0.0.1`, or a Docker Compose service name resolved inside this repo's own compose file. A test enforces this before any replay runs.
- No live API keys, Jira tokens, or SIEM credentials are stored in this repo. `keys.example.ini` (when added) is the committed template; real values live in `keys.ini`, which is gitignored, or in environment variables.
- Nothing here generates novel exploit code against a target it hasn't been explicitly pinned to. Blueprints are data, reviewed like any other fixture, not a general-purpose payload generator.
