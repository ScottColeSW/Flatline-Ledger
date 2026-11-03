# Where this overlaps the other repos

Three repos now measure different slices of the same problem (can an attacker get an AI-adjacent system to do something it shouldn't, and does the fix actually hold). Noted here so the overlap is a design choice, not something a reader has to reconstruct.

## Agent Defense Theater (ADT)

- **ASI02 (Tool Misuse)** runs a real MCP server (`items/asi02-tool-misuse/targets/real-estate-tools`) that an agent can call. Flatline Ledger's DAST pass can point at the *same* server and ask a different question: not "did the agent choose to misuse this tool" but "does this tool's own HTTP surface have a classic injection or access-control flaw regardless of which agent calls it." Same infrastructure, two angles, worth a shared results table once both have numbers.
- **ASI04 (Supply Chain)** stages a tampered tool in front of a real server. A SAST/dependency scan here against the same staged package is the classic-AppSec half of that story; ADT measures whether the agent's manifest/canary/code-pin controls notice, Flatline Ledger measures whether a standard SCA tool would have flagged the tampering in the first place.
- **blackice** (ADT's OWASP-crosswalk module) already maps agentic risks to a maturity ladder. This repo's MITRE ATT&CK mapping is the classic-AppSec equivalent; the two crosswalks should eventually cite each other rather than duplicate technique IDs independently.

## Project Aegis Vector (PAV)

- PAV's memory-gate work (ASI06, shared with Palimpsest) is about forged documents changing what a model believes. Flatline Ledger doesn't test belief, it tests whether a web application's access control or input handling holds. The overlap is methodological, not infrastructural: both repos score a defense as "held / cost nothing" vs "held / cost something" vs "didn't hold," and both report misses rather than only wins.

## ai-agent-exposure-appraisal

- Once Flatline Ledger has run numbers, it gets its own rows in the appraisal's CISO/CTO/Head-of-AppSec tables, the classic-pentest answers sitting next to the agentic-risk answers for the same executive questions ("which control still holds if the attacker knows it's there," "what does a control cost in work that no longer gets done").

## What hasn't happened yet

None of these cross-links have numbers behind them yet; Flatline Ledger itself hasn't run a live item. This file records the intended shape so the first results land in the right table instead of a new one.
