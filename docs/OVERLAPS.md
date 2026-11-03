# Where this overlaps the other repos

Three repos now measure different slices of the same problem (can an attacker get an AI-adjacent system to do something it shouldn't, and does the fix actually hold). Noted here so the overlap is a design choice, not something a reader has to reconstruct.

## Inside this repo: pt05 closes into pt06

[pt05](../items/pt05-vulnerable-dependency/) found `jsonwebtoken@0.4.0` and `express-jwt@0.1.3` present in Juice Shop's dependency tree, with known algorithm-confusion advisories, but explicitly declined to claim the running app's real authentication path was exploitable through them; SCA detects presence, not exploitation, and said so plainly. [pt06](../items/pt06-jwt-algorithm-confusion/) traced the actual verification code and confirmed it live: a forged HS256 token, signed with the RS256 public key as an HMAC secret, authenticates as admin with zero login. Exactly the loop ADT's own blind-attacker rounds describe (a defense or a risk looking real on paper vs. confirmed against a live attacker), done here with SCA standing in for "on paper" and DAST for "confirmed."

## Agent Defense Theater (ADT)

- **ASI02 (Tool Misuse)** runs a real MCP server (`items/asi02-tool-misuse/targets/real-estate-tools`) that an agent can call. Flatline Ledger's DAST pass can point at the *same* server and ask a different question: not "did the agent choose to misuse this tool" but "does this tool's own HTTP surface have a classic injection or access-control flaw regardless of which agent calls it." Same infrastructure, two angles, worth a shared results table once both have numbers.
- **ASI04 (Supply Chain)** stages a tampered tool in front of a real server. A SAST/dependency scan here against the same staged package is the classic-AppSec half of that story; ADT measures whether the agent's manifest/canary/code-pin controls notice, Flatline Ledger measures whether a standard SCA tool would have flagged the tampering in the first place.
- **blackice** (ADT's OWASP-crosswalk module) already maps agentic risks to a maturity ladder. This repo's MITRE ATT&CK mapping is the classic-AppSec equivalent; the two crosswalks should eventually cite each other rather than duplicate technique IDs independently.

## Project Aegis Vector (PAV)

- PAV's memory-gate work (ASI06, shared with Palimpsest) is about forged documents changing what a model believes. Flatline Ledger doesn't test belief, it tests whether a web application's access control or input handling holds. The overlap is methodological, not infrastructural: both repos score a defense as "held / cost nothing" vs "held / cost something" vs "didn't hold," and both report misses rather than only wins.

## ai-agent-exposure-appraisal

- Once Flatline Ledger has run numbers, it gets its own rows in the appraisal's CISO/CTO/Head-of-AppSec tables, the classic-pentest answers sitting next to the agentic-risk answers for the same executive questions ("which control still holds if the attacker knows it's there," "what does a control cost in work that no longer gets done").

## What hasn't happened yet

Flatline Ledger now has six live items (pt01-pt06) with real numbers of its own. The cross-repo links above (to ADT, PAV, and the exposure-appraisal tables) don't have numbers behind them yet; this file records the intended shape so those results land in the right table instead of a new one, once that work happens.
