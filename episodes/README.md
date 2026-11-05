# Black Hat vs White Hat: the episode player

A visual, side-by-side player for a pilot batch of six items from this repo, in the same spirit as [Project-Aegis-Vector](https://github.com/ScottColeSW/Project-Aegis-Vector)'s own Black Hat vs White Hat player. Everything it shows comes from a real run: REPLAY shows the most recent saved `results/*.json` pair for an item; RUN LIVE actually invokes that item's own `scenario.py` and `proxy.py` against the real running Juice Shop container (or `flatline-juice-shop-unsafe`) right now. No simulated data, no invented narration, no fakery, every narration line is a restatement of that item's own already-verified `blueprints/*.json` and `README.md`.

## Pilot episodes

1. **The Forged Coupon** — [pt32](../items/pt32-forged-discount-coupon/)
2. **Just Keep Asking** — [pt37](../items/pt37-chatbot-coupon-leak/)
3. **The Search Box That Knew Too Much** — [pt38](../items/pt38-sqli-search-credential-schema-dump/)
4. **Death by a Thousand Laughs** — [pt27](../items/pt27-yaml-bomb-dos/) (runs against `flatline-juice-shop-unsafe`)
5. **The Checkout That Took Everyone Down** — [pt31](../items/pt31-wallet-checkout-crash/) (runs against `flatline-juice-shop-unsafe`; a live run genuinely crashes and auto-restarts the container)
6. **What's in a Name** — [pt41](../items/pt41-ssti-eval-rce/) (config pairing, no `proxy.py`: safe default vs. `NODE_ENV=unsafe`)

## Running it

```bash
pip install -r episodes/requirements.txt
docker start flatline-juice-shop            # needed for episodes 1-3
docker start flatline-juice-shop-unsafe     # needed for episodes 4-6
python episodes/server.py
```

Then open `http://localhost:8008/`.

## What RUN LIVE actually does

For each episode, the backend (`episodes.py`) shells out to that item's real `scenario.py` (pre-fix, direct against the real container), then starts that item's real `proxy.py` as a subprocess and re-runs `scenario.py --target http://localhost:<proxy-port>` (post-fix). For the two episodes that target `flatline-juice-shop-unsafe`, it checks the container's health before and after, and restarts it automatically if the exploit took it down, exactly what pt27 and pt31's own write-ups already document happening during the original live runs. Episode 6 (pt41) has no `proxy.py` to start; "fixed" there means re-running with `--mode safe` against the default container instead of `--mode unsafe`.

## What this does not show

- This is a pilot of 6 of the repo's 41 items, not all of them. Expanding to more episodes means adding entries to `SCRIPT` in `episodes.py`; the narration-extraction and live-run machinery doesn't care how many there are.
- No screenshot capture of the real Juice Shop UI yet. Each pane renders the real request/response JSON instead, which is more directly verifiable than a screenshot but less visually "a browser window." A v2 could add real browser screenshots per beat using the same real-run pipeline.
- Live runs are not rate-limited or queued; running several in quick succession, especially the two `-unsafe` episodes, will be slower and should be done one at a time, same as every other live run in this repo.
