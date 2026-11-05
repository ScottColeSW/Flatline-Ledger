"""
Flatline Ledger "Black Hat vs White Hat" episode player backend.

Serves the captured/replay episode data and, on request, actually runs an
item's real scenario.py and proxy.py against the real running Juice Shop
container (or flatline-juice-shop-unsafe) right now. No simulated data: every
number this returns came from a real subprocess run against a real server.

Run with: python episodes/server.py
Then open http://localhost:8008/
"""

from __future__ import annotations

import sys
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

sys.path.insert(0, str(Path(__file__).resolve().parent))
from episodes import build_episodes, live_summary, run_live  # noqa: E402

FRONTEND_DIR = Path(__file__).resolve().parent / "frontend"

app = FastAPI(title="Flatline Ledger: Black Hat vs White Hat")


@app.get("/api/episodes")
def list_episodes():
    try:
        return build_episodes()
    except Exception as e:
        return JSONResponse({"episodes": [], "error": str(e)}, status_code=500)


@app.post("/api/episodes/{number}/live")
def live_episode(number: int):
    try:
        return run_live(number)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/api/episodes/live")
def live_history():
    return live_summary()


@app.get("/")
def index():
    return FileResponse(str(FRONTEND_DIR / "episodes.html"))


app.mount("/", StaticFiles(directory=str(FRONTEND_DIR)), name="frontend")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8008)
