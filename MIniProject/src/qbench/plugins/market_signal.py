from __future__ import annotations

import random
from datetime import datetime


def get_plugin_info() -> dict:
    return {
        "name": "market_signal",
        "description": "Generates a synthetic market signal for demo purposes.",
        "version": "1.0.0",
    }


def run(payload: dict) -> dict:
    seed = payload.get("seed")
    if seed is not None:
        random.seed(seed)
    return {
        "timestamp": datetime.utcnow().isoformat(timespec="seconds"),
        "signal": random.choice(["bullish", "neutral", "bearish"]),
        "confidence": round(random.uniform(0.5, 0.95), 2),
    }
