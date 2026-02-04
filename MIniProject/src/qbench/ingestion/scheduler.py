from __future__ import annotations

import threading
import time
from datetime import datetime
from typing import List

from qbench.config import SCHEDULER_ENABLED, SCHEDULER_INTERVAL_SECONDS, ALERT_MIN_NEW_ITEMS, ALERTS_PATH
from qbench.ingestion.market_data import refresh_news_cache, load_cached_news


_scheduler_started = False


def _write_alerts(alerts: List[dict]) -> None:
    ALERTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    ALERTS_PATH.write_text(__import__("json").dumps(alerts, indent=2), encoding="utf-8")


def _read_alerts() -> List[dict]:
    if not ALERTS_PATH.exists():
        return []
    try:
        return __import__("json").loads(ALERTS_PATH.read_text(encoding="utf-8"))
    except Exception:
        return []


def _tick():
    before = load_cached_news()
    after = refresh_news_cache() or before

    new_count = max(0, len(after) - len(before))
    if new_count >= ALERT_MIN_NEW_ITEMS:
        alerts = _read_alerts()
        alerts.insert(0, {
            "timestamp": datetime.utcnow().isoformat(timespec="seconds"),
            "type": "news_update",
            "message": f"{new_count} new market news items added.",
        })
        _write_alerts(alerts)


def _loop():
    while True:
        try:
            _tick()
        except Exception:
            pass
        time.sleep(SCHEDULER_INTERVAL_SECONDS)


def start_scheduler() -> None:
    global _scheduler_started
    if not SCHEDULER_ENABLED or _scheduler_started:
        return
    t = threading.Thread(target=_loop, daemon=True)
    t.start()
    _scheduler_started = True
