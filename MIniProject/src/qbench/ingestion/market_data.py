from __future__ import annotations

from pathlib import Path
import json
import pandas as pd
import requests
from bs4 import BeautifulSoup

from qbench.config import CACHE_DIR, DATASETS_DIR, NEWS_SOURCE_URLS, ALERTS_PATH


def _read_csv(path: Path) -> pd.DataFrame:
    if not path.exists():
        return pd.DataFrame()
    return pd.read_csv(path)


def _read_json(path: Path):
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def load_cached_companies() -> pd.DataFrame:
    return _read_csv(CACHE_DIR / "companies_cache.csv")


def load_cached_funding() -> pd.DataFrame:
    return _read_csv(CACHE_DIR / "funding_cache.csv")


def load_cached_news():
    return _read_json(CACHE_DIR / "news_cache.json")


def refresh_from_datasets() -> None:
    (CACHE_DIR / "companies_cache.csv").write_text(
        (DATASETS_DIR / "companies.csv").read_text(encoding="utf-8"), encoding="utf-8"
    )
    (CACHE_DIR / "funding_cache.csv").write_text(
        (DATASETS_DIR / "funding.csv").read_text(encoding="utf-8"), encoding="utf-8"
    )
    (CACHE_DIR / "news_cache.json").write_text(
        (DATASETS_DIR / "news.json").read_text(encoding="utf-8"), encoding="utf-8"
    )


def validate_datasets() -> dict:
    issues = []

    companies_path = DATASETS_DIR / "companies.csv"
    funding_path = DATASETS_DIR / "funding.csv"
    news_path = DATASETS_DIR / "news.json"

    if companies_path.exists():
        df = pd.read_csv(companies_path)
        required = {"id", "name", "sector", "country", "year_founded", "website"}
        missing = required - set(df.columns)
        if missing:
            issues.append({"dataset": "companies.csv", "missing_columns": sorted(missing)})
    else:
        issues.append({"dataset": "companies.csv", "error": "file not found"})

    if funding_path.exists():
        df = pd.read_csv(funding_path)
        required = {"year", "sector", "amount_usd_m", "rounds"}
        missing = required - set(df.columns)
        if missing:
            issues.append({"dataset": "funding.csv", "missing_columns": sorted(missing)})
    else:
        issues.append({"dataset": "funding.csv", "error": "file not found"})

    if news_path.exists():
        try:
            items = _read_json(news_path)
            if not isinstance(items, list):
                issues.append({"dataset": "news.json", "error": "not a list"})
            else:
                for i, item in enumerate(items[:10]):
                    if not all(k in item for k in ("date", "title", "source")):
                        issues.append({"dataset": "news.json", "error": f"missing keys at index {i}"})
                        break
        except Exception:
            issues.append({"dataset": "news.json", "error": "invalid json"})
    else:
        issues.append({"dataset": "news.json", "error": "file not found"})

    return {"ok": len(issues) == 0, "issues": issues}


def try_fetch_news_online(url: str) -> list:
    try:
        resp = requests.get(url, timeout=5)
        resp.raise_for_status()
    except Exception:
        return []

    soup = BeautifulSoup(resp.text, "html.parser")
    items = []
    for h in soup.select("h2, h3")[:5]:
        title = h.get_text(strip=True)
        if title:
            items.append({"date": "", "title": title, "source": url})
    return items


def refresh_news_cache() -> list:
    cached = load_cached_news()
    existing_titles = {item.get("title", "").strip().lower() for item in cached}
    fresh_items = []

    for url in NEWS_SOURCE_URLS:
        for item in try_fetch_news_online(url):
            title = item.get("title", "").strip()
            if not title:
                continue
            key = title.lower()
            if key in existing_titles:
                continue
            existing_titles.add(key)
            fresh_items.append(item)

    if fresh_items:
        merged = fresh_items + cached
        with (CACHE_DIR / "news_cache.json").open("w", encoding="utf-8") as f:
            json.dump(merged, f, ensure_ascii=False, indent=2)
        return merged

    return cached


def load_alerts():
    if not ALERTS_PATH.exists():
        return []
    try:
        return json.loads(ALERTS_PATH.read_text(encoding="utf-8"))
    except Exception:
        return []


_POS_WORDS = {"raises", "growth", "breakthrough", "partnership", "funding", "expands", "wins", "record"}
_NEG_WORDS = {"delay", "cut", "decline", "loss", "layoff", "risk", "issue", "drop"}


def compute_sentiment(items: list) -> dict:
    if not items:
        return {"score": 0, "label": "neutral", "items": []}

    scored = []
    total = 0
    for item in items:
        title = (item.get("title") or "").lower()
        pos = sum(1 for w in _POS_WORDS if w in title)
        neg = sum(1 for w in _NEG_WORDS if w in title)
        score = pos - neg
        total += score
        scored.append({**item, "score": score})

    avg = total / max(1, len(items))
    label = "positive" if avg > 0 else "negative" if avg < 0 else "neutral"
    return {"score": round(avg, 2), "label": label, "items": scored}
