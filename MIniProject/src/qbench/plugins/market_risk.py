from __future__ import annotations


def get_plugin_info() -> dict:
    return {
        "name": "market_risk",
        "description": "Computes a simple market risk score from counts.",
        "version": "1.0.0",
    }


def run(payload: dict) -> dict:
    funding_rows = payload.get("funding_rows", 0)
    news_items = payload.get("news_items", 0)
    companies = payload.get("companies", 0)
    score = max(0, 100 - (funding_rows * 2 + news_items + companies))
    return {"risk_score": score, "explanation": "Lower is better."}
