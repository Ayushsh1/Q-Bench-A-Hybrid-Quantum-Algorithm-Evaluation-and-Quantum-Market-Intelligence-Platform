from __future__ import annotations

from typing import Dict, Any, List
import numpy as np


def compute_metrics(probabilities: Dict[str, float], expected_state: str) -> Dict[str, float]:
    success_prob = probabilities.get(expected_state, 0.0)
    error_rate = 1.0 - success_prob

    values = np.array(list(probabilities.values()))
    variance = float(np.var(values)) if values.size else 0.0

    return {
        "success_probability": float(success_prob),
        "error_rate": float(error_rate),
        "variance": float(variance),
    }


def benchmark_series(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    rows = []
    for r in results:
        metrics = compute_metrics(r["probabilities"], r["expected_state"])
        rows.append({
            "noise_level": r["noise_level"],
            **metrics,
        })
    return {"benchmarks": rows}
