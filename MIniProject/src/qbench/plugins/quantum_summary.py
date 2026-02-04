from __future__ import annotations


def get_plugin_info() -> dict:
    return {
        "name": "quantum_summary",
        "description": "Summarizes a quantum run payload.",
        "version": "1.0.0",
    }


def run(payload: dict) -> dict:
    metrics = payload.get("metrics", {})
    return {
        "algorithm": payload.get("algorithm"),
        "shots": payload.get("shots"),
        "noise_level": payload.get("noise_level"),
        "success_probability": metrics.get("success_probability"),
        "error_rate": metrics.get("error_rate"),
    }
