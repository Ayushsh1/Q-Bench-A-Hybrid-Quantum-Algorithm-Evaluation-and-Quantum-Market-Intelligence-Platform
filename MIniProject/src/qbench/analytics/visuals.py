from __future__ import annotations

from typing import List, Dict, Any
from pathlib import Path
import pandas as pd


def plot_benchmark(benchmarks: List[Dict[str, Any]], output_path: Path) -> str:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    df = pd.DataFrame(benchmarks)
    plt.figure(figsize=(8, 5))
    plt.plot(df["noise_level"], df["success_probability"], marker="o", label="Success Prob")
    plt.plot(df["noise_level"], df["error_rate"], marker="o", label="Error Rate")
    plt.xlabel("Noise Level")
    plt.ylabel("Metric Value")
    plt.title("Quantum Algorithm Performance vs Noise")
    plt.legend()
    plt.grid(True)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()
    return str(output_path)


def save_benchmark_csv(benchmarks: List[Dict[str, Any]], output_path: Path) -> str:
    df = pd.DataFrame(benchmarks)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_path, index=False)
    return str(output_path)


def plot_comparison(series: Dict[str, List[Dict[str, Any]]], output_path: Path) -> str:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plt.figure(figsize=(8, 5))
    for label, benchmarks in series.items():
        df = pd.DataFrame(benchmarks)
        plt.plot(df["noise_level"], df["success_probability"], marker="o", label=f"{label} Success")

    plt.xlabel("Noise Level")
    plt.ylabel("Success Probability")
    plt.title("Algorithm Comparison vs Noise")
    plt.legend()
    plt.grid(True)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()
    return str(output_path)


def plot_sentiment(items: List[Dict[str, Any]], output_path: Path) -> str:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    if not items:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        plt.figure(figsize=(6, 3))
        plt.text(0.5, 0.5, "No news", ha="center", va="center")
        plt.axis("off")
        plt.savefig(output_path)
        plt.close()
        return str(output_path)

    scores = [i.get("score", 0) for i in items]
    labels = [i.get("date", "") for i in items]
    plt.figure(figsize=(6, 3))
    plt.bar(range(len(scores)), scores)
    plt.xticks(range(len(labels)), labels, rotation=45, ha="right", fontsize=8)
    plt.title("News Sentiment Scores")
    plt.tight_layout()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(output_path)
    plt.close()
    return str(output_path)
