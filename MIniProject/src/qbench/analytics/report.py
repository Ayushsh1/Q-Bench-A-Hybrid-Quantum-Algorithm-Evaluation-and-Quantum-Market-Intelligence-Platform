from __future__ import annotations

from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.pdfgen import canvas


def _draw_section_title(c: canvas.Canvas, title: str, y: float) -> float:
    c.setFont("Helvetica-Bold", 12)
    c.drawString(2 * cm, y, title)
    return y - 0.6 * cm


def _draw_kv(c: canvas.Canvas, data: Dict[str, Any], y: float) -> float:
    c.setFont("Helvetica", 10)
    for k, v in data.items():
        c.drawString(2.2 * cm, y, f"{k}: {v}")
        y -= 0.5 * cm
    return y


def generate_report(report_data: Dict[str, Any], output_path: Path) -> str:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    c = canvas.Canvas(str(output_path), pagesize=A4)
    width, height = A4

    c.setFont("Helvetica-Bold", 16)
    c.drawString(2 * cm, height - 2 * cm, "Q-Bench Report")
    c.setFont("Helvetica", 10)
    c.drawString(2 * cm, height - 2.6 * cm, f"Generated: {datetime.now().isoformat(timespec='seconds')}")

    y = height - 3.6 * cm

    quantum = report_data.get("quantum", {})
    if quantum:
        y = _draw_section_title(c, "Quantum Run Summary", y)
        y = _draw_kv(c, {
            "Algorithm": quantum.get("algorithm"),
            "Shots": quantum.get("shots"),
            "Noise": quantum.get("noise_level"),
            "Expected State": quantum.get("expected_state"),
            "Success Probability": quantum.get("metrics", {}).get("success_probability"),
            "Error Rate": quantum.get("metrics", {}).get("error_rate"),
        }, y)

    benchmark = report_data.get("benchmark", {})
    if benchmark:
        y = _draw_section_title(c, "Benchmark Summary", y)
        y = _draw_kv(c, {
            "Algorithm": benchmark.get("algorithm"),
            "Noise Levels": ", ".join(map(str, benchmark.get("noise_levels", []))),
            "Plot Path": benchmark.get("plot_path"),
            "CSV Path": benchmark.get("csv_path"),
        }, y)

    compare = report_data.get("comparison", {})
    if compare:
        y = _draw_section_title(c, "Comparison Summary", y)
        y = _draw_kv(c, {
            "Algorithms": ", ".join(compare.get("algorithms", [])),
            "Plot Path": compare.get("plot_path"),
        }, y)

    market = report_data.get("market", {})
    if market:
        y = _draw_section_title(c, "Market Snapshot", y)
        y = _draw_kv(c, {
            "Companies": market.get("companies_count"),
            "Funding Rows": market.get("funding_count"),
            "News Items": market.get("news_count"),
        }, y)

    c.showPage()
    c.save()
    return str(output_path)
