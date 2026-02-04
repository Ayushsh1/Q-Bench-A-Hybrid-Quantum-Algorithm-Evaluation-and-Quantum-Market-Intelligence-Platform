from __future__ import annotations

from flask import Flask, jsonify, request
from qbench.config import API_HOST, API_PORT, DEFAULT_SHOTS, DEFAULT_NOISE
from qbench.engine.algorithms import run_grover, run_deutsch_jozsa
from qbench.engine.circuits import grover_circuit, deutsch_jozsa_circuit, circuit_to_text
from qbench.analytics.metrics import compute_metrics, benchmark_series
from qbench.analytics.visuals import plot_benchmark, save_benchmark_csv, plot_comparison, plot_sentiment
from qbench.analytics.report import generate_report
from qbench.ingestion.market_data import (
    load_cached_companies,
    load_cached_funding,
    load_cached_news,
    refresh_from_datasets,
    refresh_news_cache,
    load_alerts,
    validate_datasets,
    compute_sentiment,
)
from pathlib import Path
from qbench.config import REPORTS_DIR, IBMQ_CHANNEL, IBMQ_TOKEN_PATH, BUNDLES_DIR, APP_VERSION
import os
from qbench.ingestion.scheduler import start_scheduler
from qbench.config import PLUGINS_DIR
import importlib.util
import os
import zipfile

app = Flask(__name__)
start_scheduler()


def _parse_int(value, default):
    try:
        return int(value)
    except Exception:
        return default


def _parse_float(value, default):
    try:
        return float(value)
    except Exception:
        return default


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/version")
def version():
    return jsonify({"version": APP_VERSION})


@app.route("/")
def root():
    return jsonify({
        "service": "qbench-api",
        "status": "ok",
        "endpoints": [
            "/health",
            "/quantum/grover",
            "/quantum/deutsch-jozsa",
            "/quantum/benchmark",
            "/market/companies",
            "/market/funding",
            "/market/news",
        ],
    })


@app.route("/favicon.ico")
def favicon():
    return ("", 204)


@app.route("/quantum/grover", methods=["POST"])
def api_grover():
    data = request.json or {}
    num_qubits = _parse_int(data.get("num_qubits", 2), 2)
    shots = _parse_int(data.get("shots", DEFAULT_SHOTS), DEFAULT_SHOTS)
    noise_level = _parse_float(data.get("noise_level", DEFAULT_NOISE), DEFAULT_NOISE)

    result = run_grover(num_qubits=num_qubits, shots=shots, noise_level=noise_level)
    metrics = compute_metrics(result["probabilities"], result["expected_state"])
    return jsonify({**result, "metrics": metrics})


@app.route("/quantum/deutsch-jozsa", methods=["POST"])
def api_deutsch_jozsa():
    data = request.json or {}
    num_qubits = _parse_int(data.get("num_qubits", 3), 3)
    shots = _parse_int(data.get("shots", DEFAULT_SHOTS), DEFAULT_SHOTS)
    noise_level = _parse_float(data.get("noise_level", DEFAULT_NOISE), DEFAULT_NOISE)
    balanced = bool(data.get("balanced", True))

    result = run_deutsch_jozsa(
        num_qubits=num_qubits, shots=shots, noise_level=noise_level, balanced=balanced
    )
    metrics = compute_metrics(result["probabilities"], result["expected_state"])
    return jsonify({**result, "metrics": metrics})


@app.route("/quantum/circuit", methods=["POST"])
def api_circuit():
    data = request.json or {}
    algo = data.get("algorithm", "grover")
    num_qubits = _parse_int(data.get("num_qubits", 2), 2)
    balanced = bool(data.get("balanced", True))

    if algo == "deutsch-jozsa":
        qc = deutsch_jozsa_circuit(num_qubits=num_qubits, balanced=balanced)
    else:
        qc = grover_circuit(num_qubits=num_qubits)

    return jsonify({"algorithm": algo, "text": circuit_to_text(qc)})


@app.route("/quantum/circuit-image", methods=["POST"])
def api_circuit_image():
    data = request.json or {}
    algo = data.get("algorithm", "grover")
    num_qubits = _parse_int(data.get("num_qubits", 2), 2)
    balanced = bool(data.get("balanced", True))

    if algo == "deutsch-jozsa":
        qc = deutsch_jozsa_circuit(num_qubits=num_qubits, balanced=balanced)
    else:
        qc = grover_circuit(num_qubits=num_qubits)

    try:
        import matplotlib
        matplotlib.use("Agg")
        fig = qc.draw(output="mpl")
        out_path = Path("plots") / f"circuit_{algo}.png"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        fig.savefig(out_path)
        return jsonify({"plot_path": str(out_path)})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/quantum/benchmark", methods=["POST"])
def api_benchmark():
    data = request.json or {}
    algo = data.get("algorithm", "grover")
    noise_levels = data.get("noise_levels", [0.0, 0.01, 0.05, 0.1])
    shots = _parse_int(data.get("shots", DEFAULT_SHOTS), DEFAULT_SHOTS)
    num_qubits = _parse_int(data.get("num_qubits", 2), 2)

    results = []
    for nl in noise_levels:
        noise = _parse_float(nl, 0.0)
        if algo == "deutsch-jozsa":
            r = run_deutsch_jozsa(num_qubits=num_qubits + 1, shots=shots, noise_level=noise, balanced=True)
        else:
            r = run_grover(num_qubits=num_qubits, shots=shots, noise_level=noise)
        results.append(r)

    benchmarks = benchmark_series(results)["benchmarks"]
    output_plot = Path("plots") / f"benchmark_{algo}.png"
    output_csv = Path("plots") / f"benchmark_{algo}.csv"
    plot_path = plot_benchmark(benchmarks, output_plot)
    csv_path = save_benchmark_csv(benchmarks, output_csv)
    return jsonify({"benchmarks": benchmarks, "plot_path": plot_path, "csv_path": csv_path})


@app.route("/quantum/compare", methods=["POST"])
def api_compare():
    data = request.json or {}
    noise_levels = data.get("noise_levels", [0.0, 0.01, 0.05, 0.1])
    shots = _parse_int(data.get("shots", DEFAULT_SHOTS), DEFAULT_SHOTS)
    num_qubits = _parse_int(data.get("num_qubits", 2), 2)

    results_grover = []
    results_dj = []
    for nl in noise_levels:
        noise = _parse_float(nl, 0.0)
        results_grover.append(run_grover(num_qubits=num_qubits, shots=shots, noise_level=noise))
        results_dj.append(run_deutsch_jozsa(num_qubits=num_qubits + 1, shots=shots, noise_level=noise, balanced=True))

    series = {
        "grover": benchmark_series(results_grover)["benchmarks"],
        "deutsch-jozsa": benchmark_series(results_dj)["benchmarks"],
    }
    output_plot = Path("plots") / "compare_grover_vs_deutsch-jozsa.png"
    plot_path = plot_comparison(series, output_plot)
    return jsonify({"series": series, "plot_path": plot_path, "algorithms": list(series.keys())})


@app.route("/market/companies")
def api_companies():
    refresh_from_datasets()
    df = load_cached_companies()
    return jsonify(df.to_dict(orient="records"))


@app.route("/market/funding")
def api_funding():
    refresh_from_datasets()
    df = load_cached_funding()
    return jsonify(df.to_dict(orient="records"))


@app.route("/market/news")
def api_news():
    refresh_from_datasets()
    items = refresh_news_cache() or load_cached_news()
    return jsonify(items)


@app.route("/market/alerts")
def api_alerts():
    return jsonify(load_alerts())


@app.route("/market/validate")
def api_market_validate():
    return jsonify(validate_datasets())


@app.route("/market/sentiment")
def api_market_sentiment():
    items = load_cached_news()
    sentiment = compute_sentiment(items)
    plot_path = plot_sentiment(sentiment.get("items", []), Path("plots") / "news_sentiment.png")
    return jsonify({"sentiment": sentiment, "plot_path": plot_path})


def _load_plugins():
    plugins = []
    if not PLUGINS_DIR.exists():
        return plugins
    for fname in os.listdir(PLUGINS_DIR):
        if not fname.endswith(".py") or fname.startswith("__"):
            continue
        path = PLUGINS_DIR / fname
        name = fname.replace(".py", "")
        spec = importlib.util.spec_from_file_location(name, path)
        if not spec or not spec.loader:
            continue
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)
            info = mod.get_plugin_info()
            plugins.append(info)
        except Exception:
            continue
    return plugins


@app.route("/plugins/list")
def api_plugins_list():
    return jsonify(_load_plugins())


@app.route("/plugins/run", methods=["POST"])
def api_plugins_run():
    data = request.json or {}
    plugin_name = data.get("plugin")
    payload = data.get("payload", {})

    if not plugin_name:
        return jsonify({"error": "plugin required"}), 400

    path = PLUGINS_DIR / f"{plugin_name}.py"
    if not path.exists():
        return jsonify({"error": "plugin not found"}), 404

    spec = importlib.util.spec_from_file_location(plugin_name, path)
    if not spec or not spec.loader:
        return jsonify({"error": "plugin load failed"}), 500
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    result = mod.run(payload)
    return jsonify({"plugin": plugin_name, "result": result})


@app.route("/quantum/ibmq/status")
def api_ibmq_status():
    token = os.getenv("IBMQ_TOKEN")
    if not token and IBMQ_TOKEN_PATH.exists():
        try:
            token = IBMQ_TOKEN_PATH.read_text(encoding="utf-8").strip()
        except Exception:
            token = None
    if not token:
        return jsonify({
            "status": "not_configured",
            "message": "IBMQ_TOKEN not set. Set environment variable to enable live status.",
        })

    try:
        from qiskit_ibm_runtime import QiskitRuntimeService
        service = QiskitRuntimeService(channel=IBMQ_CHANNEL, token=token)
        backends = service.backends()
        items = []
        for b in backends:
            try:
                status = b.status()
                items.append({
                    "name": b.name,
                    "status": str(status.status).lower(),
                    "pending_jobs": status.pending_jobs,
                })
            except Exception:
                items.append({"name": b.name, "status": "unknown", "pending_jobs": None})

        return jsonify({
            "status": "ok",
            "message": "Live IBMQ status fetched.",
            "backends": items,
        })
    except Exception as exc:
        return jsonify({
            "status": "error",
            "message": f"Failed to fetch IBMQ status: {exc}",
        }), 500


@app.route("/quantum/ibmq/queue-chart")
def api_ibmq_queue_chart():
    token = os.getenv("IBMQ_TOKEN")
    if not token and IBMQ_TOKEN_PATH.exists():
        try:
            token = IBMQ_TOKEN_PATH.read_text(encoding="utf-8").strip()
        except Exception:
            token = None
    if not token:
        return jsonify({"error": "IBMQ_TOKEN not set"}), 400

    try:
        from qiskit_ibm_runtime import QiskitRuntimeService
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        service = QiskitRuntimeService(channel=IBMQ_CHANNEL, token=token)
        backends = service.backends()
        names = []
        pending = []
        for b in backends:
            try:
                status = b.status()
                names.append(b.name)
                pending.append(status.pending_jobs)
            except Exception:
                continue

        out_path = Path("plots") / "ibmq_queue.png"
        plt.figure(figsize=(7, 4))
        plt.bar(names, pending)
        plt.title("IBMQ Pending Jobs")
        plt.ylabel("Pending Jobs")
        plt.xticks(rotation=45, ha="right", fontsize=8)
        plt.tight_layout()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        plt.savefig(out_path)
        plt.close()

        return jsonify({"plot_path": str(out_path)})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/quantum/ibmq/set-token", methods=["POST"])
def api_ibmq_set_token():
    data = request.json or {}
    token = (data.get("token") or "").strip()
    if not token:
        return jsonify({"error": "token required"}), 400
    IBMQ_TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)
    IBMQ_TOKEN_PATH.write_text(token, encoding="utf-8")
    return jsonify({"status": "saved"})


@app.route("/reports/generate", methods=["POST"])
def api_report():
    data = request.json or {}
    refresh_from_datasets()
    report_data = {
        "quantum": data.get("quantum"),
        "benchmark": data.get("benchmark"),
        "comparison": data.get("comparison"),
        "market": {
            "companies_count": len(load_cached_companies()),
            "funding_count": len(load_cached_funding()),
            "news_count": len(load_cached_news()),
        },
    }
    output_path = REPORTS_DIR / "qbench_report.pdf"
    path = generate_report(report_data, output_path)
    return jsonify({"report_path": path})


@app.route("/reports/bundle", methods=["POST"])
def api_report_bundle():
    payload = request.json or {}
    items = payload.get("paths", [])

    BUNDLES_DIR.mkdir(parents=True, exist_ok=True)
    bundle_path = BUNDLES_DIR / "qbench_bundle.zip"

    with zipfile.ZipFile(bundle_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in items:
            try:
                path = Path(p)
                if path.exists():
                    zf.write(path, arcname=path.name)
            except Exception:
                continue

    return jsonify({"bundle_path": str(bundle_path)})


def main():
    app.run(host=API_HOST, port=API_PORT, debug=False)


if __name__ == "__main__":
    main()
