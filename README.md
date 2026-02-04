# Q-Bench-A-Hybrid-Quantum-Algorithm-Evaluation-and-Quantum-Market-Intelligence-Platform
Q-Bench is an industry‑grade hybrid desktop + API platform for benchmarking quantum algorithms under noise while delivering quantum market intelligence dashboards, offline‑safe caching, analytics, and extensible plugins—all in a single product-oriented system.

Key Features
Quantum Compute Lab (Grover, Deutsch–Jozsa)
Noise benchmarking with depolarizing noise
Analytics: success probability, error rate, variance
Benchmark comparison dashboard + plots
REST API for quantum and market datasets
Desktop GUI (Tkinter) consuming API with cache fallback
Market intelligence: companies, funding, news, alerts, sentiment
PDF reports + bundle export (plots/CSV)
Plugins system with demo plugins
Login + role gating (admin/researcher)
IBMQ live status + queue chart (token required)
Offline demo-safe cached datasets
Project Structure
src/qbench/api: Flask REST API
src/qbench/engine: Quantum algorithm execution
src/qbench/analytics: Benchmarking & visualization
src/qbench/ingestion: Market data ingestion & caching
src/qbench/gui: Tkinter GUI
src/qbench/data: cached datasets
docs: documentation assets
scripts: helper run scripts
Quick Start (Windows)
Create a virtual environment and install dependencies:
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
Start API:
python scripts/run_api.py
Start GUI:
python scripts/run_gui.py
Login
On first launch, register a local user and then log in. Roles:

researcher: standard access
admin: can run admin-only plugins (e.g., export_snapshot)
IBMQ Live Status (Optional)
Provide an IBM Quantum token in the Reports tab, then click “Check Status”.

Offline Demo Mode
If the API is unreachable, the GUI uses local cached datasets under src/qbench/data/cache.

Notes
Qiskit Aer is required for simulations.
The project is designed for local, offline-safe execution.
Documentation
Architecture: docs/architecture.md
API: docs/api_endpoints.md
Runbook: docs/runbook.md
Report Outline: docs/report_outline.md
Screenshot Checklist: docs/screenshots.md
