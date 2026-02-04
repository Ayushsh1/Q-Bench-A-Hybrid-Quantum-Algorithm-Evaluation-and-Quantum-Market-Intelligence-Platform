from __future__ import annotations

import json
from pathlib import Path
import tkinter as tk
from tkinter import messagebox, filedialog
from datetime import datetime
import requests
import pandas as pd
import bcrypt

try:
    import ttkbootstrap as ttk
    _HAS_TTKB = True
except Exception:
    from tkinter import ttk
    _HAS_TTKB = False

from qbench.config import API_HOST, API_PORT, CACHE_DIR, MARKET_AUTO_REFRESH_SECONDS, EXPERIMENTS_PATH, HISTORY_PATH, USERS_PATH, UPDATE_INFO_PATH

API_BASE = f"http://{API_HOST}:{API_PORT}"
OUTPUT_TEXT_HEIGHT = 18
MARKET_TABLE_HEIGHT = OUTPUT_TEXT_HEIGHT


def _safe_get(url: str, default):
    try:
        r = requests.get(url, timeout=3)
        r.raise_for_status()
        return r.json()
    except Exception:
        return default


def _safe_post(url: str, payload: dict, default):
    try:
        r = requests.post(url, json=payload, timeout=5)
        r.raise_for_status()
        return r.json()
    except Exception:
        return default


class QBenchGUI(ttk.Window if _HAS_TTKB else tk.Tk):
    def __init__(self):
        if _HAS_TTKB:
            super().__init__(themename="darkly")
        else:
            super().__init__()
        self.title("Q-Bench")
        self.geometry("1100x750")
        self.configure(bg="#f6f7fb")

        self.last_quantum_result = None
        self.last_benchmark_result = None
        self.last_compare_result = None
        self.last_market_snapshot = None
        self.benchmark_image = None
        self.compare_image = None
        self._loading = False
        self._loading_dots = 0
        self._auto_refresh = False

        self._apply_theme()

        self.current_user = {"name": "guest", "role": "researcher"}

        self.tabs = ttk.Notebook(self)
        self.tabs.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)

        self._build_quantum_lab()
        self._build_benchmark_tab()
        self._build_market_dashboard()
        self._build_reports_tab()
        self._build_experiments_tab()
        self._build_plugins_tab()
        self._build_history_tab()

        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(self, textvariable=self.status_var, anchor="w")
        status_bar.pack(fill=tk.X, side=tk.BOTTOM, padx=10, pady=(0, 8))

        self.tabs.pack_forget()
        self._show_login()

    def _apply_theme(self):
        if _HAS_TTKB:
            return
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure("TFrame", background="#f6f7fb")
        style.configure("TLabelframe", background="#f6f7fb")
        style.configure("TLabelframe.Label", background="#f6f7fb", font=("Segoe UI", 10, "bold"))
        style.configure("TLabel", background="#f6f7fb", font=("Segoe UI", 10))
        style.configure("TButton", font=("Segoe UI", 10))
        style.configure("Header.TLabel", font=("Segoe UI", 14, "bold"))
        style.configure("Subheader.TLabel", font=("Segoe UI", 11, "bold"))

    def _set_status(self, text: str):
        user = self.current_user.get("name", "guest")
        role = self.current_user.get("role", "researcher")
        self.status_var.set(f"{text} | User: {user} ({role})")

    def _show_login(self):
        self.login_frame = ttk.Frame(self)
        self.login_frame.pack(fill=tk.BOTH, expand=True, padx=80, pady=80)

        header = ttk.Label(self.login_frame, text="Q-Bench Access", style="Header.TLabel")
        header.pack(anchor="center", pady=(14, 6))

        card = ttk.LabelFrame(self.login_frame, text="Sign In / Register")
        card.pack(fill=tk.BOTH, expand=True, padx=16, pady=10)

        ttk.Label(card, text="Username").pack(anchor="w", padx=12, pady=(10, 4))
        name_var = tk.StringVar()
        ttk.Entry(card, textvariable=name_var).pack(fill=tk.X, padx=12)

        ttk.Label(card, text="Password").pack(anchor="w", padx=12, pady=(10, 4))
        pass_var = tk.StringVar()
        ttk.Entry(card, textvariable=pass_var, show="*").pack(fill=tk.X, padx=12)

        ttk.Label(card, text="Role").pack(anchor="w", padx=12, pady=(10, 4))
        role_var = tk.StringVar(value="researcher")
        ttk.Combobox(card, textvariable=role_var, values=["researcher", "admin"], state="readonly").pack(fill=tk.X, padx=12)

        def submit():
            name = (name_var.get() or "guest").strip()
            role = role_var.get() or "researcher"
            password = pass_var.get()

            if not self._verify_user(name, password):
                messagebox.showerror("Login", "Invalid username or password.")
                return

            self.current_user = {"name": name, "role": role}
            self._set_status("Ready")
            self.login_frame.destroy()
            self.tabs.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)

        def register():
            name = (name_var.get() or "").strip()
            role = role_var.get() or "researcher"
            password = pass_var.get()
            if not name or not password:
                messagebox.showinfo("Register", "Enter username and password.")
                return
            if self._user_exists(name):
                messagebox.showinfo("Register", "User already exists.")
                return
            self._create_user(name, role, password)
            messagebox.showinfo("Register", "User created. You can now login.")

        btns = ttk.Frame(card)
        btns.pack(pady=14)
        ttk.Button(btns, text="Login", command=submit).pack(side=tk.LEFT, padx=6)
        ttk.Button(btns, text="Register", command=register).pack(side=tk.LEFT, padx=6)

    def _save_user(self, user: dict):
        users = []
        if USERS_PATH.exists():
            try:
                users = json.loads(USERS_PATH.read_text(encoding="utf-8"))
            except Exception:
                users = []
        users = [u for u in users if u.get("name") != user.get("name")]
        users.insert(0, user)
        USERS_PATH.parent.mkdir(parents=True, exist_ok=True)
        USERS_PATH.write_text(json.dumps(users, indent=2), encoding="utf-8")

    def _load_users(self):
        if not USERS_PATH.exists():
            return []
        try:
            return json.loads(USERS_PATH.read_text(encoding="utf-8"))
        except Exception:
            return []

    def _user_exists(self, name: str) -> bool:
        return any(u.get("name") == name for u in self._load_users())

    def _create_user(self, name: str, role: str, password: str) -> None:
        users = self._load_users()
        pw_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        users.insert(0, {"name": name, "role": role, "password": pw_hash})
        USERS_PATH.parent.mkdir(parents=True, exist_ok=True)
        USERS_PATH.write_text(json.dumps(users, indent=2), encoding="utf-8")

    def _verify_user(self, name: str, password: str) -> bool:
        users = self._load_users()
        for u in users:
            if u.get("name") == name:
                pw_hash = u.get("password", "").encode("utf-8")
                return bcrypt.checkpw(password.encode("utf-8"), pw_hash)
        return False

    def _start_loading(self, message: str = "Loading"):
        self._loading = True
        self._loading_dots = 0
        self._set_status(message)
        self._animate_loading(message)

    def _stop_loading(self, message: str = "Ready"):
        self._loading = False
        self._set_status(message)

    def _animate_loading(self, message: str):
        if not self._loading:
            return
        self._loading_dots = (self._loading_dots + 1) % 4
        dots = "." * self._loading_dots
        self._set_status(f"{message}{dots}")
        self.after(300, lambda: self._animate_loading(message))

    def _build_quantum_lab(self):
        frame = ttk.Frame(self.tabs)
        self.tabs.add(frame, text="Quantum Compute Lab")

        header = ttk.Label(frame, text="Quantum Compute Lab", style="Header.TLabel")
        header.pack(anchor="w", padx=10, pady=(10, 4))

        controls = ttk.LabelFrame(frame, text="Run Configuration")
        controls.pack(fill=tk.X, padx=10, pady=10)

        ttk.Label(controls, text="Algorithm").grid(row=0, column=0, sticky=tk.W)
        self.algo_var = tk.StringVar(value="grover")
        ttk.Combobox(controls, textvariable=self.algo_var, values=["grover", "deutsch-jozsa"], width=20).grid(row=0, column=1)

        ttk.Label(controls, text="Qubits").grid(row=0, column=2, sticky=tk.W)
        self.qubits_var = tk.IntVar(value=2)
        ttk.Entry(controls, textvariable=self.qubits_var, width=10).grid(row=0, column=3)

        ttk.Label(controls, text="Shots").grid(row=0, column=4, sticky=tk.W)
        self.shots_var = tk.IntVar(value=1024)
        ttk.Entry(controls, textvariable=self.shots_var, width=10).grid(row=0, column=5)

        ttk.Label(controls, text="Noise Level").grid(row=0, column=6, sticky=tk.W)
        self.noise_var = tk.DoubleVar(value=0.01)
        ttk.Entry(controls, textvariable=self.noise_var, width=10).grid(row=0, column=7)

        ttk.Button(controls, text="Run", command=self._run_quantum).grid(row=0, column=8, padx=10)
        ttk.Button(controls, text="Export CSV", command=self._export_quantum_csv).grid(row=0, column=9, padx=10)
        ttk.Button(controls, text="View Circuit", command=self._view_circuit).grid(row=0, column=10, padx=10)
        ttk.Button(controls, text="Circuit Diagram", command=self._view_circuit_image).grid(row=0, column=11, padx=10)

        result_frame = ttk.LabelFrame(frame, text="Run Output")
        result_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        self.output = tk.Text(result_frame, height=OUTPUT_TEXT_HEIGHT, wrap=tk.WORD)
        self.output.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

    def _build_market_dashboard(self):
        frame = ttk.Frame(self.tabs)
        self.tabs.add(frame, text="Market & Intelligence")

        canvas = tk.Canvas(frame, highlightthickness=0)
        scroll_y = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=canvas.yview)
        canvas.configure(yscrollcommand=scroll_y.set)
        scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        content = ttk.Frame(canvas)
        content_window = canvas.create_window((0, 0), window=content, anchor="nw")
        content.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(content_window, width=e.width))

        header = ttk.Label(content, text="Quantum Market & Intelligence", style="Header.TLabel")
        header.pack(anchor="w", padx=10, pady=(10, 4))

        actions = ttk.Frame(content)
        actions.pack(fill=tk.X, padx=10, pady=(0, 8))
        ttk.Button(actions, text="Refresh", command=self._refresh_market).pack(side=tk.LEFT)
        ttk.Button(actions, text="Validate Data", command=self._validate_market).pack(side=tk.LEFT, padx=8)
        self.auto_refresh_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            actions,
            text="Auto Refresh",
            variable=self.auto_refresh_var,
            command=self._toggle_auto_refresh,
        ).pack(side=tk.LEFT, padx=10)
        self.last_updated_var = tk.StringVar(value="Last updated: -")
        ttk.Label(actions, textvariable=self.last_updated_var).pack(side=tk.LEFT, padx=10)

        grid = ttk.Frame(content)
        grid.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        grid.columnconfigure(0, weight=1)
        grid.columnconfigure(1, weight=1)
        grid.rowconfigure(1, weight=1)

        ttk.Label(grid, text="Companies", style="Subheader.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 4))
        ttk.Label(grid, text="Funding", style="Subheader.TLabel").grid(row=0, column=1, sticky="w", pady=(0, 4))

        self.companies_table = ttk.Treeview(grid, columns=("name", "sector", "country", "year"), show="headings", height=MARKET_TABLE_HEIGHT)
        self.companies_table.heading("name", text="Name")
        self.companies_table.heading("sector", text="Sector")
        self.companies_table.heading("country", text="Country")
        self.companies_table.heading("year", text="Founded")
        self.companies_table.column("name", width=180)
        self.companies_table.column("sector", width=100)
        self.companies_table.column("country", width=100)
        self.companies_table.column("year", width=80)
        self.companies_table.grid(row=1, column=0, sticky="nsew", padx=(0, 8))

        self.funding_table = ttk.Treeview(grid, columns=("year", "sector", "amount", "rounds"), show="headings", height=MARKET_TABLE_HEIGHT)
        self.funding_table.heading("year", text="Year")
        self.funding_table.heading("sector", text="Sector")
        self.funding_table.heading("amount", text="Amount (USD M)")
        self.funding_table.heading("rounds", text="Rounds")
        self.funding_table.column("year", width=80)
        self.funding_table.column("sector", width=100)
        self.funding_table.column("amount", width=140)
        self.funding_table.column("rounds", width=80)
        self.funding_table.grid(row=1, column=1, sticky="nsew")

        news_frame = ttk.LabelFrame(content, text="News Feed")
        news_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        self.news_output = tk.Text(news_frame, height=OUTPUT_TEXT_HEIGHT, wrap=tk.WORD)
        self.news_output.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        charts = ttk.LabelFrame(content, text="Market Analytics")
        charts.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        chart_actions = ttk.Frame(charts)
        chart_actions.pack(fill=tk.X, padx=8, pady=6)
        ttk.Button(chart_actions, text="Generate Funding Chart", command=self._generate_market_chart).pack(side=tk.LEFT)
        ttk.Button(chart_actions, text="Sentiment Analysis", command=self._generate_sentiment_chart).pack(side=tk.LEFT, padx=8)
        self.market_chart_label = ttk.Label(charts)
        self.market_chart_label.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        self.sentiment_label = ttk.Label(charts)
        self.sentiment_label.pack(anchor="w", padx=8, pady=(0, 6))

        alerts = ttk.LabelFrame(content, text="Alerts")
        alerts.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        ttk.Button(alerts, text="Refresh Alerts", command=self._refresh_alerts).pack(anchor="w", padx=8, pady=6)
        self.alerts_output = tk.Text(alerts, height=OUTPUT_TEXT_HEIGHT, wrap=tk.WORD)
        self.alerts_output.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

    def _build_benchmark_tab(self):
        frame = ttk.Frame(self.tabs)
        self.tabs.add(frame, text="Benchmark")

        canvas = tk.Canvas(frame, highlightthickness=0)
        scroll_y = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=canvas.yview)
        canvas.configure(yscrollcommand=scroll_y.set)
        scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        content = ttk.Frame(canvas)
        content_window = canvas.create_window((0, 0), window=content, anchor="nw")
        content.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(content_window, width=e.width))

        header = ttk.Label(content, text="Benchmark Dashboard", style="Header.TLabel")
        header.pack(anchor="w", padx=10, pady=(10, 4))

        controls = ttk.LabelFrame(content, text="Benchmark Configuration")
        controls.pack(fill=tk.X, padx=10, pady=10)

        ttk.Label(controls, text="Algorithm").grid(row=0, column=0, sticky=tk.W)
        self.bench_algo_var = tk.StringVar(value="grover")
        ttk.Combobox(controls, textvariable=self.bench_algo_var, values=["grover", "deutsch-jozsa"], width=20).grid(row=0, column=1)

        ttk.Label(controls, text="Qubits").grid(row=0, column=2, sticky=tk.W)
        self.bench_qubits_var = tk.IntVar(value=2)
        ttk.Entry(controls, textvariable=self.bench_qubits_var, width=10).grid(row=0, column=3)

        ttk.Label(controls, text="Shots").grid(row=0, column=4, sticky=tk.W)
        self.bench_shots_var = tk.IntVar(value=1024)
        ttk.Entry(controls, textvariable=self.bench_shots_var, width=10).grid(row=0, column=5)

        ttk.Label(controls, text="Noise Levels (csv)").grid(row=0, column=6, sticky=tk.W)
        self.bench_noise_var = tk.StringVar(value="0.0,0.01,0.05,0.1")
        ttk.Entry(controls, textvariable=self.bench_noise_var, width=20).grid(row=0, column=7)

        ttk.Button(controls, text="Run Benchmark", command=self._run_benchmark).grid(row=0, column=8, padx=10)
        ttk.Button(controls, text="Compare Algorithms", command=self._run_comparison).grid(row=0, column=9, padx=10)
        ttk.Button(controls, text="Preview Plot", command=self._preview_benchmark_plot).grid(row=0, column=10, padx=10)
        ttk.Button(controls, text="Save Plot As...", command=self._save_benchmark_plot).grid(row=0, column=11, padx=10)
        ttk.Button(controls, text="Save CSV As...", command=self._save_benchmark_csv).grid(row=0, column=12, padx=10)

        output_frame = ttk.LabelFrame(content, text="Benchmark Output")
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        self.benchmark_output = tk.Text(output_frame, height=OUTPUT_TEXT_HEIGHT, wrap=tk.WORD)
        self.benchmark_output.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        preview_frame = ttk.LabelFrame(content, text="Plot Preview")
        preview_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.benchmark_plot_label = ttk.Label(preview_frame)
        self.benchmark_plot_label.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        compare_frame = ttk.LabelFrame(content, text="Comparison Preview")
        compare_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        self.compare_plot_label = ttk.Label(compare_frame)
        self.compare_plot_label.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

    def _build_reports_tab(self):
        frame = ttk.Frame(self.tabs)
        self.tabs.add(frame, text="Reports")

        header = ttk.Label(frame, text="Export Report", style="Header.TLabel")
        header.pack(anchor="w", padx=10, pady=(10, 4))

        actions = ttk.Frame(frame)
        actions.pack(fill=tk.X, padx=10, pady=(0, 8))
        ttk.Button(actions, text="Generate PDF Report", command=self._export_report).pack(side=tk.LEFT)
        ttk.Button(actions, text="Export Bundle", command=self._export_bundle).pack(side=tk.LEFT, padx=8)
        ttk.Button(actions, text="Check Updates", command=self._check_updates).pack(side=tk.LEFT, padx=8)
        self.report_status = tk.StringVar(value="No report generated")
        ttk.Label(actions, textvariable=self.report_status).pack(side=tk.LEFT, padx=10)

        ibm_frame = ttk.LabelFrame(frame, text="IBMQ Live Status")
        ibm_frame.pack(fill=tk.X, padx=10, pady=10)
        ttk.Label(ibm_frame, text="Token").pack(side=tk.LEFT, padx=8)
        self.ibmq_token_var = tk.StringVar()
        ttk.Entry(ibm_frame, textvariable=self.ibmq_token_var, width=40, show="*").pack(side=tk.LEFT, padx=6)
        ttk.Button(ibm_frame, text="Save Token", command=self._save_ibmq_token).pack(side=tk.LEFT, padx=6)
        ttk.Button(ibm_frame, text="Check Status", command=self._check_ibmq_status).pack(side=tk.LEFT, padx=6)
        ttk.Button(ibm_frame, text="Queue Chart", command=self._ibmq_queue_chart).pack(side=tk.LEFT, padx=6)
        self.ibmq_status_var = tk.StringVar(value="Not configured")
        ttk.Label(ibm_frame, textvariable=self.ibmq_status_var).pack(side=tk.LEFT, padx=10)

        self.ibmq_chart_label = ttk.Label(frame)
        self.ibmq_chart_label.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

    def _build_experiments_tab(self):
        frame = ttk.Frame(self.tabs)
        self.tabs.add(frame, text="Experiments")

        header = ttk.Label(frame, text="Saved Experiments", style="Header.TLabel")
        header.pack(anchor="w", padx=10, pady=(10, 4))

        controls = ttk.Frame(frame)
        controls.pack(fill=tk.X, padx=10, pady=(0, 8))
        ttk.Label(controls, text="Name").pack(side=tk.LEFT)
        self.exp_name_var = tk.StringVar(value="Experiment 1")
        ttk.Entry(controls, textvariable=self.exp_name_var, width=30).pack(side=tk.LEFT, padx=8)
        ttk.Button(controls, text="Save Current", command=self._save_experiment).pack(side=tk.LEFT, padx=6)
        ttk.Button(controls, text="Load", command=self._load_experiment).pack(side=tk.LEFT, padx=6)
        ttk.Button(controls, text="Delete", command=self._delete_experiment).pack(side=tk.LEFT, padx=6)

        self.exp_list = tk.Listbox(frame, height=12)
        self.exp_list.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self._refresh_experiment_list()

    def _build_plugins_tab(self):
        frame = ttk.Frame(self.tabs)
        self.tabs.add(frame, text="Plugins")

        header = ttk.Label(frame, text="Plugin Manager", style="Header.TLabel")
        header.pack(anchor="w", padx=10, pady=(10, 4))

        actions = ttk.Frame(frame)
        actions.pack(fill=tk.X, padx=10, pady=(0, 8))
        ttk.Button(actions, text="Refresh", command=self._refresh_plugins).pack(side=tk.LEFT)
        ttk.Button(actions, text="Run Selected", command=self._run_plugin).pack(side=tk.LEFT, padx=8)

        self.plugins_list = tk.Listbox(frame, height=12)
        self.plugins_list.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.plugins_output = tk.Text(frame, height=OUTPUT_TEXT_HEIGHT, wrap=tk.WORD)
        self.plugins_output.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        self._refresh_plugins()

    def _build_history_tab(self):
        frame = ttk.Frame(self.tabs)
        self.tabs.add(frame, text="Run History")

        header = ttk.Label(frame, text="Run History", style="Header.TLabel")
        header.pack(anchor="w", padx=10, pady=(10, 4))

        controls = ttk.Frame(frame)
        controls.pack(fill=tk.X, padx=10, pady=(0, 8))
        ttk.Label(controls, text="Filter").pack(side=tk.LEFT)
        self.history_filter_var = tk.StringVar()
        ttk.Entry(controls, textvariable=self.history_filter_var, width=30).pack(side=tk.LEFT, padx=8)
        ttk.Button(controls, text="Apply", command=self._refresh_history).pack(side=tk.LEFT, padx=6)
        ttk.Label(controls, text="Tag").pack(side=tk.LEFT, padx=6)
        self.history_tag_var = tk.StringVar()
        ttk.Entry(controls, textvariable=self.history_tag_var, width=20).pack(side=tk.LEFT, padx=6)
        ttk.Button(controls, text="Add Tag", command=self._add_history_tag).pack(side=tk.LEFT, padx=6)

        self.history_list = tk.Listbox(frame, height=OUTPUT_TEXT_HEIGHT)
        self.history_list.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self._refresh_history()

    def _run_quantum(self):
        self._start_loading("Running quantum job")
        algo = self.algo_var.get()
        payload = {
            "num_qubits": int(self.qubits_var.get()),
            "shots": int(self.shots_var.get()),
            "noise_level": float(self.noise_var.get()),
        }
        if algo == "grover":
            data = _safe_post(f"{API_BASE}/quantum/grover", payload, None)
        else:
            data = _safe_post(f"{API_BASE}/quantum/deutsch-jozsa", {**payload, "balanced": True}, None)

        if not data:
            self._stop_loading("API unavailable")
            messagebox.showwarning("API Unavailable", "Using cached data not applicable for quantum runs.")
            return

        self.last_quantum_result = data
        self.output.delete("1.0", tk.END)
        self.output.insert(tk.END, json.dumps(data, indent=2))
        self._stop_loading("Quantum job completed")
        self._record_history("quantum", data)

    def _export_quantum_csv(self):
        if not self.last_quantum_result:
            messagebox.showinfo("No Data", "Run an algorithm first.")
            return

        export_dir = CACHE_DIR / "exports"
        export_dir.mkdir(parents=True, exist_ok=True)
        algo = self.algo_var.get()
        csv_path = export_dir / f"{algo}_latest.csv"

        rows = []
        probs = self.last_quantum_result.get("probabilities", {})
        for state, prob in probs.items():
            rows.append({"state": state, "probability": prob})

        pd.DataFrame(rows).to_csv(csv_path, index=False)
        messagebox.showinfo("Exported", f"Saved to {csv_path}")

    def _view_circuit(self):
        payload = {
            "algorithm": self.algo_var.get(),
            "num_qubits": int(self.qubits_var.get()),
            "balanced": True,
        }
        data = _safe_post(f"{API_BASE}/quantum/circuit", payload, None)
        if not data:
            messagebox.showwarning("API Unavailable", "Circuit viewer requires the API.")
            return

        win = tk.Toplevel(self)
        win.title("Circuit Viewer")
        win.geometry("800x400")
        text = tk.Text(win, wrap=tk.NONE)
        scroll_y = ttk.Scrollbar(win, orient=tk.VERTICAL, command=text.yview)
        scroll_x = ttk.Scrollbar(win, orient=tk.HORIZONTAL, command=text.xview)
        text.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)
        text.insert(tk.END, data.get("text", ""))
        text.configure(state=tk.DISABLED)
        scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        scroll_x.pack(side=tk.BOTTOM, fill=tk.X)
        text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    def _view_circuit_image(self):
        payload = {
            "algorithm": self.algo_var.get(),
            "num_qubits": int(self.qubits_var.get()),
            "balanced": True,
        }
        data = _safe_post(f"{API_BASE}/quantum/circuit-image", payload, None)
        if not data or not data.get("plot_path"):
            messagebox.showwarning("API Unavailable", "Circuit diagram requires the API.")
            return
        path = Path(data["plot_path"])
        if not path.exists():
            messagebox.showwarning("Missing File", "Circuit image not found.")
            return
        win = tk.Toplevel(self)
        win.title("Circuit Diagram")
        win.geometry("900x500")
        label = ttk.Label(win)
        try:
            self.circuit_image = tk.PhotoImage(file=str(path))
            label.configure(image=self.circuit_image)
        except Exception:
            label.configure(text="Unable to load image")
        label.pack(fill=tk.BOTH, expand=True)

    def _refresh_market(self):
        self._start_loading("Refreshing market data")
        companies = _safe_get(f"{API_BASE}/market/companies", None)
        funding = _safe_get(f"{API_BASE}/market/funding", None)
        news = _safe_get(f"{API_BASE}/market/news", None)

        if companies is None:
            companies = pd.read_csv(CACHE_DIR / "companies_cache.csv").to_dict(orient="records")
        if funding is None:
            funding = pd.read_csv(CACHE_DIR / "funding_cache.csv").to_dict(orient="records")
        if news is None:
            with (CACHE_DIR / "news_cache.json").open("r", encoding="utf-8") as f:
                news = json.load(f)

        for item in self.companies_table.get_children():
            self.companies_table.delete(item)
        for row in companies:
            self.companies_table.insert("", tk.END, values=(
                row.get("name"),
                row.get("sector"),
                row.get("country"),
                row.get("year_founded"),
            ))

        for item in self.funding_table.get_children():
            self.funding_table.delete(item)
        for row in funding:
            self.funding_table.insert("", tk.END, values=(
                row.get("year"),
                row.get("sector"),
                row.get("amount_usd_m"),
                row.get("rounds"),
            ))

        self.news_output.delete("1.0", tk.END)
        for item in news:
            self.news_output.insert(tk.END, f"• {item.get('date', '')} {item.get('title', '')} ({item.get('source', '')})\n")

        self.last_market_snapshot = {
            "companies": companies,
            "funding": funding,
            "news": news,
        }

        self.last_updated_var.set(f"Last updated: {datetime.now().strftime('%H:%M:%S')}")
        self._stop_loading("Market data refreshed")

    def _refresh_alerts(self):
        alerts = _safe_get(f"{API_BASE}/market/alerts", [])
        self.alerts_output.delete("1.0", tk.END)
        for item in alerts:
            self.alerts_output.insert(tk.END, f"• {item.get('timestamp', '')} {item.get('message', '')}\n")

    def _validate_market(self):
        data = _safe_get(f"{API_BASE}/market/validate", None)
        if not data:
            messagebox.showwarning("API Unavailable", "Validation requires the API.")
            return
        if data.get("ok"):
            messagebox.showinfo("Validation", "Market datasets look good.")
        else:
            messagebox.showwarning("Validation Issues", json.dumps(data.get("issues", []), indent=2))

    def _generate_market_chart(self):
        try:
            df = pd.read_csv(CACHE_DIR / "funding_cache.csv")
        except Exception:
            messagebox.showwarning("Data Missing", "Funding cache not available.")
            return

        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
        except Exception:
            messagebox.showwarning("Plot Error", "Matplotlib not available.")
            return

        out_dir = CACHE_DIR / "exports"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / "funding_trend.png"

        plt.figure(figsize=(6, 4))
        for sector, sdf in df.groupby("sector"):
            plt.plot(sdf["year"], sdf["amount_usd_m"], marker="o", label=sector)
        plt.title("Funding Trends by Sector")
        plt.xlabel("Year")
        plt.ylabel("Amount (USD M)")
        plt.legend()
        plt.tight_layout()
        plt.savefig(out_path)
        plt.close()

        try:
            self.market_chart_image = tk.PhotoImage(file=str(out_path))
            self.market_chart_label.configure(image=self.market_chart_image)
        except Exception:
            messagebox.showwarning("Preview Failed", "Unable to load chart preview.")

    def _generate_sentiment_chart(self):
        data = _safe_get(f"{API_BASE}/market/sentiment", None)
        if not data:
            messagebox.showwarning("API Unavailable", "Sentiment analysis requires the API.")
            return

        sentiment = data.get("sentiment", {})
        self.sentiment_label.configure(text=f"Sentiment: {sentiment.get('label')} (score {sentiment.get('score')})")

        plot_path = data.get("plot_path")
        if plot_path and Path(plot_path).exists():
            try:
                self.market_chart_image = tk.PhotoImage(file=str(Path(plot_path)))
                self.market_chart_label.configure(image=self.market_chart_image)
            except Exception:
                messagebox.showwarning("Preview Failed", "Unable to load sentiment chart.")

    def _toggle_auto_refresh(self):
        self._auto_refresh = self.auto_refresh_var.get()
        if self._auto_refresh:
            self._schedule_auto_refresh()

    def _schedule_auto_refresh(self):
        if not self._auto_refresh:
            return
        self._refresh_market()
        self.after(MARKET_AUTO_REFRESH_SECONDS * 1000, self._schedule_auto_refresh)

    def _run_benchmark(self):
        self._start_loading("Running benchmark")
        algo = self.bench_algo_var.get()
        raw_levels = self.bench_noise_var.get()
        try:
            noise_levels = [float(x.strip()) for x in raw_levels.split(",") if x.strip()]
        except Exception:
            self._stop_loading("Invalid noise levels")
            messagebox.showwarning("Invalid Input", "Noise levels must be a comma-separated list of numbers.")
            return

        payload = {
            "algorithm": algo,
            "num_qubits": int(self.bench_qubits_var.get()),
            "shots": int(self.bench_shots_var.get()),
            "noise_levels": noise_levels,
        }

        data = _safe_post(f"{API_BASE}/quantum/benchmark", payload, None)
        if not data:
            self._stop_loading("API unavailable")
            messagebox.showwarning("API Unavailable", "Benchmark requires the API.")
            return

        self.last_benchmark_result = data
        self.benchmark_output.delete("1.0", tk.END)
        self.benchmark_output.insert(tk.END, json.dumps(data, indent=2))
        self._stop_loading("Benchmark completed")
        self._record_history("benchmark", data)

    def _run_comparison(self):
        self._start_loading("Running comparison")
        raw_levels = self.bench_noise_var.get()
        try:
            noise_levels = [float(x.strip()) for x in raw_levels.split(",") if x.strip()]
        except Exception:
            self._stop_loading("Invalid noise levels")
            messagebox.showwarning("Invalid Input", "Noise levels must be a comma-separated list of numbers.")
            return

        payload = {
            "num_qubits": int(self.bench_qubits_var.get()),
            "shots": int(self.bench_shots_var.get()),
            "noise_levels": noise_levels,
        }

        data = _safe_post(f"{API_BASE}/quantum/compare", payload, None)
        if not data:
            self._stop_loading("API unavailable")
            messagebox.showwarning("API Unavailable", "Comparison requires the API.")
            return

        self.last_compare_result = data
        self._stop_loading("Comparison completed")
        self._record_history("compare", data)

        plot_path = data.get("plot_path")
        if plot_path and Path(plot_path).exists():
            try:
                self.compare_image = tk.PhotoImage(file=str(Path(plot_path)))
                self.compare_plot_label.configure(image=self.compare_image)
            except Exception:
                messagebox.showwarning("Preview Failed", "Unable to load comparison preview.")

    def _preview_benchmark_plot(self):
        if not self.last_benchmark_result:
            messagebox.showinfo("No Data", "Run a benchmark first.")
            return

        plot_path = self.last_benchmark_result.get("plot_path")
        if not plot_path:
            messagebox.showinfo("No Plot", "No plot path available.")
            return

        path = Path(plot_path)
        if not path.exists():
            messagebox.showwarning("Missing File", f"Plot not found: {plot_path}")
            return

        try:
            self.benchmark_image = tk.PhotoImage(file=str(path))
            self.benchmark_plot_label.configure(image=self.benchmark_image)
        except Exception:
            messagebox.showwarning("Preview Failed", "Unable to load plot preview. Use OS to open the file.")

    def _save_benchmark_plot(self):
        if not self.last_benchmark_result:
            messagebox.showinfo("No Data", "Run a benchmark first.")
            return

        plot_path = self.last_benchmark_result.get("plot_path")
        if not plot_path:
            messagebox.showinfo("No Plot", "No plot path available.")
            return

        src = Path(plot_path)
        if not src.exists():
            messagebox.showwarning("Missing File", f"Plot not found: {plot_path}")
            return

        dest = filedialog.asksaveasfilename(
            defaultextension=".png",
            filetypes=[("PNG Image", "*.png")],
            initialfile=src.name,
            title="Save Benchmark Plot",
        )
        if not dest:
            return

        try:
            Path(dest).write_bytes(src.read_bytes())
            messagebox.showinfo("Saved", f"Saved to {dest}")
        except Exception:
            messagebox.showwarning("Save Failed", "Unable to save the plot.")

    def _save_benchmark_csv(self):
        if not self.last_benchmark_result:
            messagebox.showinfo("No Data", "Run a benchmark first.")
            return

        csv_path = self.last_benchmark_result.get("csv_path")
        if not csv_path:
            messagebox.showinfo("No CSV", "No CSV path available.")
            return

        src = Path(csv_path)
        if not src.exists():
            messagebox.showwarning("Missing File", f"CSV not found: {csv_path}")
            return

        dest = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv")],
            initialfile=src.name,
            title="Save Benchmark CSV",
        )
        if not dest:
            return

        try:
            Path(dest).write_bytes(src.read_bytes())
            messagebox.showinfo("Saved", f"Saved to {dest}")
        except Exception:
            messagebox.showwarning("Save Failed", "Unable to save the CSV.")

    def _export_report(self):
        payload = {
            "quantum": self.last_quantum_result,
            "benchmark": self.last_benchmark_result,
            "comparison": self.last_compare_result,
        }
        data = _safe_post(f"{API_BASE}/reports/generate", payload, None)
        if not data:
            messagebox.showwarning("API Unavailable", "Report generation requires the API.")
            return

        report_path = data.get("report_path")
        if report_path:
            self.report_status.set(f"Report saved: {report_path}")
        else:
            self.report_status.set("Report generation failed")

    def _export_bundle(self):
        paths = []
        if self.last_benchmark_result:
            if self.last_benchmark_result.get("plot_path"):
                paths.append(self.last_benchmark_result["plot_path"])
            if self.last_benchmark_result.get("csv_path"):
                paths.append(self.last_benchmark_result["csv_path"])
        if self.last_compare_result and self.last_compare_result.get("plot_path"):
            paths.append(self.last_compare_result["plot_path"])

        data = _safe_post(f"{API_BASE}/reports/bundle", {"paths": paths}, None)
        if not data:
            messagebox.showwarning("API Unavailable", "Bundle export requires the API.")
            return
        self.report_status.set(f"Bundle saved: {data.get('bundle_path')}")

    def _check_ibmq_status(self):
        data = _safe_get(f"{API_BASE}/quantum/ibmq/status", None)
        if not data:
            self.ibmq_status_var.set("Unavailable")
            return
        self.ibmq_status_var.set(data.get("message", "Unknown"))

    def _ibmq_queue_chart(self):
        data = _safe_get(f"{API_BASE}/quantum/ibmq/queue-chart", None)
        if not data or not data.get("plot_path"):
            messagebox.showwarning("IBMQ", "Queue chart unavailable.")
            return
        plot_path = Path(data["plot_path"])
        if plot_path.exists():
            try:
                self.ibmq_chart_image = tk.PhotoImage(file=str(plot_path))
                self.ibmq_chart_label.configure(image=self.ibmq_chart_image)
            except Exception:
                messagebox.showwarning("Preview Failed", "Unable to load IBMQ chart.")

    def _save_ibmq_token(self):
        token = self.ibmq_token_var.get().strip()
        if not token:
            messagebox.showinfo("Token", "Enter a token first.")
            return
        data = _safe_post(f"{API_BASE}/quantum/ibmq/set-token", {"token": token}, None)
        if not data:
            messagebox.showwarning("API Unavailable", "API required to save token.")
            return
        self.ibmq_status_var.set("Token saved")

    def _refresh_plugins(self):
        items = _safe_get(f"{API_BASE}/plugins/list", [])
        self.plugins_list.delete(0, tk.END)
        for item in items:
            self.plugins_list.insert(tk.END, f"{item.get('name')} | {item.get('description')}")

    def _run_plugin(self):
        idx = self.plugins_list.curselection()
        if not idx:
            messagebox.showinfo("Select", "Select a plugin to run.")
            return
        name = self.plugins_list.get(idx[0]).split("|")[0].strip()

        payload = {}
        if name == "quantum_summary":
            payload = self.last_quantum_result or {}
            payload["algorithm"] = self.algo_var.get()
        elif name == "market_risk":
            snap = self.last_market_snapshot or {}
            payload = {
                "companies": len(snap.get("companies", [])),
                "funding_rows": len(snap.get("funding", [])),
                "news_items": len(snap.get("news", [])),
            }
        elif name == "export_snapshot":
            payload = {
                "path": "snapshot.json",
                "data": {
                    "quantum": self.last_quantum_result,
                    "benchmark": self.last_benchmark_result,
                    "comparison": self.last_compare_result,
                    "market": self.last_market_snapshot,
                },
            }

        if self.current_user.get("role") != "admin" and name == "export_snapshot":
            messagebox.showwarning("Permission", "Only admin can run export_snapshot.")
            return

        data = _safe_post(f"{API_BASE}/plugins/run", {"plugin": name, "payload": payload}, None)
        if not data:
            messagebox.showwarning("API Unavailable", "Plugin run requires the API.")
            return
        self.plugins_output.delete("1.0", tk.END)
        self.plugins_output.insert(tk.END, json.dumps(data, indent=2))

    def _load_history(self):
        if not HISTORY_PATH.exists():
            return []
        try:
            return json.loads(HISTORY_PATH.read_text(encoding="utf-8"))
        except Exception:
            return []

    def _save_history(self, items):
        HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
        HISTORY_PATH.write_text(json.dumps(items, indent=2), encoding="utf-8")

    def _record_history(self, kind: str, payload: dict):
        items = self._load_history()
        items.insert(0, {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "type": kind,
            "tags": [],
            "payload": payload,
        })
        self._save_history(items)
        self._refresh_history()

    def _refresh_history(self):
        filt = (self.history_filter_var.get() or "").lower()
        items = self._load_history()
        self.history_list.delete(0, tk.END)
        for item in items:
            text = f"{item.get('timestamp')} | {item.get('type')} | tags={','.join(item.get('tags', []))}"
            if filt and filt not in text.lower():
                continue
            self.history_list.insert(tk.END, text)

    def _add_history_tag(self):
        idx = self.history_list.curselection()
        if not idx:
            messagebox.showinfo("Select", "Select a history item first.")
            return
        tag = self.history_tag_var.get().strip()
        if not tag:
            messagebox.showinfo("Tag", "Enter a tag.")
            return

        items = self._load_history()
        item = items[idx[0]]
        tags = set(item.get("tags", []))
        tags.add(tag)
        item["tags"] = sorted(tags)
        items[idx[0]] = item
        self._save_history(items)
        self._refresh_history()

    def _check_updates(self):
        current = _safe_get(f"{API_BASE}/version", {"version": "0.0.0"}).get("version", "0.0.0")
        latest = current
        if UPDATE_INFO_PATH.exists():
            try:
                data = json.loads(UPDATE_INFO_PATH.read_text(encoding="utf-8"))
                latest = data.get("latest_version", current)
            except Exception:
                latest = current

        def _ver_tuple(v):
            return tuple(int(x) for x in v.split(".")) if v else (0, 0, 0)

        if _ver_tuple(latest) > _ver_tuple(current):
            messagebox.showinfo("Update", f"Update available: {latest} (current {current})")
        else:
            messagebox.showinfo("Update", f"You are up to date ({current}).")

    def _load_experiments(self):
        if not EXPERIMENTS_PATH.exists():
            return []
        try:
            return json.loads(EXPERIMENTS_PATH.read_text(encoding="utf-8"))
        except Exception:
            return []

    def _save_experiments(self, items):
        EXPERIMENTS_PATH.parent.mkdir(parents=True, exist_ok=True)
        EXPERIMENTS_PATH.write_text(json.dumps(items, indent=2), encoding="utf-8")

    def _refresh_experiment_list(self):
        self.exp_list.delete(0, tk.END)
        for item in self._load_experiments():
            self.exp_list.insert(tk.END, f"{item.get('name')} | {item.get('timestamp')}")

    def _save_experiment(self):
        items = self._load_experiments()
        items.insert(0, {
            "name": self.exp_name_var.get(),
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "quantum": self.last_quantum_result,
            "benchmark": self.last_benchmark_result,
            "comparison": self.last_compare_result,
        })
        self._save_experiments(items)
        self._refresh_experiment_list()

    def _load_experiment(self):
        idx = self.exp_list.curselection()
        if not idx:
            messagebox.showinfo("Select", "Select an experiment to load.")
            return
        items = self._load_experiments()
        item = items[idx[0]]
        self.last_quantum_result = item.get("quantum")
        self.last_benchmark_result = item.get("benchmark")
        self.last_compare_result = item.get("comparison")

        if self.last_quantum_result:
            self.output.delete("1.0", tk.END)
            self.output.insert(tk.END, json.dumps(self.last_quantum_result, indent=2))

        if self.last_benchmark_result:
            self.benchmark_output.delete("1.0", tk.END)
            self.benchmark_output.insert(tk.END, json.dumps(self.last_benchmark_result, indent=2))

        if self.last_compare_result and self.last_compare_result.get("plot_path"):
            plot_path = Path(self.last_compare_result["plot_path"])
            if plot_path.exists():
                try:
                    self.compare_image = tk.PhotoImage(file=str(plot_path))
                    self.compare_plot_label.configure(image=self.compare_image)
                except Exception:
                    pass

        detail = json.dumps(item, indent=2)
        win = tk.Toplevel(self)
        win.title("Experiment Details")
        win.geometry("800x400")
        text = tk.Text(win, wrap=tk.WORD)
        text.insert(tk.END, detail)
        text.configure(state=tk.DISABLED)
        text.pack(fill=tk.BOTH, expand=True)

    def _delete_experiment(self):
        idx = self.exp_list.curselection()
        if not idx:
            messagebox.showinfo("Select", "Select an experiment to delete.")
            return
        items = self._load_experiments()
        items.pop(idx[0])
        self._save_experiments(items)
        self._refresh_experiment_list()


def main():
    app = QBenchGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
