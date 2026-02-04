from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
APP_VERSION = "1.0.0"
DATA_DIR = ROOT_DIR / "src" / "qbench" / "data"
CACHE_DIR = DATA_DIR / "cache"
DATASETS_DIR = DATA_DIR / "datasets"
REPORTS_DIR = ROOT_DIR / "reports"
EXPERIMENTS_PATH = CACHE_DIR / "experiments.json"
HISTORY_PATH = CACHE_DIR / "run_history.json"
BUNDLES_DIR = ROOT_DIR / "reports" / "bundles"
USERS_PATH = CACHE_DIR / "users.json"
UPDATE_INFO_PATH = CACHE_DIR / "update_info.json"

API_HOST = "127.0.0.1"
API_PORT = 5050

DEFAULT_SHOTS = 1024
DEFAULT_NOISE = 0.01

# Market news sources (optional online refresh)
NEWS_SOURCE_URLS = [
	"https://thequantuminsider.com",
	"https://www.quantumtechnews.com",
]

MARKET_AUTO_REFRESH_SECONDS = 60

# Phase 3: Scheduler + alerts + plugins
SCHEDULER_ENABLED = True
SCHEDULER_INTERVAL_SECONDS = 300
ALERT_MIN_NEW_ITEMS = 1
PLUGINS_DIR = ROOT_DIR / "src" / "qbench" / "plugins"
ALERTS_PATH = CACHE_DIR / "alerts.json"

# IBM Quantum runtime settings
IBMQ_CHANNEL = "ibm_quantum"
IBMQ_TOKEN_PATH = CACHE_DIR / "ibmq_token.txt"
