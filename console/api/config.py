"""Paths and tunables for the console. Everything is overridable by env var
so the demo can be pointed at a different DB, port or trace folder without
editing code."""
import os

HERE = os.path.dirname(os.path.abspath(__file__))
CONSOLE_DIR = os.path.dirname(HERE)
REPO_DIR = os.path.dirname(CONSOLE_DIR)

CONTRACTS_DIR = os.environ.get("SENTINEL_CONTRACTS_DIR", os.path.join(REPO_DIR, "contracts"))
EVENT_SCHEMA_PATH = os.path.join(CONTRACTS_DIR, "event.schema.json")
TRACE_SCHEMA_PATH = os.path.join(CONTRACTS_DIR, "trace.schema.json")

DB_PATH = os.environ.get("SENTINEL_DB", os.path.join(CONSOLE_DIR, "data", "console.db"))

# Recorded traces land here. The ML stream trains from ml/data/traces/, so the
# handoff is a copy -- see demo/RUNBOOK.md. Kept inside console/ because the
# console owns its own folder.
TRACE_DIR = os.environ.get("SENTINEL_TRACE_DIR", os.path.join(CONSOLE_DIR, "data", "traces"))

# 127.0.0.1, never "localhost": on Windows, "localhost" resolves to ::1 first and
# stalls ~2s per request before falling back to IPv4 (measured on the gateway
# laptop: 2047ms vs 2.4ms). At demo pace that lag is visible on stage.
CONSOLE_URL = os.environ.get("SENTINEL_CONSOLE_URL", "http://127.0.0.1:8000")
ML_URL = os.environ.get("SENTINEL_ML_URL", "http://127.0.0.1:8001")

# Largest upload POST /api/scan/file accepts before proxying it to the ML
# service. The body is buffered in memory (and again by the ML service), so
# without a cap one request could fill the laptop's RAM. 20 MB covers the
# benign PE/.eml files the demo scans; bigger is refused with 413.
MAX_UPLOAD_BYTES = int(os.environ.get("SENTINEL_MAX_UPLOAD_BYTES", 20 * 1024 * 1024))

# Correlation window: events more than this far apart start a new incident.
INCIDENT_WINDOW_MS = int(os.environ.get("SENTINEL_INCIDENT_WINDOW_MS", 10 * 60 * 1000))

# Where the ML stream's charts and metrics live, for the Evidence page (read-only).
ML_REPORTS_DIR = os.environ.get("SENTINEL_ML_REPORTS", os.path.join(REPO_DIR, "ml", "reports"))

# Host names the API answers to (api/main.py, same_origin_only). Anything else
# is refused, which stops DNS rebinding: a web page whose domain re-resolves to
# 127.0.0.1 still sends its own name as Host. Comma-separated; add the laptop's
# LAN name/IP here if the console is ever served beyond 127.0.0.1.
ALLOWED_HOSTS = {h.strip().lower() for h in
                 os.environ.get("SENTINEL_ALLOWED_HOSTS", "127.0.0.1,localhost,::1").split(",")
                 if h.strip()}

# -- v4 energy -------------------------------------------------------------

# Cell capacity used to turn measured draw into "projected days". One 18650 at
# 2500 mAh x 3.7 V = 9.25 Wh (brief v2 BOM). An assumption, not a measurement --
# the UI labels projections as estimates. Override for a different cell.
BATTERY_WH = float(os.environ.get("SENTINEL_BATTERY_WH", 9.25))

# Idle draw. Unset = derived from data (see energy.baseline_mw). Set it once the
# rig has measured the real idle figure.
BASELINE_MW = float(os.environ["SENTINEL_BASELINE_MW"]) if os.environ.get("SENTINEL_BASELINE_MW") else None

# Default length of one experiment-table run.
EXPERIMENT_DURATION_S = int(os.environ.get("SENTINEL_EXPERIMENT_DURATION_S", 120))

# A node not heard from for this long is shown offline.
OFFLINE_AFTER_MS = int(os.environ.get("SENTINEL_OFFLINE_AFTER_MS", 120_000))

# Where the built React frontend lives; served at / when present.
WEB_DIST = os.environ.get("SENTINEL_WEB_DIST", os.path.join(CONSOLE_DIR, "web", "dist"))
ENERGY_SCHEMA_PATH = os.path.join(CONTRACTS_DIR, "energy.schema.json")

# -- detection channels ------------------------------------------------------

# One subfolder per channel, each with a manifest.json (api/channels.py).
# Sits next to console/, ml/, firmware/ -- not owned by any one stream's
# folder, since a channel manifest can point at a model trained by ml/ (SMS)
# or reference one that already lives there (MailGuard, FileGuard) without
# console/ needing to contain model code itself.
CHANNELS_DIR = os.environ.get("SENTINEL_CHANNELS_DIR", os.path.join(REPO_DIR, "channels"))

# The only folders a channel manifest's model_path / vectorizer_path may point
# into. joblib.load unpickles, which runs code, so a manifest.json that names
# a file anywhere else (absolute, or ../ out of the repo) is refused, not loaded.
MODEL_DIRS = [os.path.join(REPO_DIR, "channels"), os.path.join(REPO_DIR, "ml", "models")]
