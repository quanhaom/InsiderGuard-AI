from pathlib import Path

from dotenv import load_dotenv
import os

# =====================================
# Load .env
# =====================================

BASE_DIR = Path(__file__).resolve().parent.parent

load_dotenv(BASE_DIR / ".env")

# =====================================
# Backend
# =====================================

API_URL = os.getenv(
    "API_URL",
    "http://127.0.0.1:8000/api/v1/collector/events"
)

# =====================================
# Event Log
# =====================================

EVENT_LOG = os.getenv(
    "EVENT_LOG",
    "Security"
)

POLL_INTERVAL = int(
    os.getenv(
        "POLL_INTERVAL",
        "2"
    )
)

# =====================================
# Data
# =====================================

DATA_DIR = BASE_DIR / "data"

LOG_DIR = BASE_DIR / "logs"

BOOKMARK_FILE = DATA_DIR / "bookmark.json"

QUEUE_DATABASE = DATA_DIR / "queue.db"

# =====================================
# Create directories automatically
# =====================================

DATA_DIR.mkdir(
    exist_ok=True
)

LOG_DIR.mkdir(
    exist_ok=True
)