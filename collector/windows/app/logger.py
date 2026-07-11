import logging

from app.config import LOG_DIR

LOG_FILE = LOG_DIR / "collector.log"

LOGGER_NAME = "InsiderGuardCollector"

logger = logging.getLogger(
    LOGGER_NAME
)

logger.setLevel(logging.INFO)

formatter = logging.Formatter(
    "%(asctime)s | %(levelname)s | %(message)s"
)

file_handler = logging.FileHandler(
    LOG_FILE,
    encoding="utf-8"
)

file_handler.setFormatter(
    formatter
)

console_handler = logging.StreamHandler()

console_handler.setFormatter(
    formatter
)

if not logger.handlers:

    logger.addHandler(
        file_handler
    )

    logger.addHandler(
        console_handler
    )