"""SentinelAI logging helpers.

This module sets up a simple, shared logging foundation using only the
Python standard library ``logging`` module:

* every message is written to a log file at ``logs/sentinelai.log``
* every message is also shown on the console (stdout)

Security note: never log passwords, API keys, tokens or other sensitive
values. Log files are written to disk and are easy to share by accident,
so treat every log file as if other people can read it.
"""

import logging
import sys
from pathlib import Path

# The format used for every log line. Example:
# 2026-10-06 20:30:00,123 | INFO     | sentinelai | Logging is ready.
LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"


def setup_logging(log_dir=None, level=logging.INFO):
    """Configure the root logger with a file handler and a console handler.

    Parameters
    ----------
    log_dir : str or Path, optional
        Folder where the log file is created. When omitted, the project's
        own "logs" folder is used.
    level : int, optional
        Minimum log level to record (logging.INFO by default).
    """
    if log_dir is None:
        # Work out the "logs" folder from this file's own location.
        # This file lives at  src/utils/logger.py  inside the project:
        #   parents[0] -> src/utils     (the folder that contains this file)
        #   parents[1] -> src
        #   parents[2] -> project root  (two parents up)
        project_root = Path(__file__).resolve().parents[2]
        log_dir = project_root / "logs"
    log_dir = Path(log_dir)

    # Make sure the log folder exists (creates it only if it is missing).
    log_dir.mkdir(parents=True, exist_ok=True)

    root_logger = logging.getLogger()

    # Guard against duplicate handlers: if the root logger is already set
    # up, stop here so the same message is not logged twice.
    if root_logger.handlers:
        return

    # One shared formatter for both handlers.
    formatter = logging.Formatter(LOG_FORMAT)

    # Handler 1: write records to the log file (UTF-8 so any text is safe).
    file_handler = logging.FileHandler(log_dir / "sentinelai.log", encoding="utf-8")
    file_handler.setFormatter(formatter)

    # Handler 2: also show records on the console (stdout).
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)

    # Attach the handlers and set the minimum level for the root logger.
    root_logger.setLevel(level)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(stream_handler)


def get_logger(name="sentinelai"):
    """Return a logger for the given name.

    Use it in any module, for example::

        from src.utils.logger import get_logger
        log = get_logger(__name__)
        log.info("Ready.")
    """
    return logging.getLogger(name)
