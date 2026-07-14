"""
Diagnostics / observability for the WFH Access Portal.

Two sinks, populated by the same log_event() call:

  1. A rotating file log at logs/app.log — captures everything routed through
     the root logger (including boto3 / paramiko output), for shell access.
  2. A `debug_logs` DB table surfaced in the in-app "Diagnostics" tab via
     log_event(), so admins can see structured events (logins, AWS security
     group operations, API requests, provisioning, errors) without a shell.

log_event() is intentionally defensive: observing the app must never raise an
exception into the request/thread it is observing.
"""

import os
import logging
from logging.handlers import RotatingFileHandler

LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
LOG_FILE = os.path.join(LOG_DIR, "app.log")

_configured = False
_logger = logging.getLogger("wfh")


def configure_logging(level=logging.INFO):
    """Attach a rotating file handler (and a console handler) to the root logger.
    Idempotent — safe to call more than once."""
    global _configured
    if _configured:
        return
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
    except Exception:
        pass

    fmt = logging.Formatter(
        "%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s] %(name)s: %(message)s"
    )
    root = logging.getLogger()
    root.setLevel(level)

    # Rotating file: 5 x 2MB.
    if not any(isinstance(h, RotatingFileHandler) for h in root.handlers):
        try:
            fh = RotatingFileHandler(LOG_FILE, maxBytes=2_000_000, backupCount=5)
            fh.setFormatter(fmt)
            root.addHandler(fh)
        except Exception:
            pass

    # Console (only if one isn't already present — manage_wfh_access adds one).
    if not any(
        isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler)
        for h in root.handlers
    ):
        ch = logging.StreamHandler()
        ch.setFormatter(fmt)
        root.addHandler(ch)

    _configured = True


def log_event(category, message, level="INFO", actor=None, details=None):
    """
    Record one structured diagnostic event to both the python log (file/console)
    and the debug_logs DB table (for the in-app Diagnostics tab). Never raises.
    """
    lvl = (level or "INFO").upper()

    # 1) python logger -> file + console
    try:
        _logger.log(
            getattr(logging, lvl, logging.INFO),
            "[%s] %s%s", category, message,
            f" (actor={actor})" if actor else "",
        )
    except Exception:
        pass

    # 2) DB row for the Diagnostics tab (imported lazily to avoid an import cycle)
    try:
        from db import add_debug_log
        add_debug_log(lvl, category, actor, message, details)
    except Exception:
        # Diagnostics must never break the code path it is observing.
        pass
