"""Append-only JSON-lines audit log. Passwords are never written here."""
import getpass
import json
import logging
import os
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler

_logger: logging.Logger | None = None


def _get_logger() -> logging.Logger:
    global _logger
    if _logger is None:
        path = os.environ.get("AD_AUDIT_LOG", "audit.log")
        handler = RotatingFileHandler(path, maxBytes=1_000_000, backupCount=5)
        handler.setFormatter(logging.Formatter("%(message)s"))
        _logger = logging.getLogger("pwreset.audit")
        _logger.setLevel(logging.INFO)
        _logger.addHandler(handler)
    return _logger


def log_event(action: str, target: str, outcome: str, reason: str = "") -> None:
    record = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "operator": getpass.getuser(),
        "action": action,
        "target": target,
        "outcome": outcome,
        "reason": reason,
    }
    _get_logger().info(json.dumps(record))
