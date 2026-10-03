"""
Audit and execution logger for KRYPT CLI.
Logs security decisions, scans, errors, and target updates while redacting secrets.
"""

import logging
from logging.handlers import RotatingFileHandler
from typing import Any
import sys

from krypt.utils.filesystem import KRYPT_LOG_FILE, ensure_krypt_dirs
from krypt.evidence.redactor import redact_text


class RedactingFormatter(logging.Formatter):
    """Logging formatter that automatically redacts sensitive tokens and secrets."""
    def format(self, record: logging.LogRecord) -> str:
        original = super().format(record)
        return redact_text(original)


def setup_logger(name: str = "krypt", level: int = logging.INFO) -> logging.Logger:
    """Configure and return the KRYPT logger."""
    ensure_krypt_dirs()
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    if not logger.handlers:
        # File handler (always logs details to ~/.krypt/logs/krypt.log)
        file_handler = RotatingFileHandler(
            KRYPT_LOG_FILE,
            maxBytes=10 * 1024 * 1024,  # 10 MB
            backupCount=5,
            encoding="utf-8"
        )
        formatter = RedactingFormatter(
            fmt="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


logger = setup_logger()


def audit_log(action: str, target: str, status: str, details: str = "") -> None:
    """Record an audit trail event."""
    msg = f"AUDIT | Action={action} | Target={target} | Status={status}"
    if details:
        msg += f" | Details={details}"
    logger.info(msg)
