"""
CloudSync Logging Configuration.

Provides centralized logging configuration for the entire backend.

All backend modules should obtain loggers using get_logger()
instead of configuring logging individually.
"""

from __future__ import annotations

import logging

from backend.core.config import get_settings


def configure_logging() -> None:
    """
    Configure application-wide logging.

    This function should be called once during application startup.
    Subsequent calls will have no effect if logging has already
    been configured.
    """
    root_logger = logging.getLogger()

    # Prevent duplicate handlers
    if root_logger.handlers:
        return

    settings = get_settings()

    log_level = getattr(
        logging,
        settings.LOG_LEVEL.upper(),
        logging.INFO,
    )

    logging.basicConfig(
        level=log_level,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[
            logging.StreamHandler(),
        ],
    )


def get_logger(name: str) -> logging.Logger:
    """
    Return a configured logger instance.

    Args:
        name: Usually __name__ of the calling module.

    Returns:
        Configured Logger instance.
    """
    return logging.getLogger(name)