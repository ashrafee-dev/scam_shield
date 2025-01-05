"""Structured logging configuration.

Provides a consistent logging setup across all modules. In production,
swap the formatter for a JSON formatter (e.g. python-json-logger) and
ship logs to your preferred aggregator (CloudWatch, Datadog, etc.).
"""

from __future__ import annotations

import logging
import sys

from app.core.config import get_settings


def configure_logging() -> None:
    """Initialize the root logger with the configured log level and format.

    Call once at application startup in main.py.
    """
    settings = get_settings()
    level = getattr(logging, settings.log_level, logging.INFO)

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Avoid duplicate handlers if configure_logging() is called more than once
    if not root_logger.handlers:
        root_logger.addHandler(handler)
    else:
        root_logger.handlers.clear()
        root_logger.addHandler(handler)


def get_logger(name: str) -> logging.Logger:
    """Return a named logger. Use module __name__ as the name convention."""
    return logging.getLogger(name)
