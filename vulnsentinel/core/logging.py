"""Structured logging configuration — structlog + stdlib logging."""

from __future__ import annotations

import logging
import logging.config
import os

import structlog


def setup_logging() -> None:
    """Configure structlog and stdlib logging.

    Reads from environment variables:
        VULNSENTINEL_LOG_LEVEL  — business log level (default: INFO)
        VULNSENTINEL_LOG_FORMAT — console | json (default: console)
    """
    log_level = os.environ.get("VULNSENTINEL_LOG_LEVEL", "INFO").upper()
    log_format = os.environ.get("VULNSENTINEL_LOG_FORMAT", "console").lower()

    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
    ]

    if log_format == "json":
        renderer: structlog.types.Processor = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer()

    # --- structlog configure ---
    structlog.configure(
        processors=shared_processors
        + [structlog.stdlib.ProcessorFormatter.wrap_for_formatter],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # --- stdlib logging configure ---
    logging.config.dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "structlog": {
                    "()": structlog.stdlib.ProcessorFormatter,
                    "foreign_pre_chain": shared_processors,
                    "processors": [
                        structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                        renderer,
                    ],
                },
            },
            "handlers": {
                "default": {
                    "class": "logging.StreamHandler",
                    "stream": "ext://sys.stdout",
                    "formatter": "structlog",
                },
            },
            "root": {
                "handlers": ["default"],
                "level": log_level,
            },
            "loggers": {
                "vulnsentinel": {"level": log_level},
                "uvicorn.access": {"level": "WARNING"},
                "uvicorn.error": {"level": "INFO"},
                "sqlalchemy.engine": {"level": "WARNING"},
                "asyncpg": {"level": "WARNING"},
                "httpx": {"level": "WARNING"},
            },
        }
    )
