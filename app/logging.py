"""Leveled logging configuration for the utility.

Registers a custom ``TRACE`` level below ``DEBUG`` and configures a formatter
that emits a timestamp, level, and message. Importing this module never emits
secrets; redaction is the responsibility of :mod:`app.utils.debug` and the HTTP
wrapper before values reach the logger.

Note: this module intentionally does NOT shadow the stdlib ``logging`` module.
Because it lives inside the ``app`` package, ``import logging`` here resolves to
the standard library via absolute import.
"""

from __future__ import annotations

import logging
from typing import Final

TRACE: Final[int] = 5
_LEVEL_NAMES: Final[tuple[str, ...]] = ("ERROR", "WARNING", "INFO", "DEBUG", "TRACE")

_LOGGER_NAME: Final[str] = "snyk_sbom_to_servicenow"
_configured = False


def _install_trace_level() -> None:
    """Register the TRACE level and a ``logger.trace(...)`` convenience method."""
    if logging.getLevelName(TRACE) != "TRACE":
        logging.addLevelName(TRACE, "TRACE")

    def trace(self: logging.Logger, message: str, *args: object, **kwargs: object) -> None:
        if self.isEnabledFor(TRACE):
            self._log(TRACE, message, args, **kwargs)  # type: ignore[arg-type]

    if not hasattr(logging.Logger, "trace"):
        logging.Logger.trace = trace  # type: ignore[attr-defined]


def resolve_level(name: str | None) -> int:
    """Resolve a level name (case-insensitive) to a numeric logging level."""
    if not name:
        return logging.INFO
    candidate = name.strip().upper()
    if candidate == "TRACE":
        return TRACE
    return getattr(logging, candidate, logging.INFO)


def configure_logging(level_name: str | None = "INFO") -> logging.Logger:
    """Configure and return the application logger.

    Idempotent: repeated calls only update the level, never add handlers twice.
    """
    global _configured
    _install_trace_level()

    logger = logging.getLogger(_LOGGER_NAME)
    level = resolve_level(level_name)
    logger.setLevel(level)

    if not _configured:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s | %(levelname)-7s | %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        logger.addHandler(handler)
        logger.propagate = False
        _configured = True

    for handler in logger.handlers:
        handler.setLevel(level)

    return logger


def get_logger() -> logging.Logger:
    """Return the shared application logger, configuring it if necessary."""
    logger = logging.getLogger(_LOGGER_NAME)
    if not _configured:
        return configure_logging()
    return logger
