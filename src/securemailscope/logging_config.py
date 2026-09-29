"""
SecureMailScope — Logging configuration.

Uses Python standard library logging only.
No remote log shipping, telemetry, or external services.
"""

from __future__ import annotations

import logging
import sys

_VALID_LEVELS = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})


def configure_logging(level: str = "INFO") -> None:
    """Configure root logger for SecureMailScope.

    Args:
        level: Log level string. Must be one of DEBUG, INFO, WARNING,
               ERROR, or CRITICAL. Case-insensitive.

    Raises:
        ValueError: If *level* is not a recognised log level.
    """
    normalised = level.upper()
    if normalised not in _VALID_LEVELS:
        raise ValueError(
            f"Invalid log level: {level!r}. "
            f"Choose from: {sorted(_VALID_LEVELS)}"
        )

    numeric_level = getattr(logging, normalised)

    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        stream=sys.stderr,
    )
    logger = logging.getLogger("securemailscope")
    logger.setLevel(numeric_level)
