"""
Structured Logging
Provides consistent logging across all MiMo Sentinel modules.
"""

from __future__ import annotations
import logging
import sys
from typing import Optional


_loggers: dict[str, logging.Logger] = {}
_initialized = False

LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)-25s | %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def _setup_root_logger(level: str = "INFO") -> None:
    """Configure the root logger once."""
    global _initialized
    if _initialized:
        return
    root = logging.getLogger("sentinel")
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT)
    handler.setFormatter(formatter)
    root.addHandler(handler)
    _initialized = True


def get_logger(name: str, level: Optional[str] = None) -> logging.Logger:
    """
    Get or create a named logger.
    
    Args:
        name: Logger name (typically __name__)
        level: Optional log level override
    
    Returns:
        Configured logger instance
    """
    _setup_root_logger()

    if name in _loggers:
        return _loggers[name]

    logger = logging.getLogger(f"sentinel.{name}")
    if level:
        logger.setLevel(getattr(logging, level.upper(), logging.DEBUG))
    _loggers[name] = logger
    return logger


def set_log_level(level: str) -> None:
    """Set global log level."""
    root = logging.getLogger("sentinel")
    root.setLevel(getattr(logging, level.upper(), logging.INFO))


def add_file_handler(path: str, level: str = "DEBUG") -> None:
    """Add a file handler to the root logger."""
    root = logging.getLogger("sentinel")
    handler = logging.FileHandler(path)
    handler.setLevel(getattr(logging, level.upper(), logging.DEBUG))
    formatter = logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT)
    handler.setFormatter(formatter)
    root.addHandler(handler)
