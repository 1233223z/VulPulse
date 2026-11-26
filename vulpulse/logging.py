"""Loguru configuration and standard-library logging interception."""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from types import FrameType

from loguru import logger

_CONFIGURED = False

_CONSOLE_FORMAT = (
    "<green>{time:HH:mm:ss}</green> | "
    "<level>{level: <8}</level> | "
    "<cyan>{name}</cyan> - <level>{message}</level>"
)


class _InterceptHandler(logging.Handler):
    """Route standard-library log records to loguru."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            level: str | int = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno

        frame: FrameType | None
        frame, depth = logging.currentframe(), 2
        while frame is not None and frame.f_code.co_filename == logging.__file__:
            frame = frame.f_back
            depth += 1

        logger.opt(depth=depth, exception=record.exc_info).log(level, record.getMessage())


def setup_logging(level: str = "INFO", log_dir: Path | None = None) -> None:
    """Configure loguru once per process.

    Console output is always enabled. When ``log_dir`` is provided, logs are
    also written to a rotating file.
    """
    global _CONFIGURED
    if _CONFIGURED:
        return

    logger.remove()
    logger.add(sys.stderr, level=level.upper(), colorize=True, format=_CONSOLE_FORMAT)

    if log_dir is not None:
        log_dir.mkdir(parents=True, exist_ok=True)
        logger.add(
            log_dir / "vulpulse.log",
            level=level.upper(),
            rotation="10 MB",
            retention="14 days",
            encoding="utf-8",
            enqueue=True,
        )

    logging.basicConfig(handlers=[_InterceptHandler()], level=0, force=True)
    # httpx logs full request URLs at INFO, which can contain webhook keys.
    # The Anthropic SDK uses httpx2/httpcore2, so suppress both client stacks.
    for name in ("httpx", "httpcore", "httpx2", "httpcore2"):
        logging.getLogger(name).setLevel(logging.WARNING)
    _CONFIGURED = True
