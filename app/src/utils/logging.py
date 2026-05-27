from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Optional

from utils.paths import RunPaths


def setup_logging(
    *,
    name: str = "framework_eval_cs_llm",
    level: str = "INFO",
    run_paths: Optional[RunPaths] = None,
    filename: str = "app.log",
) -> logging.Logger:
    """Configure a logger that writes to stdout and optionally to a per-run file.

    Idempotent: clears existing handlers on the named logger before adding new
    ones, so repeated calls (e.g. from tests) do not produce duplicate output.

    Args:
        name: Logger name; shared across the application so callers can
            retrieve the same instance with ``logging.getLogger(name)``.
        level: Logging level string (e.g. ``"INFO"``, ``"DEBUG"``).
        run_paths: When provided, a ``FileHandler`` writing to
            ``run_paths.logs_dir / filename`` is added alongside stdout.
        filename: Log file name used when ``run_paths`` is supplied.

    Returns:
        The configured :class:`logging.Logger` instance.
    """
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.propagate = False  # Prevent duplicate entries if the root logger also has handlers.

    # Clear handlers from a previous call to avoid duplicate output.
    if logger.handlers:
        logger.handlers.clear()

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(formatter)
    logger.addHandler(sh)

    if run_paths is not None:
        log_path: Path = run_paths.logs_dir / filename
        fh = logging.FileHandler(log_path, encoding="utf-8")
        fh.setFormatter(formatter)
        logger.addHandler(fh)

    return logger
