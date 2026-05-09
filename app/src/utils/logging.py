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
    """
    Configure a logger writing to stdout and, when run_paths is provided, to a per-run log file.

    Usage::

        logger = setup_logging(level="DEBUG", run_paths=run_paths)
        logger.info("starting run")
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
