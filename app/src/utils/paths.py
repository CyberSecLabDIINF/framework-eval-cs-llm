from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Literal, Dict, Any
import re
import json
import subprocess

from settings import Settings


@dataclass(frozen=True)
class RunPaths:
    """
    Standard directory layout for a single evaluation run.
    Holds paths for config snapshots, logs, Garak outputs, and metrics.
    """
    run_dir: Path
    logs_dir: Path
    config_used_dir: Path
    garak_dir: Path
    summary_md: Path
    metrics_json: Path


def utc_run_id(prefix: Optional[str] = None) -> str:
    """
    Generate a UTC-based run ID.
    e.g. 20260128_175121 or 20260128_175121_unprotected_garak with a prefix.
    """
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    return f"{ts}_{prefix}" if prefix else ts

def _sanitize_tag(tag: str) -> str:
    tag = (tag or "").strip().lower()
    tag = tag.replace(" ", "_")
    tag = re.sub(r"[^a-z0-9_-]+", "", tag)
    return tag or "default"

def make_run_paths(
    settings: Settings,
    target: Literal["unprotected", "protected"],
    run_id: Optional[str] = None,
    run_kind: Optional[str] = None,
) -> RunPaths:
    """Create the standard directory layout for a new run and return its paths.

    Subdirectories ``logs/``, ``config_used/``, and ``garak/`` are created
    immediately under the run directory.

    Run directory naming convention:
      - ``garak``   → ``<ts>_<dataset>_<target>_garak``
      - ``latency`` → ``<ts>_<dataset>_latency``
      - ``compare`` → ``<ts>_<dataset>_compare``
      - (fallback)  → ``<ts>_<dataset>_<target>``

    Args:
        settings: Application settings instance.
        target: Evaluation scenario (``"unprotected"`` or ``"protected"``).
        run_id: Explicit run identifier; a UTC timestamp is generated when omitted.
        run_kind: Run type label used for directory naming (e.g. ``"garak"``).

    Returns:
        A :class:`RunPaths` instance with all sub-paths populated.
    """
    tag = _sanitize_tag(getattr(settings, "dataset_tag", "default"))

    if run_kind in ("latency", "compare", "ingest"):
        prefix = f"{tag}_{run_kind}"
    elif run_kind == "garak":
        prefix = f"{tag}_{target}_garak"
    else:
        prefix = f"{tag}_{target}"

    rid = run_id or utc_run_id(prefix=prefix)
    run_dir = settings.runs_dir / rid

    logs_dir = run_dir / "logs"
    config_used_dir = run_dir / "config_used"
    garak_dir = run_dir / "garak"

    summary_md = run_dir / "summary.md"
    metrics_json = run_dir / "metrics.json"

    for d in (run_dir, logs_dir, config_used_dir, garak_dir):
        d.mkdir(parents=True, exist_ok=True)

    return RunPaths(
        run_dir=run_dir,
        logs_dir=logs_dir,
        config_used_dir=config_used_dir,
        garak_dir=garak_dir,
        summary_md=summary_md,
        metrics_json=metrics_json,
    )

def run_paths_from_existing(run_dir: Path) -> RunPaths:
    """
    Reconstruct a RunPaths from an existing run directory.
    Used by analysis commands that receive an explicit output directory.
    """
    logs_dir = run_dir / "logs"
    config_used_dir = run_dir / "config_used"
    garak_dir = run_dir / "garak"

    summary_md = run_dir / "summary.md"
    metrics_json = run_dir / "metrics.json"

    for d in (run_dir, logs_dir, config_used_dir, garak_dir):
        d.mkdir(parents=True, exist_ok=True)

    return RunPaths(
        run_dir=run_dir,
        logs_dir=logs_dir,
        config_used_dir=config_used_dir,
        garak_dir=garak_dir,
        summary_md=summary_md,
        metrics_json=metrics_json,
    )

def _safe_git_commit(project_root: Path) -> Optional[str]:
    """Return the current git commit hash, or None if not in a git repository."""
    try:
        if not (project_root / ".git").exists():
            return None
        out = subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=str(project_root),
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        return out or None
    except Exception:
        return None

def snapshot_configs(
    settings: Settings,
    run_paths: RunPaths,
    *,
    target: Optional[Literal["unprotected", "protected"]] = None,
    suite: Optional[str] = None,
    probe: Optional[str] = None,
    run_kind: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    """Copy key config files into the run directory and write ``run_meta.json``.

    Provides reproducibility: every run captures the exact config that was
    active at execution time. Secrets (e.g. ``.env``) are intentionally
    excluded.

    Args:
        settings: Application settings instance.
        run_paths: Paths for the current run (destination for copied files).
        target: Evaluation scenario written to ``run_meta.json``.
        suite: OWASP suite filter applied during this run, if any.
        probe: Specific probe filter applied during this run, if any.
        run_kind: Run classification — ``"experiment"`` or ``"smoke_test"``.
            Recorded in ``run_meta.json`` and used downstream to route
            consolidated results to the correct CSV.
        extra: Additional key/value pairs merged into ``run_meta.json``.
    """
    dataset_tag = getattr(settings, "dataset_tag", "default")
    to_copy = [
        settings.get_rag_config_path(dataset_tag),
        settings.owasp_suites_path,
        settings.garak_rest_base_path,
    ]

    for src in to_copy:
        if src.exists():
            dst = run_paths.config_used_dir / src.name
            dst.write_bytes(src.read_bytes())

    meta: Dict[str, Any] = {
        "run_id": run_paths.run_dir.name,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "dataset_tag": getattr(settings, "dataset_tag", "default"),
        "target": target or getattr(settings, "target", None),
        "run_kind": run_kind,
        "suite_filter": suite,
        "probe_filter": probe,
        "rag_url": settings.rag_url,
        "shield_url": settings.shield_url,
        "rag_health_url": settings.rag_health_url,
        "shield_health_url": settings.shield_health_url,
        "rag_generate_url": settings.rag_generate_url,
        "shield_generate_url": settings.shield_generate_url,
        "project_root": str(settings.project_root),
        "data_dir": str(settings.data_dir),
        "artifacts_dir": str(settings.artifacts_dir),
        "runs_dir": str(settings.runs_dir),
        "garak_runs_dir": str(settings.garak_runs_dir),
        "config_used_dir": str(run_paths.config_used_dir),
        "garak_dir": str(run_paths.garak_dir),
        "logs_dir": str(run_paths.logs_dir),
        "git_commit": _safe_git_commit(settings.project_root),
    }

    if extra:
        meta.update(extra)

    (run_paths.run_dir / "run_meta.json").write_text(
        json.dumps(meta, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )