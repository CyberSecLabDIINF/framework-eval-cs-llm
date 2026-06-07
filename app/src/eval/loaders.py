"""Data loading layer for evaluation result processing.

Reads Garak ``*.report.jsonl`` files, consolidated CSVs and latency CSVs,
and discovers run directories/domains under ``artifacts/``. These functions
form the data-access layer consumed by ``metrics.py`` and ``plots.py``.
"""

import json
from collections import defaultdict
from pathlib import Path

import pandas as pd

from eval.constants import PRIMARY_DETECTOR, PROBE_TO_SUITE


# ─────────────────────────────────────────────
# Private helpers — shared across functions
# ─────────────────────────────────────────────

def _load_jsonl_eval_entries(garak_dir: Path):
    """Yields (probe, detector, passed, total) for every eval entry in *.report.jsonl files."""
    for jsonl_file in sorted(garak_dir.glob("*.report.jsonl")):
        with jsonl_file.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if obj.get("entry_type") != "eval":
                    continue
                yield (
                    obj.get("probe", "unknown"),
                    obj.get("detector", ""),
                    obj.get("passed", 0),
                    obj.get("total", 0),
                )


def _extract_suite(val) -> str:
    """Parses 'LLM01|probe.name' into 'LLM01'. Returns 'UNKNOWN' if unparseable."""
    if pd.isna(val):
        return "UNKNOWN"
    return str(val).split("|")[0] if "|" in str(val) else "UNKNOWN"


def _confusion_counts(adv_df: pd.DataFrame, legit_df: pd.DataFrame) -> dict:
    """Returns TP, FN, FP, TN counts from adversarial and legitimate DataFrames."""
    return {
        "TP": int(((adv_df["should_block"]  == 1) & (adv_df["was_blocked"]  == 1)).sum()),
        "FN": int(((adv_df["should_block"]  == 1) & (adv_df["was_blocked"]  == 0)).sum()),
        "FP": int(((legit_df["should_block"] == 0) & (legit_df["was_blocked"] == 1)).sum()),
        "TN": int(((legit_df["should_block"] == 0) & (legit_df["was_blocked"] == 0)).sum()),
    }


def _load_consolidated_legit(artifacts_dir: Path, domain: str, scenario: str) -> pd.DataFrame:
    """Loads consolidated CSV for a domain/scenario, legitimate rows only."""
    path = artifacts_dir / f"consolidated_{domain}_{scenario}.csv"
    if not path.exists():
        return pd.DataFrame()
    df = pd.read_csv(path)
    df = df[df["prompt_type"] == "legitimate"].copy()
    if "response_has_confidential" in df.columns:
        df["response_has_confidential"] = pd.to_numeric(
            df["response_has_confidential"], errors="coerce"
        ).fillna(0).astype(int)
    return df


# ─────────────────────────────────────────────
# Data loading
# ─────────────────────────────────────────────

def load_tfa_from_jsonl(garak_dir: Path) -> dict:
    """Computes TFA per probe and suite from *.report.jsonl files."""
    per_probe: dict[str, dict] = defaultdict(lambda: {"passed": 0, "total": 0})

    for probe, detector, passed, total in _load_jsonl_eval_entries(garak_dir):
        primary = PRIMARY_DETECTOR.get(probe)
        if primary is not None and detector != primary:
            continue
        per_probe[probe]["passed"] += passed
        per_probe[probe]["total"]  += total

    for probe, v in per_probe.items():
        v["suite"] = PROBE_TO_SUITE.get(probe, "UNKNOWN")
        v["TFA"]   = round(v["passed"] / v["total"], 4) if v["total"] > 0 else None

    per_suite: dict[str, dict] = defaultdict(lambda: {"passed": 0, "total": 0})
    for probe, v in per_probe.items():
        suite = v["suite"]
        per_suite[suite]["passed"] += v["passed"]
        per_suite[suite]["total"]  += v["total"]
    for suite, v in per_suite.items():
        v["TFA"] = round(v["passed"] / v["total"], 4) if v["total"] > 0 else None

    total_passed = sum(v["passed"] for v in per_probe.values())
    total_total  = sum(v["total"]  for v in per_probe.values())

    return {
        "per_probe": dict(per_probe),
        "per_suite": dict(per_suite),
        "global": {
            "passed": total_passed,
            "total":  total_total,
            "TFA":    round(total_passed / total_total, 4) if total_total > 0 else None,
        },
    }


def load_consolidated(
    artifacts_dir: Path,
    domain: str,
    scenario: str,
    run_id: str | None = None,
) -> pd.DataFrame:
    """Loads consolidated CSV for a domain/scenario, adversarial rows only.

    Args:
        artifacts_dir: Root artifacts directory.
        domain: Corpus domain name (e.g. ``regulatory_technical``).
        scenario: Scenario tag (``unprotected`` or ``protected``).
        run_id: Optional run identifier. When provided, only rows whose
            ``run_id`` column matches this value are returned.  Rows that
            pre-date the ``run_id`` column (and therefore have an empty
            value) are excluded when a filter is supplied.
    """
    path = artifacts_dir / f"consolidated_{domain}_{scenario}.csv"
    if not path.exists():
        return pd.DataFrame()
    df = pd.read_csv(path)
    df = df[df["prompt_type"] == "adversarial"].copy()
    if run_id is not None and "run_id" in df.columns:
        df = df[df["run_id"] == run_id].copy()
    for col in ["was_blocked", "should_block", "response_has_confidential"]:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).astype(int)
    if "garak_passed" in df.columns:
        df["garak_passed"] = pd.to_numeric(df["garak_passed"], errors="coerce")
    return df


def load_latency(latency_dir: Path, filename: str) -> pd.DataFrame:
    """Loads a latency CSV, keeping only /generate requests."""
    path = latency_dir / filename
    if not path.exists():
        return pd.DataFrame()
    df = pd.read_csv(path, header=None, names=[
        "timestamp", "scenario", "domain", "method",
        "endpoint", "status_code", "latency_ms",
        "col8", "suite_probe", "prompt_tokens", "response_tokens"
    ])
    df = df[df["endpoint"] == "/generate"].copy()
    df["latency_ms"] = pd.to_numeric(df["latency_ms"], errors="coerce")
    df = df[df["latency_ms"].notna()]
    return df


def find_run_dir(runs_dir: Path, domain: str, scenario: str) -> Path | None:
    """Return the most recent run directory matching ``domain`` and ``scenario``, or None."""
    keyword = f"{domain}_{scenario}"
    matches = [d for d in runs_dir.iterdir() if d.is_dir() and keyword in d.name]
    return sorted(matches)[-1] if matches else None


def discover_domains(runs_dir: Path) -> list:
    """Auto-discovers available domains from run directory names."""
    domains = set()
    if not runs_dir.exists():
        return []
    for d in runs_dir.iterdir():
        if not d.is_dir():
            continue
        parts = d.name.split("_")
        if len(parts) < 4 or parts[-1] != "garak":
            continue
        scenario = parts[-2]
        if scenario not in ("unprotected", "protected"):
            continue
        domain = "_".join(parts[2:-2])
        if domain:
            domains.add(domain)
    return sorted(domains)
