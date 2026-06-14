"""Artifact characterization pipeline for LLM-Sec evaluation results.

Provides per-scenario/per-domain consolidated CSV characterization, per-file
Garak ``.report.jsonl`` characterization, cross-repetition TFA variance
analysis, and latency comparison utilities.

``run_full_characterization`` orchestrates all of the above over an
``artifacts/`` tree, prints a console summary, and persists every result to
``output_dir`` as JSON/CSV files so that nothing is available only as console
output.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path

import pandas as pd

from eval.constants import PROBE_TO_SUITE


# ─────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────

# Primary detector per probe, used for TFA calculation. For probes with
# multiple detectors (e.g. encoding.* has DecodeMatch + DecodeApprox), only
# the primary detector is used to avoid double counting.
PRIMARY_DETECTOR = {
    "encoding.InjectBase64": "encoding.DecodeMatch",
    "encoding.InjectHex": "encoding.DecodeMatch",
    "promptinject.HijackKillHumans": "promptinject.AttackRogueString",
    "promptinject.HijackHateHumans": "promptinject.AttackRogueString",
    "promptinject.HijackLongPrompt": "promptinject.AttackRogueString",
    "latentinjection.LatentInjectionReport": "latentinjection.TriggerListDetector",
    "latentinjection.LatentInjectionFactSnippetLegal": "latentinjection.TriggerListDetector",
    "latentinjection.LatentInjectionResume": "latentinjection.TriggerListDetector",
    "latentinjection.LatentWhois": "latentinjection.TriggerListDetector",
    "leakreplay.GuardianComplete": "leakreplay.StartsWith",
    "goodside.Tag": "goodside.TriggerListDetector",
}

# Maps the 'A'/'B' scenario identifiers used by this module's public API to
# the literal strings used in consolidated CSV filenames and Garak run
# directory / report filenames, and back.
SCENARIO_TO_FILE = {
    "A": "unprotected",
    "B": "protected",
    "unprotected": "unprotected",
    "protected": "protected",
}
FILE_TO_SCENARIO = {"unprotected": "A", "protected": "B"}

# Matches Garak run directory names, e.g.
# '20260605_161626_regulatory_technical_unprotected_garak'.
_RUNDIR_RE = re.compile(
    r"^\d{8}_\d{6}_(?P<domain>.+)_(?P<scenario>unprotected|protected)_garak$"
)

# Matches Garak report filenames, e.g.
# 'unprotected_LLM01_encoding.InjectBase64_20260605_161626_rep00.report.jsonl'.
_JSONL_NAME_RE = re.compile(
    r"^(?P<scenario>unprotected|protected)_(?P<suite>LLM\d+)_(?P<probe>[\w.]+)_"
    r"(?P<timestamp>\d{8}_\d{6})_rep(?P<repetition>\d+)\.report\.jsonl$"
)


# ─────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────

def _latency_stats(series: pd.Series) -> dict:
    """Compute summary latency statistics for a numeric series.

    Args:
        series: Series of latency values in milliseconds (may contain NaNs
            or be empty).

    Returns:
        Dictionary with keys 'n', 'median', 'mean', 'std', 'p5', 'p95'.
        All statistic values are None when the series has no valid data.
    """
    values = pd.to_numeric(series, errors="coerce").dropna()
    if values.empty:
        return {"n": 0, "median": None, "mean": None, "std": None, "p5": None, "p95": None}
    return {
        "n": int(len(values)),
        "median": round(float(values.median()), 3),
        "mean": round(float(values.mean()), 3),
        "std": round(float(values.std()), 3) if len(values) > 1 else 0.0,
        "p5": round(float(values.quantile(0.05)), 3),
        "p95": round(float(values.quantile(0.95)), 3),
    }


def _iter_eval_entries(jsonl_path: Path):
    """Yield (probe, detector, passed, total) for each 'eval' entry.

    Args:
        jsonl_path: Path to a single .report.jsonl file.

    Yields:
        Tuples of (probe, detector, passed, total) extracted from lines
        whose entry_type is 'eval'. Malformed lines are skipped silently.
    """
    if not jsonl_path.exists():
        return
    with jsonl_path.open("r", encoding="utf-8") as f:
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
                obj.get("probe", ""),
                obj.get("detector", ""),
                obj.get("passed", 0),
                obj.get("total", 0),
            )


def _parse_run_dir_name(name: str) -> tuple[str, str] | None:
    """Parse a Garak run directory name into (domain, scenario).

    Args:
        name: Directory name, e.g.
            '20260605_161626_regulatory_technical_unprotected_garak'.

    Returns:
        A (domain, scenario) tuple where scenario is 'unprotected' or
        'protected', or None if the name does not match the expected
        pattern.
    """
    m = _RUNDIR_RE.match(name)
    if not m:
        return None
    return m.group("domain"), m.group("scenario")


def _summarize_detector_scores(detector_scores: dict) -> dict:
    """Reduce raw per-prompt detector scores to summary statistics.

    Args:
        detector_scores: Mapping of detector name to a list of float scores.

    Returns:
        Mapping of detector name to a dict with keys 'n', 'mean', 'std',
        'min', 'max'.
    """
    summary = {}
    for detector, scores in detector_scores.items():
        series = pd.Series(scores, dtype=float)
        summary[detector] = {
            "n": int(len(series)),
            "mean": round(float(series.mean()), 4) if len(series) else None,
            "std": round(float(series.std()), 4) if len(series) > 1 else 0.0,
            "min": round(float(series.min()), 4) if len(series) else None,
            "max": round(float(series.max()), 4) if len(series) else None,
        }
    return summary


# ─────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────

def characterize_consolidated_csv(
    csv_path: str,
    scenario: str,
    domain: str,
) -> dict:
    """Characterize a consolidated CSV for a given scenario and domain.

    Computes row counts by prompt_type, latency statistics (median, mean, std,
    p5, p95) separately for adversarial and legitimate prompts, block rate for
    adversarial prompts, and TFA per OWASP suite and per probe.

    Args:
        csv_path: Path to the consolidated CSV file.
        scenario: Scenario identifier, e.g. 'A' or 'B'.
        domain: Domain identifier, e.g. 'regulatory_technical'.

    Returns:
        Dictionary with keys: 'row_counts', 'latency_adversarial',
        'latency_legitimate', 'block_rate', 'tfa_by_suite', 'tfa_by_probe'.
    """
    result = {
        "scenario": scenario,
        "domain": domain,
        "csv_path": str(csv_path),
        "row_counts": {},
        "latency_adversarial": _latency_stats(pd.Series(dtype=float)),
        "latency_legitimate": _latency_stats(pd.Series(dtype=float)),
        "block_rate": None,
        "tfa_by_suite": {},
        "tfa_by_probe": {},
    }

    path = Path(csv_path)
    if not path.exists():
        return result

    df = pd.read_csv(path)
    if df.empty:
        return result

    result["row_counts"]["total"] = int(len(df))
    for prompt_type, count in df["prompt_type"].value_counts().items():
        result["row_counts"][str(prompt_type)] = int(count)

    df["latency_ms"] = pd.to_numeric(df["latency_ms"], errors="coerce")
    for col in ("was_blocked", "should_block", "garak_passed"):
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")

    adversarial = df[df["prompt_type"] == "adversarial"]
    legitimate = df[df["prompt_type"] == "legitimate"]

    result["latency_adversarial"] = _latency_stats(adversarial["latency_ms"])
    result["latency_legitimate"] = _latency_stats(legitimate["latency_ms"])

    if len(adversarial) > 0:
        result["block_rate"] = round(float(adversarial["was_blocked"].fillna(0).mean()), 4)

    scored = adversarial[adversarial["garak_passed"].notna()].copy()
    scored["garak_passed"] = scored["garak_passed"].astype(int)

    for suite, group in scored.groupby("suite"):
        n = int(len(group))
        passed = int(group["garak_passed"].sum())
        result["tfa_by_suite"][str(suite)] = {
            "n": n,
            "passed": passed,
            "tfa": round(passed / n, 4) if n else None,
        }

    for probe, group in scored.groupby("probe"):
        n = int(len(group))
        passed = int(group["garak_passed"].sum())
        result["tfa_by_probe"][str(probe)] = {
            "n": n,
            "passed": passed,
            "tfa": round(passed / n, 4) if n else None,
            "suite": PROBE_TO_SUITE.get(str(probe), "UNKNOWN"),
        }

    return result


def characterize_jsonl_run(
    jsonl_path: str,
) -> dict:
    """Parse a Garak .report.jsonl file and extract structured characterization.

    Parses entry_type='eval' lines for per-probe per-detector passed/total
    counts. Parses entry_type='attempt' lines for per-prompt detector scores
    and outputs. Extracts run metadata from entry_type='start_run setup'.

    Args:
        jsonl_path: Path to a single .report.jsonl file.

    Returns:
        Dictionary with keys: 'run_id', 'probe', 'domain', 'scenario',
        'repetition', 'eval_summary' (list of detector results),
        'attempt_count', 'detector_scores'.
    """
    path = Path(jsonl_path)

    result = {
        "run_id": "",
        "probe": "",
        "domain": "",
        "scenario": "",
        "repetition": None,
        "eval_summary": [],
        "attempt_count": 0,
        "detector_scores": {},
    }

    name_match = _JSONL_NAME_RE.match(path.name)
    if name_match:
        result["scenario"] = name_match.group("scenario")
        result["probe"] = name_match.group("probe")
        result["repetition"] = int(name_match.group("repetition"))

    run_dir_info = _parse_run_dir_name(path.parent.parent.name)
    if run_dir_info:
        result["domain"], rundir_scenario = run_dir_info
        result["scenario"] = result["scenario"] or rundir_scenario

    if not path.exists():
        return result

    seen_attempt_uuids: set = set()
    detector_scores: dict[str, list] = defaultdict(list)

    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            entry_type = obj.get("entry_type")

            if entry_type == "start_run setup":
                result["run_id"] = obj.get("transient.run_id", result["run_id"])
                if not result["probe"]:
                    result["probe"] = obj.get("plugins.probe_spec", "")

            elif entry_type == "eval":
                passed = obj.get("passed", 0)
                total = obj.get("total", 0)
                result["eval_summary"].append({
                    "probe": obj.get("probe", result["probe"]),
                    "detector": obj.get("detector", ""),
                    "passed": passed,
                    "total": total,
                    "nones": obj.get("nones", 0),
                    "tfa": round(passed / total, 4) if total else None,
                })

            elif entry_type == "attempt":
                detector_results = obj.get("detector_results") or {}
                if not detector_results:
                    continue
                uuid = obj.get("uuid")
                if uuid is not None:
                    seen_attempt_uuids.add(uuid)
                for detector, scores in detector_results.items():
                    detector_scores[detector].extend(float(s) for s in scores)

    result["attempt_count"] = len(seen_attempt_uuids)
    result["detector_scores"] = dict(detector_scores)
    return result


def compute_repetition_variance(
    jsonl_dir: str,
    probe: str,
    scenario: str,
    domain: str,
    primary_detector: str,
) -> dict:
    """Compute TFA mean and std across rep00-rep04 for a given probe.

    Loads all 5 repetition JSONL files for the specified probe, extracts the
    passed/total from the primary detector's eval entry, computes TFA per
    repetition, then returns mean, std, min, max, and a high_variance flag
    (True if std > 0.05).

    Args:
        jsonl_dir: Directory containing the .report.jsonl files.
        probe: Probe name, e.g. 'encoding.InjectBase64'.
        scenario: 'A' or 'B'.
        domain: Domain identifier.
        primary_detector: Detector name to use for TFA, e.g. 'encoding.DecodeMatch'.

    Returns:
        Dictionary with keys: 'probe', 'tfa_per_rep', 'mean', 'std', 'min',
        'max', 'high_variance'.
    """
    directory = Path(jsonl_dir)
    scenario_file = SCENARIO_TO_FILE.get(scenario, scenario)
    suite = PROBE_TO_SUITE.get(probe, "")

    result = {
        "probe": probe,
        "scenario": scenario,
        "domain": domain,
        "tfa_per_rep": {},
        "mean": None,
        "std": None,
        "min": None,
        "max": None,
        "high_variance": False,
    }

    tfa_values = []
    for rep in range(5):
        rep_key = f"rep{rep:02d}"
        pattern = f"{scenario_file}_{suite}_{probe}_*_rep{rep:02d}.report.jsonl"
        matches = sorted(directory.glob(pattern)) if directory.exists() else []

        if not matches:
            result["tfa_per_rep"][rep_key] = None
            continue

        per_detector: dict[str, list[int]] = defaultdict(lambda: [0, 0])
        for jsonl_file in matches:
            for _, detector, passed, total in _iter_eval_entries(jsonl_file):
                per_detector[detector][0] += passed
                per_detector[detector][1] += total

        if primary_detector in per_detector:
            passed_sum, total_sum = per_detector[primary_detector]
        elif len(per_detector) == 1:
            # Garak reports some detectors under a generic 'base.*' name rather
            # than the probe-prefixed name in PRIMARY_DETECTOR. When only one
            # detector ran for this probe, it is unambiguously the primary one.
            passed_sum, total_sum = next(iter(per_detector.values()))
        else:
            passed_sum, total_sum = 0, 0

        tfa = round(passed_sum / total_sum, 4) if total_sum else None
        result["tfa_per_rep"][rep_key] = tfa
        if tfa is not None:
            tfa_values.append(tfa)

    if tfa_values:
        series = pd.Series(tfa_values, dtype=float)
        result["mean"] = round(float(series.mean()), 4)
        result["std"] = round(float(series.std()), 4) if len(tfa_values) > 1 else 0.0
        result["min"] = round(float(series.min()), 4)
        result["max"] = round(float(series.max()), 4)
        result["high_variance"] = result["std"] > 0.05

    return result


def compare_latency(
    csv_paths: dict,
) -> dict:
    """Compare latency distributions across scenarios and domains.

    Accepts a dict mapping (scenario, domain) tuples to CSV paths. For each
    combination, computes median latency separately for adversarial and
    legitimate prompts. Returns a nested dict enabling pairwise comparison
    across scenarios and domains.

    Args:
        csv_paths: Dict with keys as (scenario, domain) tuples and values as
            CSV file paths.

    Returns:
        Nested dict: {(scenario, domain): {'adversarial': stats, 'legitimate': stats}}
        where stats contains median, mean, std, p5, p95.
    """
    results = {}
    for key, csv_path in csv_paths.items():
        path = Path(csv_path)
        entry = {
            "adversarial": _latency_stats(pd.Series(dtype=float)),
            "legitimate": _latency_stats(pd.Series(dtype=float)),
        }
        if path.exists():
            df = pd.read_csv(path)
            if "latency_ms" in df.columns and "prompt_type" in df.columns:
                df["latency_ms"] = pd.to_numeric(df["latency_ms"], errors="coerce")
                for prompt_type in ("adversarial", "legitimate"):
                    subset = df[df["prompt_type"] == prompt_type]["latency_ms"]
                    entry[prompt_type] = _latency_stats(subset)
        results[key] = entry
    return results


def run_full_characterization(
    artifacts_dir: str,
    output_dir: str,
) -> None:
    """Run complete artifact characterization and persist all results.

    Discovers all consolidated CSVs and JSONL files under artifacts_dir,
    runs all characterization and comparison functions, prints a summary
    to console, and persists all results to output_dir as:
      - characterization_summary.json  (full structured results)
      - repetition_variance.csv        (one row per probe per scenario per domain)
      - latency_comparison.csv         (one row per scenario/domain/prompt_type)
      - tfa_by_probe.csv               (one row per probe per scenario per domain)

    Args:
        artifacts_dir: Root directory containing run subdirectories.
        output_dir: Directory where output files will be written.
    """
    artifacts_path = Path(artifacts_dir)
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    print(f"\n{'='*70}")
    print("  ARTIFACT CHARACTERIZATION")
    print(f"  Artifacts : {artifacts_path.resolve()}")
    print(f"  Output    : {output_path.resolve()}")
    print(f"{'='*70}\n")

    # ── Consolidated CSV characterization ───────────────────────
    consolidated: dict[str, dict] = {}
    csv_paths: dict[tuple[str, str], Path] = {}

    print("[1/4] Characterizing consolidated CSVs...")
    for scenario_file, scenario_label in (("unprotected", "A"), ("protected", "B")):
        for csv_path in sorted(artifacts_path.glob(f"consolidated_*_{scenario_file}.csv")):
            domain = csv_path.stem[len("consolidated_"):-len(f"_{scenario_file}")]
            char = characterize_consolidated_csv(str(csv_path), scenario_label, domain)
            consolidated[f"{scenario_label}|{domain}"] = char
            csv_paths[(scenario_label, domain)] = csv_path

            rc = char["row_counts"]
            print(
                f"  - {scenario_label}/{domain}: "
                f"rows={rc.get('total', 0)} "
                f"(adversarial={rc.get('adversarial', 0)}, legitimate={rc.get('legitimate', 0)}), "
                f"block_rate={char['block_rate']}, "
                f"latency_adv_median={char['latency_adversarial']['median']}ms, "
                f"latency_legit_median={char['latency_legitimate']['median']}ms"
            )

    # ── Latency comparison ───────────────────────────────────────
    print("\n[2/4] Comparing latency across scenarios and domains...")
    latency_cmp = compare_latency(csv_paths)
    for (scenario_label, domain), stats in latency_cmp.items():
        print(
            f"  - {scenario_label}/{domain}: "
            f"adversarial median={stats['adversarial']['median']}ms (n={stats['adversarial']['n']}), "
            f"legitimate median={stats['legitimate']['median']}ms (n={stats['legitimate']['n']})"
        )

    # ── JSONL run characterization + repetition variance ─────────
    print("\n[3/4] Characterizing JSONL runs and computing repetition variance...")
    jsonl_runs: dict[str, list] = {}
    repetition_variance: list = []

    runs_dir = artifacts_path / "runs"
    if runs_dir.exists():
        for run_dir in sorted(runs_dir.iterdir()):
            if not run_dir.is_dir():
                continue
            info = _parse_run_dir_name(run_dir.name)
            if info is None:
                continue
            domain, scenario_file = info
            scenario_label = FILE_TO_SCENARIO[scenario_file]
            garak_dir = run_dir / "garak"
            if not garak_dir.exists():
                continue

            print(f"  - {run_dir.name}")

            file_summaries = []
            for jsonl_file in sorted(garak_dir.glob("*.report.jsonl")):
                char = characterize_jsonl_run(str(jsonl_file))
                file_summaries.append({
                    "file": jsonl_file.name,
                    "run_id": char["run_id"],
                    "probe": char["probe"],
                    "domain": char["domain"],
                    "scenario": char["scenario"],
                    "repetition": char["repetition"],
                    "eval_summary": char["eval_summary"],
                    "attempt_count": char["attempt_count"],
                    "detector_scores_summary": _summarize_detector_scores(char["detector_scores"]),
                })
            jsonl_runs[run_dir.name] = file_summaries

            for probe, primary_detector in PRIMARY_DETECTOR.items():
                variance = compute_repetition_variance(
                    str(garak_dir), probe, scenario_label, domain, primary_detector,
                )
                repetition_variance.append(variance)
                if variance["high_variance"]:
                    print(
                        f"    [HIGH VARIANCE] {probe}: "
                        f"mean={variance['mean']} std={variance['std']} "
                        f"per_rep={variance['tfa_per_rep']}"
                    )

    # ── Persist results ────────────────────────────────────────
    print("\n[4/4] Persisting results...")

    summary_json = {
        "consolidated": consolidated,
        "latency_comparison": {f"{s}|{d}": v for (s, d), v in latency_cmp.items()},
        "repetition_variance": repetition_variance,
        "jsonl_runs": jsonl_runs,
    }
    summary_path = output_path / "characterization_summary.json"
    with summary_path.open("w", encoding="utf-8") as f:
        json.dump(summary_json, f, indent=2, default=str)
    print(f"  - wrote {summary_path}")

    rep_rows = []
    for entry in repetition_variance:
        row = {
            "domain": entry["domain"],
            "scenario": entry["scenario"],
            "probe": entry["probe"],
            "suite": PROBE_TO_SUITE.get(entry["probe"], "UNKNOWN"),
        }
        row.update(entry["tfa_per_rep"])
        row["mean"] = entry["mean"]
        row["std"] = entry["std"]
        row["min"] = entry["min"]
        row["max"] = entry["max"]
        row["high_variance"] = entry["high_variance"]
        rep_rows.append(row)
    rep_path = output_path / "repetition_variance.csv"
    pd.DataFrame(rep_rows).to_csv(rep_path, index=False)
    print(f"  - wrote {rep_path} ({len(rep_rows)} rows)")

    lat_rows = []
    for (scenario_label, domain), stats in latency_cmp.items():
        for prompt_type, s in stats.items():
            row = {"scenario": scenario_label, "domain": domain, "prompt_type": prompt_type}
            row.update(s)
            lat_rows.append(row)
    lat_path = output_path / "latency_comparison.csv"
    pd.DataFrame(lat_rows).to_csv(lat_path, index=False)
    print(f"  - wrote {lat_path} ({len(lat_rows)} rows)")

    tfa_rows = []
    for key, char in consolidated.items():
        scenario_label, domain = key.split("|", 1)
        for probe, stats in char["tfa_by_probe"].items():
            row = {"scenario": scenario_label, "domain": domain, "probe": probe}
            row.update(stats)
            tfa_rows.append(row)
    tfa_path = output_path / "tfa_by_probe.csv"
    pd.DataFrame(tfa_rows).to_csv(tfa_path, index=False)
    print(f"  - wrote {tfa_path} ({len(tfa_rows)} rows)")

    print(f"\n{'='*70}\n")
