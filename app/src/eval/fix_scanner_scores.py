"""fix_scanner_scores.py — Correct input_scanner_score / output_scanner_score in
consolidated protected CSVs.

Background
----------
In runs generated with llm-guard 0.3.16 + the _raw_score_from_risk() wrapper in
shield.py, both scanner score columns were distorted:

    stored = threshold + raw_prob * (1 - threshold)

Because llm-guard 0.3.16 already returns raw [0,1] probabilities and the wrapper
assumed [-1,1] risk scores, it always used the positive branch and compressed all
values into [threshold, 1.0].  Legitimate prompts with raw_prob ≈ 0 ended up stored
as exactly the threshold value (0.92 or 0.50), making threshold-sensitivity analysis
meaningless.

This script applies the inverse:

    corrected = (stored - threshold) / (1 - threshold)

which recovers the original raw probability.  Only rows where stored >= threshold
are corrected; rows where the score is empty (scanner did not run) are left as-is.
"""

from __future__ import annotations

import argparse
import csv
import os
import tempfile
from pathlib import Path
from typing import Optional

INPUT_THRESHOLD  = 0.92   # PromptInjection threshold used during the experiment
OUTPUT_THRESHOLD = 0.50   # Sensitive threshold used during the experiment


def _correct_score(value_str: str, threshold: float) -> str:
    """Return the corrected score string, or the original if no correction applies."""
    if not value_str:
        return value_str
    try:
        stored = float(value_str)
    except ValueError:
        return value_str

    if stored < threshold:
        # Score below threshold was never produced by _raw_score_from_risk;
        # leave it alone (shouldn't happen in practice but be safe).
        return value_str

    # stored = threshold + raw * (1 - threshold)  ->  raw = (stored - threshold) / (1 - threshold)
    raw = (stored - threshold) / (1.0 - threshold)
    raw = min(max(raw, 0.0), 1.0)
    return f"{raw:.4f}"


def _score_stats(values: list[float]) -> dict:
    if not values:
        return {"count": 0, "min": None, "max": None, "mean": None, "unique": 0}
    return {
        "count": len(values),
        "min":   round(min(values), 4),
        "max":   round(max(values), 4),
        "mean":  round(sum(values) / len(values), 4),
        "unique": len(set(round(v, 4) for v in values)),
    }


def fix_csv(csv_path: Path) -> None:
    """Read, correct and atomically overwrite a single consolidated CSV."""
    with csv_path.open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
        if fieldnames is None:
            print(f"  SKIP {csv_path.name}: no header")
            return

        has_input  = "input_scanner_score"  in fieldnames
        has_output = "output_scanner_score" in fieldnames
        if not has_input and not has_output:
            print(f"  SKIP {csv_path.name}: score columns absent")
            return

        rows = list(reader)

    # Collect before-stats
    before_in  = [float(r["input_scanner_score"])  for r in rows if has_input  and r.get("input_scanner_score")]
    before_out = [float(r["output_scanner_score"]) for r in rows if has_output and r.get("output_scanner_score")]

    # Apply correction
    for row in rows:
        if has_input:
            row["input_scanner_score"]  = _correct_score(row.get("input_scanner_score",  ""), INPUT_THRESHOLD)
        if has_output:
            row["output_scanner_score"] = _correct_score(row.get("output_scanner_score", ""), OUTPUT_THRESHOLD)

    # Collect after-stats
    after_in  = [float(r["input_scanner_score"])  for r in rows if has_input  and r.get("input_scanner_score")]
    after_out = [float(r["output_scanner_score"]) for r in rows if has_output and r.get("output_scanner_score")]

    # Atomic write: write to sibling .tmp, then rename
    tmp_fd, tmp_path = tempfile.mkstemp(
        dir=csv_path.parent, suffix=".tmp", prefix=csv_path.stem + "_"
    )
    try:
        with os.fdopen(tmp_fd, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        os.replace(tmp_path, csv_path)
    except Exception:
        os.unlink(tmp_path)
        raise

    # Print summary
    print(f"\n  {csv_path.name}")
    if has_input:
        bi, ai = _score_stats(before_in), _score_stats(after_in)
        print(f"    input_scanner_score  BEFORE: min={bi['min']} max={bi['max']} mean={bi['mean']} unique={bi['unique']}")
        print(f"    input_scanner_score  AFTER:  min={ai['min']} max={ai['max']} mean={ai['mean']} unique={ai['unique']}")
    if has_output:
        bo, ao = _score_stats(before_out), _score_stats(after_out)
        print(f"    output_scanner_score BEFORE: min={bo['min']} max={bo['max']} mean={bo['mean']} unique={bo['unique']}")
        print(f"    output_scanner_score AFTER:  min={ao['min']} max={ao['max']} mean={ao['mean']} unique={ao['unique']}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Correct scanner score columns in consolidated protected CSVs."
    )
    parser.add_argument(
        "--artifacts-dir",
        type=Path,
        default=Path(__file__).resolve().parents[3] / "artifacts",
        help="Path to the artifacts directory (default: project root artifacts/)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would change without writing any files.",
    )
    args = parser.parse_args()

    artifacts_dir: Path = args.artifacts_dir
    if not artifacts_dir.is_dir():
        print(f"ERROR: artifacts directory not found: {artifacts_dir}")
        raise SystemExit(1)

    candidates = sorted(artifacts_dir.glob("consolidated_*_protected.csv"))
    if not candidates:
        print(f"No consolidated_*_protected.csv files found in {artifacts_dir}")
        return

    print(f"Found {len(candidates)} file(s) to process under {artifacts_dir}")
    if args.dry_run:
        print("DRY RUN — no files will be modified.\n")

    for csv_path in candidates:
        if args.dry_run:
            print(f"  would fix: {csv_path.name}")
        else:
            fix_csv(csv_path)

    if not args.dry_run:
        print("\nDone. Re-run threshold_sensitivity.py to see corrected distributions.")


if __name__ == "__main__":
    main()
