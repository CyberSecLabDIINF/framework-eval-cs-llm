"""
extract_examples.py
-------------------
Extracts contrasting example pairs (attack succeeded in Scenario A vs. attack
failed in Scenario B) from the four consolidated CSVs and writes the results to
artifacts/examples.json.

Usage (from repo root, with venv active):
    python3 scripts/extract_examples.py [--artifacts <dir>]
"""

import argparse
import json
import sys
from pathlib import Path

import pandas as pd

# Ground-truth column per OWASP suite (as documented in CLAUDE.md).
GT_COLUMN: dict[str, str] = {
    "LLM01": "garak_passed",
    "LLM02": "response_has_confidential",
    "LLM07": "response_has_system_prompt",
    "LLM08": "injection_followed",
}

DOMAINS = ["academic_institutional", "regulatory_technical"]

# Columns carried into the output JSON for each scenario row.
_SCALAR_COLS = [
    "probe",
    "response",
    "latency_ms",
    "was_blocked",
    "scanner_triggered",
    "block_reason",
    "garak_passed",
    "response_has_confidential",
    "response_has_system_prompt",
    "injection_followed",
]


def _load_csv(artifacts: Path, domain: str, scenario: str) -> pd.DataFrame:
    path = artifacts / f"consolidated_{domain}_{scenario}.csv"
    return pd.read_csv(path, low_memory=False)


def _nullable_val(val):
    """Convert NaN / NA to None for JSON serialisation."""
    try:
        if pd.isna(val):
            return None
    except (TypeError, ValueError):
        pass
    # Convert numpy scalars to native Python types.
    if hasattr(val, "item"):
        return val.item()
    return val


def _row_to_dict(row: pd.Series, suffix: str, gt_col: str) -> dict:
    """Extract output fields from a DataFrame row, keyed with a scenario suffix."""
    out: dict = {}
    for col in _SCALAR_COLS:
        key = f"{col}_{suffix}" if col not in ("probe",) else col
        out[key] = _nullable_val(row.get(col))
    # Expose the specific GT column value under a suite-agnostic key.
    out[f"gt_value_{suffix}"] = _nullable_val(row.get(gt_col))
    out[f"gt_column"] = gt_col
    return out


def extract_pairs(artifacts: Path) -> tuple[list[dict], list[dict]]:
    """
    Return (examples, missing) where:
      - examples: list of contrasting pair dicts
      - missing:  list of dicts describing (suite, domain) combos with no pair found
    """
    examples: list[dict] = []
    missing: list[dict] = []

    for domain in DOMAINS:
        dfu = _load_csv(artifacts, domain, "unprotected")
        dfp = _load_csv(artifacts, domain, "protected")

        adv_u = dfu[dfu["prompt_type"] == "adversarial"].copy()
        adv_p = dfp[dfp["prompt_type"] == "adversarial"].copy()

        # Pre-compute response length for shortest-response tie-breaking.
        adv_u["_resp_len"] = adv_u["response"].astype(str).str.len()
        adv_p["_resp_len"] = adv_p["response"].astype(str).str.len()

        for suite, gt_col in GT_COLUMN.items():
            su = adv_u[adv_u["suite"] == suite]
            sp = adv_p[adv_p["suite"] == suite]

            # --- Scenario A: attack succeeded (ground-truth column == 1) ---
            success_mask_u = su[gt_col] == 1
            success_u = su[success_mask_u]

            if success_u.empty:
                missing.append(
                    {
                        "suite": suite,
                        "domain": domain,
                        "reason": (
                            f"Attack never succeeded in unprotected scenario "
                            f"('{gt_col}' is always 0 or absent)."
                        ),
                    }
                )
                continue

            # --- Scenario B: attack failed (blocked OR ground-truth column == 0) ---
            # Note: for LLM01, garak_passed remains 1 even when the shield blocks
            # the request, so we rely on was_blocked as the primary failure signal.
            failure_mask_p = (sp["was_blocked"] == 1) | (sp[gt_col] == 0)
            failed_p = sp[failure_mask_p]

            if failed_p.empty:
                missing.append(
                    {
                        "suite": suite,
                        "domain": domain,
                        "reason": (
                            "Defense never triggered in protected scenario "
                            f"('{gt_col}' always 1 and 'was_blocked' always 0)."
                        ),
                    }
                )
                continue

            # --- Prompt intersection ---
            prompts_success = set(success_u["prompt"].dropna())
            prompts_failed = set(failed_p["prompt"].dropna())
            shared_prompts = prompts_success & prompts_failed

            if not shared_prompts:
                missing.append(
                    {
                        "suite": suite,
                        "domain": domain,
                        "reason": (
                            f"No common prompt found between unprotected-success "
                            f"({len(success_u)} rows) and protected-failure "
                            f"({len(failed_p)} rows)."
                        ),
                    }
                )
                continue

            # --- Select the pair with the shortest combined response ---
            best_score = float("inf")
            best_u: pd.Series | None = None
            best_p: pd.Series | None = None

            for prompt in shared_prompts:
                cand_u = success_u[success_u["prompt"] == prompt]
                cand_p = failed_p[failed_p["prompt"] == prompt]

                if cand_u.empty or cand_p.empty:
                    continue

                # Pick shortest response within each side, then minimise combined length.
                row_u = cand_u.nsmallest(1, "_resp_len").iloc[0]
                row_p = cand_p.nsmallest(1, "_resp_len").iloc[0]
                score = row_u["_resp_len"] + row_p["_resp_len"]

                if score < best_score:
                    best_score = score
                    best_u = row_u
                    best_p = row_p

            if best_u is None:
                missing.append(
                    {
                        "suite": suite,
                        "domain": domain,
                        "reason": "Shared prompts found but candidate filtering returned no rows.",
                    }
                )
                continue

            entry: dict = {
                "suite": suite,
                "domain": domain,
                "prompt": _nullable_val(best_u["prompt"]),
            }
            entry.update(_row_to_dict(best_u, "A", gt_col))
            entry.update(_row_to_dict(best_p, "B", gt_col))

            examples.append(entry)

    return examples, missing


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--artifacts",
        type=Path,
        default=Path("artifacts"),
        help="Root artifacts directory (default: artifacts/)",
    )
    args = parser.parse_args()

    artifacts = args.artifacts.resolve()
    if not artifacts.is_dir():
        sys.exit(f"ERROR: artifacts directory not found: {artifacts}")

    print(f"Loading CSVs from: {artifacts}")
    examples, missing = extract_pairs(artifacts)

    # Write JSON output.
    out_path = artifacts / "examples.json"
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(examples, fh, ensure_ascii=False, indent=2)

    print(f"\nWrote {len(examples)} example pair(s) to: {out_path}")

    # Console summary.
    if missing:
        print(f"\n{'─' * 60}")
        print(f"MISSING PAIRS ({len(missing)} combination(s) with no contrasting example):")
        print(f"{'─' * 60}")
        for m in missing:
            print(f"  [{m['suite']}] {m['domain']}")
            print(f"    Reason: {m['reason']}")
    else:
        print("\nAll (suite, domain) combinations produced a contrasting pair.")

    if examples:
        print(f"\n{'─' * 60}")
        print("FOUND PAIRS:")
        print(f"{'─' * 60}")
        for ex in examples:
            gt_col = ex["gt_column"]
            print(
                f"  [{ex['suite']}] {ex['domain']} | probe: {ex.get('probe_A') or ex.get('probe')}"
            )
            print(
                f"    A: {gt_col}={ex.get(f'gt_value_A')}, was_blocked={ex.get('was_blocked_A')}, "
                f"latency={ex.get('latency_ms_A'):.0f} ms"
            )
            print(
                f"    B: {gt_col}={ex.get(f'gt_value_B')}, was_blocked={ex.get('was_blocked_B')}, "
                f"scanner={ex.get('scanner_triggered_B')}, latency={ex.get('latency_ms_B'):.0f} ms"
            )


if __name__ == "__main__":
    main()
