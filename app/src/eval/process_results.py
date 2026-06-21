#!/usr/bin/env python3
"""
process_results.py
==================
Computes TFA, LAS and deep analysis from LLM-Sec experiment artifacts.

Sources:
  - TFA        : artifacts/runs/<run_dir>/garak/*.report.jsonl
  - LAS        : artifacts/latency/latency_unprotected_direct.csv
                  artifacts/latency/latency_protected.csv
  - Deep anal. : artifacts/consolidated_<domain>_<scenario>.csv

garak_passed convention (Garak):
  passed → count of attempts where system RESISTED the attack (TP)
  total  → total attempts for that probe/detector

TFA = sum(passed) / sum(total) per vector, using primary detector only.

Primary detector per probe:
  encoding.*  → encoding.DecodeMatch  (DecodeApprox discarded)
  all others  → single detector, used directly

Usage:
  python process_results.py --artifacts artifacts/
  python process_results.py --artifacts artifacts/ --plots
  python process_results.py --artifacts artifacts/ --domains regulatory_technical

Requires: pandas, scipy, matplotlib
  pip install pandas scipy matplotlib
"""

import argparse
from pathlib import Path

from eval.constants import *
from eval.loaders import *
from eval.loaders import load_tfa_from_csv
from eval.metrics import *
from eval.plots import *
from eval.characterizer import run_full_characterization
from eval.exfiltration import run_exfiltration_analysis
from eval.consolidator import run_backfill_scores

# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="LLM-Sec results processing & analysis")
    parser.add_argument("--artifacts", type=Path, default=Path("artifacts"),
                        help="Path to artifacts/ directory (default: artifacts/)")
    parser.add_argument("--domains", nargs="+", default=None,
                        help="Domains to analyze (default: auto-discover from runs/)")
    parser.add_argument("--plots", action="store_true",
                        help="Generate and save figures to artifacts/figures/")
    parser.add_argument("--deep", action="store_true",
                        help="Run deep analysis from consolidated CSVs")
    parser.add_argument("--exfiltration", action="store_true",
                        help="Run confidential-data exfiltration analysis (CONFIDENTIAL "
                             "marker, verbatim ground-truth values, PII) and persist results")
    parser.add_argument("--data-dir", type=Path, default=Path("data"),
                        help="Path to data/ directory for --exfiltration (default: data/)")
    parser.add_argument("--characterize", action="store_true",
                        help="Run full artifact characterization (characterizer.py) and persist results")
    parser.add_argument("--artifacts-dir", type=Path, default=None,
                        help="Artifacts directory for --characterize (default: value of --artifacts)")
    parser.add_argument("--output-dir", type=Path, default=None,
                        help="Output directory for --characterize results "
                             "(default: <artifacts-dir>/characterization)")
    parser.add_argument("--backfill-scores", action="store_true",
                        help="One-time fix: convert input_scanner_score/output_scanner_score "
                             "in every artifacts/consolidated_*.csv from threshold-relative risk "
                             "scores ([-1,1]) to raw probabilities (see "
                             "eval.consolidator.backfill_raw_scores). Only run on CSVs generated "
                             "before the _raw_score_from_risk() fix in api/shield.py.")
    args = parser.parse_args()

    # ── Backfill scanner scores (one-time fix) ───────────────
    if args.backfill_scores:
        run_backfill_scores(args.artifacts)
        return

    # ── Artifact characterization ────────────────────────────
    if args.characterize:
        char_artifacts_dir = args.artifacts_dir or args.artifacts
        char_output_dir = args.output_dir or (char_artifacts_dir / "characterization")
        run_full_characterization(str(char_artifacts_dir), str(char_output_dir))
        if not (args.deep or args.plots or args.domains):
            return

    artifacts   = args.artifacts
    runs_dir    = artifacts / "runs"
    latency_dir = artifacts / "latency"
    figures_dir = artifacts / "figures"

    available = discover_domains(runs_dir)
    if not available:
        print("  [ERROR] No runs found in", runs_dir)
        return
    domains = args.domains if args.domains else available
    unknown = [d for d in domains if d not in available]
    if unknown:
        print(f"  [WARN] Domains not found in runs/: {unknown}")
        domains = [d for d in domains if d in available]

    print(f"\n{'='*70}")
    print(f"  LLM-Sec RESULTS PROCESSING")
    print(f"  Artifacts : {artifacts.resolve()}")
    print(f"  Domains   : {domains}")
    print(f"{'='*70}")

    # ── TFA ─────────────────────────────────────────────────
    # tfa_by_domain: garak_passed-based TFA (load_tfa_from_jsonl) — only
    #   valid ground truth for LLM01, kept for per-probe detail plots.
    # tfa_csv_by_domain: per-suite TFA computed with the correct ground
    #   truth per OWASP suite (load_tfa_from_csv -> compute_tfa_by_suite).
    tfa_by_domain = {}
    tfa_csv_by_domain = {}
    for domain in domains:
        tfa_a, tfa_b = {}, {}
        run_a = find_run_dir(runs_dir, domain, "unprotected")
        if run_a:
            tfa_a = load_tfa_from_jsonl(run_a / "garak")
        else:
            print(f"  [WARN] No unprotected run found for {domain}")
        run_b = find_run_dir(runs_dir, domain, "protected")
        if run_b:
            tfa_b = load_tfa_from_jsonl(run_b / "garak")
        else:
            print(f"  [INFO] No protected run found for {domain} (Scenario B pending)")
        tfa_by_domain[domain] = {"A": tfa_a, "B": tfa_b}

        tfa_csv_a = load_tfa_from_csv(artifacts, domain, "unprotected")
        tfa_csv_b = load_tfa_from_csv(artifacts, domain, "protected")
        tfa_csv_by_domain[domain] = {"A": tfa_csv_a, "B": tfa_csv_b}

        print_tfa(tfa_a, tfa_b, domain, tfa_csv_a=tfa_csv_a, tfa_csv_b=tfa_csv_b)

        # Weighted global TFA using the correct per-suite ground truth
        # (compute_tfa_global), as opposed to the garak_passed-based GLOBAL
        # block above which is only a valid proxy for LLM01.
        global_df_a = load_consolidated(artifacts, domain, "unprotected")
        global_df_b = load_consolidated(artifacts, domain, "protected")
        global_a = compute_tfa_global(global_df_a)
        global_b = compute_tfa_global(global_df_b) if not global_df_b.empty else None
        print_tfa_global(domain, global_a, global_b)

    # ── LAS ─────────────────────────────────────────────────
    lat_a = load_latency(latency_dir, "latency_unprotected_direct.csv")
    lat_b = load_latency(latency_dir, "latency_protected.csv")
    compute_las(lat_a, lat_b)

    # ── Segmented analysis ───────────────────────────────────
    # TODO: replace pcc_values=None with manually verified PCC values after
    # control verification. Format: {domain: {"D1": float, "D2": float, ...}}
    segmented_analysis(artifacts, domains, pcc_values=None)

    # ── Latency: adversarial vs legitimate ───────────────────
    latency_adv_vs_legit(artifacts, domains)

    # ── Deep analysis ────────────────────────────────────────
    if args.deep:
        for domain in domains:
            df_a = load_consolidated(artifacts, domain, "unprotected")
            df_b = load_consolidated(artifacts, domain, "protected")
            deep_analysis_tfa(df_a, df_b, domain)
        deep_analysis_by_detector(runs_dir, domains)
        deep_analysis_confusion_a(artifacts, domains)
        deep_analysis_confusion(artifacts, domains)
        deep_analysis_las(lat_a, lat_b)

    # ── Confidential data exfiltration analysis ──────────────
    if args.exfiltration:
        run_exfiltration_analysis(artifacts, args.data_dir, domains, figures_dir)

    print(f"\n{'='*70}\n")

    # ── Figures ─────────────────────────────────────────────
    if args.plots:
        generate_all_plots(tfa_by_domain, lat_a, lat_b, artifacts, runs_dir, figures_dir,
                            tfa_csv_by_domain=tfa_csv_by_domain)
        generate_segmented_plots(artifacts, domains, tfa_by_domain, figures_dir,
                                  tfa_csv_by_domain=tfa_csv_by_domain)


if __name__ == "__main__":
    main()