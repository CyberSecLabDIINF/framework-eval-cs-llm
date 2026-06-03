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
import json
from collections import defaultdict
from pathlib import Path

import pandas as pd
from scipy.stats import fisher_exact, mannwhitneyu, spearmanr


# ─────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────

PRIMARY_DETECTOR = {
    "encoding.InjectBase64": "encoding.DecodeMatch",
    "encoding.InjectHex":    "encoding.DecodeMatch",
}

SUITE_TO_SUBDIM = {
    "LLM01": "D1",
    "LLM02": "D2",
    "LLM07": "D3",
    "LLM08": "D4",
}

VECTOR_MAP = {
    "LLM01": "D1 — Input protection",
    "LLM02": "D2 — RAG context control",
    "LLM07": "D3 — Output management",
    "LLM08": "D4 — Monitoring & traceability",
}

PROBE_TO_SUITE = {
    "promptinject.HijackKillHumans":                   "LLM01",
    "promptinject.HijackHateHumans":                   "LLM01",
    "promptinject.HijackLongPrompt":                   "LLM01",
    "encoding.InjectBase64":                           "LLM01",
    "encoding.InjectHex":                              "LLM01",
    "latentinjection.LatentInjectionReport":           "LLM02",
    "latentinjection.LatentInjectionFactSnippetLegal": "LLM02",
    "latentinjection.LatentInjectionResume":           "LLM02",
    "leakreplay.GuardianComplete":                     "LLM07",
    "goodside.Tag":                                    "LLM07",
    "latentinjection.LatentWhois":                     "LLM08",
}

PROBE_SHORT = {
    "promptinject.HijackKillHumans":                   "HijackKill",
    "promptinject.HijackHateHumans":                   "HijackHate",
    "promptinject.HijackLongPrompt":                   "HijackLong",
    "encoding.InjectBase64":                           "Base64",
    "encoding.InjectHex":                              "Hex",
    "latentinjection.LatentInjectionReport":           "LatentReport",
    "latentinjection.LatentInjectionFactSnippetLegal": "LatentFact",
    "latentinjection.LatentInjectionResume":           "LatentResume",
    "leakreplay.GuardianComplete":                     "Guardian",
    "goodside.Tag":                                    "Tag",
    "latentinjection.LatentWhois":                     "LatentWhois",
}

SUITE_COLORS = {
    "LLM01": "#4C72B0",
    "LLM02": "#DD8452",
    "LLM07": "#55A868",
    "LLM08": "#C44E52",
}

SCENARIO_COLORS = {"A": "#4C72B0", "B": "#DD8452"}


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


# ─────────────────────────────────────────────
# TFA — print
# ─────────────────────────────────────────────

def print_tfa(tfa_a: dict, tfa_b: dict, domain: str):
    """Print a formatted TFA report for one domain, comparing Scenario A and B.

    Outputs global totals, per-suite table with Fisher exact p-values, and a
    per-probe detail table.  When ``tfa_b`` is empty or None, Scenario B
    columns are omitted.

    Args:
        tfa_a: TFA dict for Scenario A as returned by :func:`load_tfa_from_jsonl`.
        tfa_b: TFA dict for Scenario B, or an empty dict when unavailable.
        domain: Domain label used in the section header.
    """
    print(f"\n{'='*70}")
    print(f"  TFA — {domain.upper()}")
    print(f"{'='*70}")

    if not tfa_a:
        print("  [WARN] No data for Scenario A.")
        return

    g_a = tfa_a["global"]
    g_b = tfa_b.get("global") if tfa_b else None

    print(f"\n  GLOBAL")
    print(f"  {'':35s} {'Scenario A':>12} {'Scenario B':>12}")
    print(f"  {'Total attempts':35s} {g_a['total']:>12}", end="")
    print(f" {g_b['total']:>12}" if g_b else "")
    print(f"  {'TP (resisted)':35s} {g_a['passed']:>12}", end="")
    print(f" {g_b['passed']:>12}" if g_b else "")
    print(f"  {'FN (attack succeeded)':35s} {g_a['total']-g_a['passed']:>12}", end="")
    if g_b:
        print(f" {g_b['total']-g_b['passed']:>12}")
    else:
        print()
    print(f"  {'TFA':35s} {g_a['TFA']:>12.4f}", end="")
    if g_b:
        delta = round(g_b["TFA"] - g_a["TFA"], 4)
        print(f" {g_b['TFA']:>12.4f}  ΔTFA={delta:+.4f}")
    else:
        print()

    if g_b:
        fn_a = g_a["total"] - g_a["passed"]
        fn_b = g_b["total"] - g_b["passed"]
        _, p_val = fisher_exact(
            [[g_a["passed"], fn_a], [g_b["passed"], fn_b]], alternative="less"
        )
        sig = "✅ significant (α=0.05)" if p_val < 0.05 else "⚠️  not significant"
        print(f"\n  Fisher exact (global): p={p_val:.6f}  {sig}")

    print(f"\n  PER OWASP SUITE")
    print(f"  {'Suite':6s} {'Description':28s} {'TFA_A':>8} {'TFA_B':>8} {'ΔTFA':>8} {'p-value':>10}")
    print(f"  {'-'*68}")
    for suite, desc in VECTOR_MAP.items():
        va = tfa_a["per_suite"].get(suite)
        vb = tfa_b["per_suite"].get(suite) if tfa_b else None
        if va is None:
            continue
        tfa_a_str = f"{va['TFA']:.4f}" if va["TFA"] is not None else "N/A"
        tfa_b_str = f"{vb['TFA']:.4f}" if (vb and vb["TFA"] is not None) else "N/A"
        delta_str = p_str = ""
        if vb and va["TFA"] is not None and vb["TFA"] is not None:
            fn_a = va["total"] - va["passed"]
            fn_b = vb["total"] - vb["passed"]
            _, p = fisher_exact([[va["passed"], fn_a], [vb["passed"], fn_b]], alternative="less")
            delta_str = f"{vb['TFA'] - va['TFA']:+.4f}"
            p_str = f"{p:.6f}"
        print(f"  {suite:6s} {desc[:28]:28s} {tfa_a_str:>8} {tfa_b_str:>8} {delta_str:>8} {p_str:>10}")

    print(f"\n  PER PROBE DETAIL")
    print(f"  {'Probe':45s} {'Suite':6s} {'TFA_A':>8} {'TFA_B':>8} {'ΔTFA':>8}")
    print(f"  {'-'*78}")
    for probe in sorted(tfa_a["per_probe"]):
        va   = tfa_a["per_probe"][probe]
        vb   = tfa_b["per_probe"].get(probe) if tfa_b else None
        suite = va.get("suite", "?")
        tfa_a_str = f"{va['TFA']:.4f}" if va["TFA"] is not None else "N/A"
        tfa_b_str = f"{vb['TFA']:.4f}" if (vb and vb["TFA"] is not None) else "N/A"
        delta_str = ""
        if vb and va["TFA"] is not None and vb["TFA"] is not None:
            delta_str = f"{vb['TFA'] - va['TFA']:+.4f}"
        print(f"  {probe:45s} {suite:6s} {tfa_a_str:>8} {tfa_b_str:>8} {delta_str:>8}")


# ─────────────────────────────────────────────
# LAS — compute and print
# ─────────────────────────────────────────────

def compute_las(lat_a: pd.DataFrame, lat_b: pd.DataFrame):
    """Print the Latency Added by Shield (LAS) summary comparing Scenario A and B.

    Computes median latency per scenario, the Δmedian (LAS), a Mann-Whitney U
    test, and a per-domain breakdown.

    Args:
        lat_a: Latency DataFrame for Scenario A (unprotected).
        lat_b: Latency DataFrame for Scenario B (protected / LLM Guard).
    """
    if lat_a.empty or lat_b.empty:
        print("  [WARN] Insufficient latency data.")
        return

    a_vals = lat_a["latency_ms"].values
    b_vals = lat_b["latency_ms"].values
    med_a  = pd.Series(a_vals).median()
    med_b  = pd.Series(b_vals).median()
    std_a  = pd.Series(a_vals).std()
    std_b  = pd.Series(b_vals).std()
    las    = med_b - med_a

    stat, p_val = mannwhitneyu(a_vals, b_vals, alternative="less")
    sig = "✅ significant (α=0.05)" if p_val < 0.05 else "⚠️  not significant"

    print(f"\n{'='*70}")
    print(f"  LAS — Aggregate Security Latency")
    print(f"{'='*70}")
    print(f"\n  {'':35s} {'Scenario A':>12} {'Scenario B':>12}")
    print(f"  {'n requests (/generate)':35s} {len(a_vals):>12} {len(b_vals):>12}")
    print(f"  {'Median (ms)':35s} {med_a:>12.3f} {med_b:>12.3f}")
    print(f"  {'Std deviation (ms)':35s} {std_a:>12.3f} {std_b:>12.3f}")
    print(f"\n  LAS (Δmedian B - A) = {las:+.3f} ms")
    print(f"  Mann-Whitney U = {stat:.1f}  p = {p_val:.6f}  {sig}")

    domains = set(lat_a["domain"].dropna().unique()) | set(lat_b["domain"].dropna().unique())
    if domains:
        print(f"\n  BY DOMAIN (exploratory)")
        print(f"  {'Domain':35s} {'Med_A':>8} {'Med_B':>8} {'Δ':>8}")
        print(f"  {'-'*60}")
        for domain in sorted(domains):
            sub_a = lat_a[lat_a["domain"] == domain]["latency_ms"]
            sub_b = lat_b[lat_b["domain"] == domain]["latency_ms"]
            if sub_a.empty or sub_b.empty:
                continue
            delta = sub_b.median() - sub_a.median()
            print(f"  {domain:35s} {sub_a.median():>8.3f} {sub_b.median():>8.3f} {delta:>+8.3f}")


# ─────────────────────────────────────────────
# Deep analysis from consolidated CSV
# ─────────────────────────────────────────────

def deep_analysis_tfa(df_a: pd.DataFrame, df_b: pd.DataFrame, domain: str):
    """
    Deep TFA analysis from consolidated CSV.
    Covers: by subdimension, by probe, confidential exposure,
    and Scenario A vs B comparison where available.
    """
    if df_a.empty:
        print(f"  [WARN] No consolidated data for {domain} Scenario A.")
        return

    print(f"\n{'='*70}")
    print(f"  DEEP TFA ANALYSIS — {domain.upper()}")
    print(f"{'='*70}")

    # ── Confidential exposure (Scenario A) ──────────────────
    total_adv   = len(df_a)
    conf_exposed = int(df_a["response_has_confidential"].sum())
    conf_rate    = conf_exposed / total_adv if total_adv > 0 else 0

    print(f"\n  CONFIDENTIAL EXPOSURE (Scenario A — no protection)")
    print(f"  {'Total adversarial attempts':40s} {total_adv:>8}")
    print(f"  {'Responses with confidential data':40s} {conf_exposed:>8}")
    print(f"  {'Exposure rate':40s} {conf_rate:>8.4f}  ({conf_rate*100:.2f}%)")

    # By subdimension
    print(f"\n  {'Subdimension':12s} {'Attempts':>10} {'Exposed':>10} {'Rate':>8}")
    print(f"  {'-'*44}")
    for subdim in sorted(df_a["subdimension"].dropna().unique()):
        sub = df_a[df_a["subdimension"] == subdim]
        exp = int(sub["response_has_confidential"].sum())
        rate = exp / len(sub) if len(sub) > 0 else 0
        print(f"  {subdim:12s} {len(sub):>10} {exp:>10} {rate:>8.4f}")

    # ── was_blocked analysis ─────────────────────────────────
    print(f"\n  BLOCKING ANALYSIS")
    print(f"  {'':40s} {'Scen A':>8} {'Scen B':>8}")

    blocked_a = int(df_a["was_blocked"].sum()) if not df_a.empty else 0
    blocked_b = int(df_b["was_blocked"].sum()) if not df_b.empty else 0
    print(f"  {'Total blocked by layer':40s} {blocked_a:>8} {blocked_b:>8}")

    if not df_b.empty:
        # False negatives of LLM Guard: not blocked but should have been
        fn_guard = df_b[(df_b["was_blocked"] == 0) & (df_b["should_block"] == 1)]
        print(f"  {'FN of LLM Guard (missed attacks)':40s} {'':>8} {len(fn_guard):>8}")
        # False positives: blocked but should not have been
        fp_guard = df_b[(df_b["was_blocked"] == 1) & (df_b["should_block"] == 0)]
        print(f"  {'FP of LLM Guard (false alarms)':40s} {'':>8} {len(fp_guard):>8}")

    # ── Latency from consolidated CSV (by probe) ─────────────
    print(f"\n  LATENCY BY PROBE — Scenario A (ms)")
    print(f"  {'Probe':45s} {'n':>6} {'Median':>8} {'Std':>8} {'Min':>8} {'Max':>8}")
    print(f"  {'-'*82}")
    if "latency_ms" in df_a.columns:
        df_a["latency_ms"] = pd.to_numeric(df_a["latency_ms"], errors="coerce")
        for probe in sorted(df_a["probe"].dropna().unique()):
            sub = df_a[df_a["probe"] == probe]["latency_ms"].dropna()
            if sub.empty:
                continue
            print(f"  {probe:45s} {len(sub):>6} {sub.median():>8.1f} "
                  f"{sub.std():>8.1f} {sub.min():>8.1f} {sub.max():>8.1f}")

    # ── Latency by subdimension ──────────────────────────────
    print(f"\n  LATENCY BY SUBDIMENSION — Scenario A (ms)")
    print(f"  {'Subdim':12s} {'n':>6} {'Median':>8} {'Std':>8}")
    print(f"  {'-'*38}")
    if "latency_ms" in df_a.columns:
        for subdim in sorted(df_a["subdimension"].dropna().unique()):
            sub = df_a[df_a["subdimension"] == subdim]["latency_ms"].dropna()
            if sub.empty:
                continue
            print(f"  {subdim:12s} {len(sub):>6} {sub.median():>8.1f} {sub.std():>8.1f}")

    # ── Scanner analysis (Scenario B only) ──────────────────
    if not df_b.empty and "scanner_triggered" in df_b.columns:
        print(f"\n  SCANNER ACTIVITY — Scenario B")
        scanner_counts = df_b["scanner_triggered"].value_counts()
        print(f"  {'Scanner':40s} {'Triggers':>10}")
        print(f"  {'-'*52}")
        for scanner, count in scanner_counts.items():
            label = scanner if scanner else "(none)"
            print(f"  {label:40s} {count:>10}")

    # ── Confidential exposure by probe ───────────────────────
    if "response_has_confidential" in df_a.columns:
        print(f"\n  CONFIDENTIAL EXPOSURE BY PROBE — Scenario A")
        print(f"  {'Probe':45s} {'Attempts':>10} {'Exposed':>10} {'Rate':>8}")
        print(f"  {'-'*76}")
        for probe in sorted(df_a["probe"].dropna().unique()):
            sub  = df_a[df_a["probe"] == probe]
            exp  = int(sub["response_has_confidential"].sum())
            rate = exp / len(sub) if len(sub) > 0 else 0
            flag = " ⚠️" if rate > 0.1 else ""
            print(f"  {probe:45s} {len(sub):>10} {exp:>10} {rate:>8.4f}{flag}")

def deep_analysis_by_detector(runs_dir: Path, domains: list):
    """
    TFA breakdown by probe × detector for Scenario A.
    Highlights difference between primary and secondary detectors
    where multiple detectors exist for the same probe.
    """
    print(f"\n{'='*70}")
    print(f"  DETECTOR-LEVEL ANALYSIS — Scenario A")
    print(f"{'='*70}")

    for domain in domains:
        run_a = find_run_dir(runs_dir, domain, "unprotected")
        if not run_a:
            print(f"  [WARN] No unprotected run found for {domain}")
            continue

        print(f"\n  DOMAIN: {domain.upper()}")
        print(f"  {'-'*65}")

        # Aggregate passed/total per (probe, detector)
        results: dict[tuple, dict] = defaultdict(lambda: {"passed": 0, "total": 0})

        for probe, detector, passed, total in _load_jsonl_eval_entries(run_a / "garak"):
            results[(probe, detector)]["passed"] += passed
            results[(probe, detector)]["total"]  += total

        # Group by probe to detect multi-detector probes
        by_probe: dict[str, list] = defaultdict(list)
        for (probe, detector), v in results.items():
            tfa = v["passed"] / v["total"] if v["total"] > 0 else None
            by_probe[probe].append({
                "detector": detector,
                "passed":   v["passed"],
                "total":    v["total"],
                "TFA":      tfa,
                "primary":  PRIMARY_DETECTOR.get(probe) == detector
                            if probe in PRIMARY_DETECTOR else True,
            })

        print(f"\n  {'Probe':45s} {'Detector':30s} {'Primary':>8} "
              f"{'Passed':>8} {'Total':>8} {'TFA':>8}")
        print(f"  {'-'*106}")

        for probe in sorted(by_probe.keys()):
            detectors = sorted(by_probe[probe], key=lambda x: x["detector"])
            suite = PROBE_TO_SUITE.get(probe, "?")
            for i, d in enumerate(detectors):
                probe_label = probe if i == 0 else ""
                primary_str = "✅ yes" if d["primary"] else "no"
                tfa_str     = f"{d['TFA']:.4f}" if d["TFA"] is not None else "N/A"
                # Flag large gap between detectors
                flag = ""
                if len(detectors) > 1 and not d["primary"] and i > 0:
                    tfa_primary = next(
                        (x["TFA"] for x in detectors if x["primary"]), None
                    )
                    if tfa_primary is not None and d["TFA"] is not None:
                        gap = abs(d["TFA"] - tfa_primary)
                        flag = f"  Δ={gap:.4f}" if gap > 0.001 else ""
                print(f"  {probe_label:45s} {d['detector']:30s} {primary_str:>8} "
                      f"{d['passed']:>8} {d['total']:>8} {tfa_str:>8}{flag}")

        # Summary: probes with multiple detectors
        multi = {p: ds for p, ds in by_probe.items() if len(ds) > 1}
        if multi:
            print(f"\n  MULTI-DETECTOR PROBES — Gap analysis (primary vs secondary)")
            print(f"  {'Probe':45s} {'Primary TFA':>12} {'Secondary TFA':>14} {'Gap':>8}")
            print(f"  {'-'*82}")
            for probe, detectors in sorted(multi.items()):
                primary   = next((d for d in detectors if d["primary"]), None)
                secondary = next((d for d in detectors if not d["primary"]), None)
                if primary and secondary:
                    gap = secondary["TFA"] - primary["TFA"]
                    print(f"  {probe:45s} {primary['TFA']:>12.4f} "
                          f"{secondary['TFA']:>14.4f} {gap:>+8.4f}")
                    print(f"  {'→ Using primary (stricter) for TFA calculation':45s}")

def deep_analysis_confusion_a(artifacts_dir: Path, domains: list):
    """
    Prints partial confusion matrix for Scenario A in terminal.
    Mirrors what plot_confusion_matrix_scenario_a shows visually.
    """
    print(f"\n{'='*70}")
    print(f"  PARTIAL CONFUSION MATRIX — Scenario A (no active classifier)")
    print(f"  FP does not exist: no blocking mechanism active by design.")
    print(f"{'='*70}")

    for domain in domains:
        df_a = load_consolidated(artifacts_dir, domain, "unprotected")
        if df_a.empty:
            print(f"  [WARN] No data for {domain}")
            continue

        df_legit = _load_consolidated_legit(artifacts_dir, domain, "unprotected")

        df_adv = df_a[df_a["garak_passed"].notna()].copy()
        df_adv["garak_passed"] = df_adv["garak_passed"].astype(int)

        TP = int((df_adv["garak_passed"] == 1).sum())
        FN = int((df_adv["garak_passed"] == 0).sum())
        TN = int((df_legit["response_has_confidential"] == 0).sum())
        legit_leaked = int((df_legit["response_has_confidential"] == 1).sum())

        total_adv   = TP + FN
        total_legit = TN + legit_leaked

        recall   = TP / total_adv   if total_adv   > 0 else 0
        fnr      = FN / total_adv   if total_adv   > 0 else 0
        tn_rate  = TN / total_legit if total_legit > 0 else 0
        leak_rate = legit_leaked / total_legit if total_legit > 0 else 0

        print(f"\n  DOMAIN: {domain.upper()}")
        print(f"  {'-'*65}")
        print(f"\n  {'':25s} {'Resisted':>12} {'Failed':>12}")
        print(f"  {'Actual ATTACK':25s} {'TP = '+str(TP):>12} {'FN = '+str(FN):>12}")
        print(f"  {'Actual LEGIT':25s} {'TN = '+str(TN):>12} {'FP = N/A':>12}")

        print(f"\n  ADVERSARIAL — Model intrinsic resistance")
        print(f"  {'-'*50}")
        print(f"  {'Total adversarial':35s} {total_adv:>8}")
        print(f"  {'TP (resisted)':35s} {TP:>8}  ({recall*100:.2f}%)")
        print(f"  {'FN (attack succeeded)':35s} {FN:>8}  ({fnr*100:.2f}%)")
        print(f"  {'Recall = TFA_A':35s} {recall:>8.4f}")
        print(f"  {'FNR':35s} {fnr:>8.4f}")

        print(f"\n  LEGITIMATE — Model behavior on clean prompts")
        print(f"  {'-'*50}")
        print(f"  {'Total legitimate':35s} {total_legit:>8}")
        print(f"  {'TN (no leakage)':35s} {TN:>8}  ({tn_rate*100:.2f}%)")
        print(f"  {'Leaked confidential data':35s} {legit_leaked:>8}  ({leak_rate*100:.2f}%)")
        print(f"  {'FP':35s} {'N/A':>8}  (no classifier active)")

        # By subdimension
        print(f"\n  BY SUBDIMENSION")
        print(f"  {'Subdim':6s} {'TP':>8} {'FN':>8} {'Recall':>8} {'FNR':>8}")
        print(f"  {'-'*44}")
        for subdim in sorted(df_adv["subdimension"].dropna().unique()):
            sub = df_adv[df_adv["subdimension"] == subdim]
            tp  = int((sub["garak_passed"] == 1).sum())
            fn  = int((sub["garak_passed"] == 0).sum())
            rec = tp / (tp + fn) if (tp + fn) > 0 else 0
            fnr_s = fn / (tp + fn) if (tp + fn) > 0 else 0
            print(f"  {subdim:6s} {tp:>8} {fn:>8} {rec:>8.4f} {fnr_s:>8.4f}")

def deep_analysis_confusion(artifacts_dir: Path, domains: list):
    """
    Confusion matrix and derived metrics for LLM Guard (Scenario B only).
    For Scenario A, reports model intrinsic resistance using garak_passed.
    
    Confusion matrix (Scenario B):
      TP: should_block=1, was_blocked=1  (attack correctly blocked)
      FN: should_block=1, was_blocked=0  (attack missed by LLM Guard)
      FP: should_block=0, was_blocked=1  (legitimate blocked — false alarm)
      TN: should_block=0, was_blocked=0  (legitimate correctly passed)
    """
    print(f"\n{'='*70}")
    print(f"  CONFUSION MATRIX ANALYSIS — LLM Guard (Scenario B)")
    print(f"{'='*70}")

    for domain in domains:
        df_b = load_consolidated(artifacts_dir, domain, "protected")
        df_a = load_consolidated(artifacts_dir, domain, "unprotected")

        print(f"\n  DOMAIN: {domain.upper()}")
        print(f"  {'-'*65}")

        # ── Scenario A: intrinsic model resistance ───────────
        if not df_a.empty and "garak_passed" in df_a.columns:
            df_a_valid = df_a[df_a["garak_passed"].notna()].copy()
            df_a_valid["garak_passed"] = df_a_valid["garak_passed"].astype(int)
            total_a  = len(df_a_valid)
            resist_a = int((df_a_valid["garak_passed"] == 1).sum())
            fail_a   = total_a - resist_a
            print(f"\n  Scenario A — Intrinsic model resistance (no classifier)")
            print(f"  {'Total adversarial attempts':40s} {total_a:>8}")
            print(f"  {'Resisted by model (garak_passed=1)':40s} {resist_a:>8}  ({resist_a/total_a*100:.2f}%)")
            print(f"  {'Succeeded against model (garak_passed=0)':40s} {fail_a:>8}  ({fail_a/total_a*100:.2f}%)")
            print(f"  Note: No FP/TN concept applies — no active classifier.")

        # ── Scenario B: full confusion matrix ───────────────
        if df_b.empty:
            print(f"\n  Scenario B — Not available yet.")
            continue

        # Split adversarial and legitimate
        adv  = df_b[df_b["prompt_type"] == "adversarial"].copy()
        legit = df_b[df_b["prompt_type"] == "legitimate"].copy()

        counts = _confusion_counts(adv, legit)
        TP, FN, FP, TN = counts["TP"], counts["FN"], counts["FP"], counts["TN"]

        total     = TP + FN + FP + TN
        precision = TP / (TP + FP) if (TP + FP) > 0 else None
        recall    = TP / (TP + FN) if (TP + FN) > 0 else None  # = TFA_B
        f1        = (2 * precision * recall / (precision + recall)
                     if precision and recall else None)
        specificity = TN / (TN + FP) if (TN + FP) > 0 else None
        fpr         = FP / (FP + TN) if (FP + TN) > 0 else None
        fnr         = FN / (FN + TP) if (FN + TP) > 0 else None
        accuracy    = (TP + TN) / total if total > 0 else None

        print(f"\n  Scenario B — LLM Guard Confusion Matrix")
        print(f"\n  {'':25s} {'Predicted BLOCK':>16} {'Predicted PASS':>16}")
        print(f"  {'Actual ATTACK':25s} {'TP = ' + str(TP):>16} {'FN = ' + str(FN):>16}")
        print(f"  {'Actual LEGITIMATE':25s} {'FP = ' + str(FP):>16} {'TN = ' + str(TN):>16}")

        print(f"\n  DERIVED METRICS")
        print(f"  {'-'*50}")

        def fmt(v):
            return f"{v:.4f}  ({v*100:.2f}%)" if v is not None else "N/A"

        print(f"  {'Accuracy  (TP+TN)/total':35s} {fmt(accuracy)}")
        print(f"  {'Precision TP/(TP+FP)':35s} {fmt(precision)}")
        print(f"  {'Recall    TP/(TP+FN)  [= TFA_B]':35s} {fmt(recall)}")
        print(f"  {'F1 score  2·P·R/(P+R)':35s} {fmt(f1)}")
        print(f"  {'Specificity TN/(TN+FP)':35s} {fmt(specificity)}")
        print(f"  {'FPR  FP/(FP+TN)':35s} {fmt(fpr)}")
        print(f"  {'FNR  FN/(FN+TP)':35s} {fmt(fnr)}")

        # ── By subdimension ──────────────────────────────────
        print(f"\n  BY SUBDIMENSION — Scenario B")
        print(f"  {'Subdim':6s} {'TP':>6} {'FN':>6} {'FP':>6} {'TN':>6} "
              f"{'Recall':>8} {'Prec':>8} {'F1':>8}")
        print(f"  {'-'*60}")

        for subdim in sorted(df_b["subdimension"].dropna().unique()):
            sub_adv   = adv[adv["subdimension"] == subdim]
            sub_legit = legit[legit["subdimension"] == subdim]
            sc = _confusion_counts(sub_adv, sub_legit)
            tp, fn, fp, tn = sc["TP"], sc["FN"], sc["FP"], sc["TN"]
            rec  = tp / (tp + fn) if (tp + fn) > 0 else None
            prec = tp / (tp + fp) if (tp + fp) > 0 else None
            f1s  = (2 * prec * rec / (prec + rec)
                    if prec and rec else None)
            rec_s  = f"{rec:.4f}"  if rec  is not None else "N/A"
            prec_s = f"{prec:.4f}" if prec is not None else "N/A"
            f1_s   = f"{f1s:.4f}"  if f1s  is not None else "N/A"
            print(f"  {subdim:6s} {tp:>6} {fn:>6} {fp:>6} {tn:>6} "
                  f"{rec_s:>8} {prec_s:>8} {f1_s:>8}")

def deep_analysis_las(lat_a: pd.DataFrame, lat_b: pd.DataFrame):
    """
    Deep LAS analysis from latency CSVs.
    Covers: distribution stats, by suite, percentiles, outliers.
    """
    if lat_a.empty:
        print("  [WARN] No Scenario A latency data available.")
        return

    print(f"\n{'='*70}")
    print(f"  DEEP LAS ANALYSIS")
    print(f"{'='*70}")

    # ── Full distribution stats ──────────────────────────────
    print(f"\n  DISTRIBUTION STATISTICS (ms)")
    print(f"  {'Metric':20s} {'Scenario A':>12} {'Scenario B':>12}")
    print(f"  {'-'*46}")

    stats = ["min", "25%", "50%", "75%", "max", "mean", "std"]
    desc_a = lat_a["latency_ms"].describe()
    desc_b = lat_b["latency_ms"].describe() if not lat_b.empty else None

    for stat in stats:
        val_a = desc_a.get(stat, float("nan"))
        val_b = desc_b.get(stat, float("nan")) if desc_b is not None else float("nan")
        b_str = f"{val_b:>12.1f}" if not pd.isna(val_b) else f"{'N/A':>12}"
        print(f"  {stat:20s} {val_a:>12.1f} {b_str}")

    # ── Percentile analysis ──────────────────────────────────
    print(f"\n  PERCENTILE ANALYSIS (ms)")
    print(f"  {'Percentile':20s} {'Scenario A':>12} {'Scenario B':>12}")
    print(f"  {'-'*46}")
    for p in [10, 25, 50, 75, 90, 95, 99]:
        val_a = lat_a["latency_ms"].quantile(p / 100)
        val_b = lat_b["latency_ms"].quantile(p / 100) if not lat_b.empty else None
        b_str = f"{val_b:>12.1f}" if val_b is not None else f"{'N/A':>12}"
        print(f"  {f'p{p}':20s} {val_a:>12.1f} {b_str}")

    # ── By suite ────────────────────────────────────────────
    lat_a = lat_a.copy()
    lat_a["suite"] = lat_a["suite_probe"].apply(_extract_suite)

    print(f"\n  MEDIAN LATENCY BY SUITE — Scenario A (ms)")
    print(f"  {'Suite':8s} {'Description':28s} {'n':>6} {'Median':>8} {'Std':>8} {'p95':>8}")
    print(f"  {'-'*64}")
    for suite, desc in VECTOR_MAP.items():
        sub = lat_a[lat_a["suite"] == suite]["latency_ms"]
        if sub.empty:
            continue
        print(f"  {suite:8s} {desc[:28]:28s} {len(sub):>6} "
              f"{sub.median():>8.1f} {sub.std():>8.1f} {sub.quantile(0.95):>8.1f}")

    # ── Overhead comparison by suite (A vs B) ───────────────
    if not lat_b.empty:
        lat_b = lat_b.copy()
        lat_b["suite"] = lat_b["suite_probe"].apply(_extract_suite)
        print(f"\n  LAS OVERHEAD BY SUITE (Δmedian B - A, ms)")
        print(f"  {'Suite':8s} {'Med_A':>8} {'Med_B':>8} {'Δ':>8} {'Δ%':>8}")
        print(f"  {'-'*40}")
        for suite in VECTOR_MAP:
            sub_a = lat_a[lat_a["suite"] == suite]["latency_ms"]
            sub_b = lat_b[lat_b["suite"] == suite]["latency_ms"]
            if sub_a.empty or sub_b.empty:
                continue
            delta = sub_b.median() - sub_a.median()
            delta_pct = (delta / sub_a.median()) * 100 if sub_a.median() > 0 else 0
            print(f"  {suite:8s} {sub_a.median():>8.1f} {sub_b.median():>8.1f} "
                  f"{delta:>+8.1f} {delta_pct:>+7.1f}%")

    # ── Outlier detection (> p99) ────────────────────────────
    p99_a = lat_a["latency_ms"].quantile(0.99)
    outliers_a = lat_a[lat_a["latency_ms"] > p99_a]
    print(f"\n  OUTLIERS (> p99 = {p99_a:.1f} ms) — Scenario A: {len(outliers_a)} requests")
    if not lat_b.empty:
        p99_b = lat_b["latency_ms"].quantile(0.99)
        outliers_b = lat_b[lat_b["latency_ms"] > p99_b]
        print(f"  OUTLIERS (> p99 = {p99_b:.1f} ms) — Scenario B: {len(outliers_b)} requests")


# ─────────────────────────────────────────────
# Segmented statistical analysis
# ─────────────────────────────────────────────

def segmented_analysis(artifacts_dir: Path, domains: list, pcc_values: dict | None = None):
    """Segmented statistical analysis across all domain × scenario × prompt_type combinations.

    Loads every ``consolidated_<domain>_<scenario>.csv`` file and runs five
    analytical blocks, printing formatted tables to stdout and exporting CSVs to
    ``artifacts/segmented/``:

    1. Segment overview — row counts, blocking rate, TFA_csv (mean garak_passed),
       and latency median for each (domain × scenario × prompt_type) cell.
    2. Adversarial TFA per probe and per OWASP suite, derived from the
       ``garak_passed`` column in the consolidated CSV (not from JSONL files).
    3. Adversarial distributions — ``garak_passed`` (0 / 1 / NaN) and
       ``was_blocked`` breakdown per segment; ``scanner_triggered`` breakdown for
       Scenario B.
    4. Legitimate FPR and latency distribution (median, IQR, p95, p99).
    5. Cross-scenario statistical tests — LAS (Mann-Whitney U), TFA (Fisher's
       exact), and, when ``pcc_values`` is supplied, Spearman ρ between PCC and
       aggregate TFA per (domain × subdimension) pair.

    Parameters
    ----------
    artifacts_dir : Path
        Root artifacts directory containing ``consolidated_*.csv`` files and the
        ``segmented/`` output sub-directory.
    domains : list
        Ordered list of corpus domain names (e.g. ``["regulatory_technical",
        "academic_institutional"]``).  Only domains present in ``artifacts_dir``
        produce non-empty output.
    pcc_values : dict or None, optional
        Manually verified PCC (Porcentaje de Controles Cumplidos) values, keyed
        as ``{domain: {subdimension: float}}``.  PCC cannot be derived from the
        CSV data — it requires out-of-band control verification.  Pass ``None``
        (default) to skip the Spearman block; a warning is printed in that case.

    Notes
    -----
    **LAS — Mann-Whitney U:**
        Preferred over a two-sample t-test because request latency distributions
        are right-skewed and heavy-tailed (Ollama inference times have a long
        tail from context-length variation and GPU scheduling jitter).  The
        Mann-Whitney U test makes no normality or equal-variance assumption.
        ``alternative="less"`` tests H₁: latency_A < latency_B, i.e. the shield
        adds overhead.

    **TFA — Fisher's exact test:**
        Preferred over the chi-square test because contingency-table cells (probe
        × scenario) often contain small expected frequencies when the number of
        Garak repetitions is limited (< 30 per probe per domain).  Fisher's exact
        test is exact regardless of sample size and is more conservative with
        sparse data.  ``alternative="less"`` tests H₁: TFA_A < TFA_B.

    **PCC–TFA — Spearman ρ:**
        Preferred over Pearson because PCC is an ordinal ratio with a bounded
        range (0–100) and no normality guarantee, while TFA is a bounded
        proportion; there is no prior reason to assume a linear relationship.
        Spearman measures rank-order association, which is the meaningful
        quantity for an exploratory comparison across only four subdimensions.

    Outputs
    -------
    - artifacts/segmented/01_segment_overview.csv : counts, blocking rate,
      mean garak_passed, latency median per (domain × scenario × prompt_type).
    - artifacts/segmented/02_tfa_per_probe.csv : TFA per probe per segment.
    - artifacts/segmented/03_tfa_per_suite.csv : TFA per OWASP suite per segment.
    - artifacts/segmented/04_garak_passed_dist.csv : gp=0/1/NaN counts.
    - artifacts/segmented/05_was_blocked_dist.csv : blocked/not-blocked counts.
    - artifacts/segmented/06_scanner_breakdown.csv : scanner_triggered value counts
      (Scenario B adversarial).
    - artifacts/segmented/07_fpr_legitimate.csv : FPR per domain × scenario.
    - artifacts/segmented/08_latency_legitimate.csv : legitimate latency stats.
    - artifacts/segmented/09_las_mannwhitney.csv : Mann-Whitney U results per domain.
    - artifacts/segmented/10_fisher_tfa_ab.csv : Fisher exact results per suite and
      per domain.
    - artifacts/segmented/11_spearman_pcc_tfa.csv : Spearman ρ results; written
      only when ``pcc_values`` is provided and has ≥ 3 (domain, subdimension) pairs.
    """
    SCENARIOS    = ["unprotected", "protected"]
    SCEN_LABEL   = {"unprotected": "A", "protected": "B"}
    PROMPT_TYPES = ["adversarial", "legitimate"]

    segmented_dir = artifacts_dir / "segmented"
    segmented_dir.mkdir(parents=True, exist_ok=True)

    # ── Load all CSVs into all_data[domain][scenario][prompt_type] ──────────
    all_data: dict = {}
    for domain in domains:
        all_data[domain] = {}
        for scenario in SCENARIOS:
            path = artifacts_dir / f"consolidated_{domain}_{scenario}.csv"
            if not path.exists():
                all_data[domain][scenario] = {pt: pd.DataFrame() for pt in PROMPT_TYPES}
                continue
            df_raw = pd.read_csv(path)
            for col in ("was_blocked", "should_block", "response_has_confidential"):
                if col in df_raw.columns:
                    df_raw[col] = pd.to_numeric(df_raw[col], errors="coerce").fillna(0).astype(int)
            for col in ("garak_passed", "latency_ms", "input_scanner_score", "output_scanner_score"):
                if col in df_raw.columns:
                    df_raw[col] = pd.to_numeric(df_raw[col], errors="coerce")
            if "suite" in df_raw.columns:
                df_raw["suite"] = df_raw["suite"].apply(_extract_suite)
            all_data[domain][scenario] = {
                pt: df_raw[df_raw["prompt_type"] == pt].copy()
                for pt in PROMPT_TYPES
            }

    print(f"\n{'='*70}")
    print(f"  SEGMENTED ANALYSIS — domain × scenario × prompt_type")
    print(f"{'='*70}")

    # ── 1. Segment overview: counts and proportions ──────────────────────────
    seg_rows = []
    for domain in domains:
        for scenario in SCENARIOS:
            for pt in PROMPT_TYPES:
                df = all_data[domain][scenario][pt]
                n  = len(df)
                row: dict = {
                    "domain": domain, "scenario": scenario,
                    "scenario_label": SCEN_LABEL[scenario], "prompt_type": pt,
                    "n_rows": n,
                }
                if n > 0:
                    if "was_blocked" in df.columns:
                        nb = int(df["was_blocked"].sum())
                        row["n_blocked"]   = nb
                        row["pct_blocked"] = round(nb / n, 4)
                    if pt == "adversarial" and "garak_passed" in df.columns:
                        valid = df["garak_passed"].dropna()
                        if len(valid):
                            row["garak_passed_mean"] = round(float(valid.mean()), 4)
                            row["garak_passed_n"]    = len(valid)
                    if "latency_ms" in df.columns:
                        lat = df["latency_ms"].dropna()
                        if len(lat):
                            row["latency_median"] = round(float(lat.median()), 2)
                            row["latency_iqr"]    = round(float(lat.quantile(0.75) - lat.quantile(0.25)), 2)
                            row["latency_p95"]    = round(float(lat.quantile(0.95)), 2)
                seg_rows.append(row)

    seg_df = pd.DataFrame(seg_rows)
    hdr = f"  {'Domain':30s} {'Scen':5s} {'Type':12s} {'n':>7} {'%blocked':>9} {'TFA_csv':>9} {'lat_p50':>9}"
    print(f"\n  SEGMENT OVERVIEW")
    print(hdr)
    print(f"  {'-'*76}")
    for _, r in seg_df.iterrows():
        pct_b = (f"{r['pct_blocked']*100:.1f}%"
                 if pd.notna(r.get("pct_blocked")) else "N/A")
        gp    = (f"{r['garak_passed_mean']:.4f}"
                 if pd.notna(r.get("garak_passed_mean")) else "N/A")
        lat   = (f"{r['latency_median']:.1f}"
                 if pd.notna(r.get("latency_median")) else "N/A")
        print(f"  {r['domain']:30s} {r['scenario_label']:5s} {r['prompt_type']:12s} "
              f"{r['n_rows']:>7} {pct_b:>9} {gp:>9} {lat:>9}")
    seg_df.to_csv(segmented_dir / "01_segment_overview.csv", index=False)
    print(f"\n  [saved] {segmented_dir / '01_segment_overview.csv'}")

    # ── 2. Adversarial: TFA per probe ────────────────────────────────────────
    print(f"\n  {'='*68}")
    print(f"  ADVERSARIAL — TFA PER PROBE (garak_passed from consolidated CSV)")
    print(f"  {'='*68}")
    probe_rows = []
    for domain in domains:
        for scenario in SCENARIOS:
            df = all_data[domain][scenario]["adversarial"]
            if df.empty or "garak_passed" not in df.columns or "probe" not in df.columns:
                continue
            dv = df[df["garak_passed"].notna()].copy()
            dv["garak_passed"] = dv["garak_passed"].astype(int)
            for probe in sorted(dv["probe"].dropna().unique()):
                sub   = dv[dv["probe"] == probe]
                n     = len(sub)
                passed = int(sub["garak_passed"].sum())
                tfa   = round(passed / n, 4) if n else None
                suite = sub["suite"].iloc[0] if "suite" in sub.columns and len(sub) else PROBE_TO_SUITE.get(probe, "UNKNOWN")
                probe_rows.append({
                    "domain": domain, "scenario": scenario,
                    "scenario_label": SCEN_LABEL[scenario],
                    "probe": probe, "probe_short": PROBE_SHORT.get(probe, probe),
                    "suite": suite, "n": n, "passed": passed,
                    "failed": n - passed, "TFA": tfa,
                })
    if probe_rows:
        probe_df = pd.DataFrame(probe_rows)
        print(f"\n  {'Domain':30s} {'Scen':5s} {'Probe':20s} {'Suite':6s} {'n':>5} {'pass':>7} {'TFA':>8}")
        print(f"  {'-'*82}")
        for _, r in probe_df.iterrows():
            tfa_s = f"{r['TFA']:.4f}" if pd.notna(r["TFA"]) else "N/A"
            print(f"  {r['domain']:30s} {r['scenario_label']:5s} {r['probe_short']:20s} "
                  f"{r['suite']:6s} {r['n']:>5} {r['passed']:>7} {tfa_s:>8}")
        probe_df.to_csv(segmented_dir / "02_tfa_per_probe.csv", index=False)
        print(f"\n  [saved] {segmented_dir / '02_tfa_per_probe.csv'}")

    # ── 3. Adversarial: TFA per suite ────────────────────────────────────────
    print(f"\n  ADVERSARIAL — TFA PER SUITE")
    suite_rows = []
    for domain in domains:
        for scenario in SCENARIOS:
            df = all_data[domain][scenario]["adversarial"]
            if df.empty or "garak_passed" not in df.columns:
                continue
            dv = df[df["garak_passed"].notna()].copy()
            dv["garak_passed"] = dv["garak_passed"].astype(int)
            suite_col = "suite" if "suite" in dv.columns else None
            if suite_col is None:
                continue
            for suite in sorted(dv[suite_col].dropna().unique()):
                sub   = dv[dv[suite_col] == suite]
                n     = len(sub)
                passed = int(sub["garak_passed"].sum())
                tfa   = round(passed / n, 4) if n else None
                suite_rows.append({
                    "domain": domain, "scenario": scenario,
                    "scenario_label": SCEN_LABEL[scenario],
                    "suite": suite, "n": n, "passed": passed,
                    "failed": n - passed, "TFA": tfa,
                })
    if suite_rows:
        suite_df = pd.DataFrame(suite_rows)
        print(f"\n  {'Domain':30s} {'Scen':5s} {'Suite':6s} {'n':>5} {'pass':>7} {'TFA':>8}")
        print(f"  {'-'*62}")
        for _, r in suite_df.iterrows():
            tfa_s = f"{r['TFA']:.4f}" if pd.notna(r["TFA"]) else "N/A"
            print(f"  {r['domain']:30s} {r['scenario_label']:5s} {r['suite']:6s} "
                  f"{r['n']:>5} {r['passed']:>7} {tfa_s:>8}")
        suite_df.to_csv(segmented_dir / "03_tfa_per_suite.csv", index=False)
        print(f"\n  [saved] {segmented_dir / '03_tfa_per_suite.csv'}")

    # ── 4. garak_passed distribution ─────────────────────────────────────────
    print(f"\n  ADVERSARIAL — GARAK_PASSED DISTRIBUTION")
    gp_rows = []
    print(f"\n  {'Domain':30s} {'Scen':5s} {'total':>7} {'gp=0':>9} {'gp=1':>9} {'gp=NaN':>8}")
    print(f"  {'-'*72}")
    for domain in domains:
        for scenario in SCENARIOS:
            df = all_data[domain][scenario]["adversarial"]
            if df.empty or "garak_passed" not in df.columns:
                continue
            total = len(df)
            n_nan = int(df["garak_passed"].isna().sum())
            dv    = df["garak_passed"].dropna().astype(int)
            n0    = int((dv == 0).sum())
            n1    = int((dv == 1).sum())
            print(f"  {domain:30s} {SCEN_LABEL[scenario]:5s} {total:>7} "
                  f"{n0:>5}({n0/total*100:.0f}%) {n1:>5}({n1/total*100:.0f}%) {n_nan:>8}")
            gp_rows.append({"domain": domain, "scenario": scenario, "total": total,
                            "gp_0": n0, "gp_1": n1, "gp_nan": n_nan})
    if gp_rows:
        pd.DataFrame(gp_rows).to_csv(segmented_dir / "04_garak_passed_dist.csv", index=False)
        print(f"\n  [saved] {segmented_dir / '04_garak_passed_dist.csv'}")

    # ── 5. was_blocked distribution ──────────────────────────────────────────
    print(f"\n  ADVERSARIAL — WAS_BLOCKED DISTRIBUTION")
    wb_rows = []
    print(f"\n  {'Domain':30s} {'Scen':5s} {'total':>7} {'blocked':>9} {'not_blk':>9} {'%blk':>7}")
    print(f"  {'-'*68}")
    for domain in domains:
        for scenario in SCENARIOS:
            df = all_data[domain][scenario]["adversarial"]
            if df.empty or "was_blocked" not in df.columns:
                continue
            total = len(df)
            nb    = int(df["was_blocked"].sum())
            pct   = nb / total * 100 if total else 0
            print(f"  {domain:30s} {SCEN_LABEL[scenario]:5s} {total:>7} "
                  f"{nb:>9} {total-nb:>9} {pct:>7.2f}%")
            wb_rows.append({"domain": domain, "scenario": scenario, "total": total,
                            "blocked": nb, "not_blocked": total - nb,
                            "pct_blocked": round(pct / 100, 4)})
    if wb_rows:
        pd.DataFrame(wb_rows).to_csv(segmented_dir / "05_was_blocked_dist.csv", index=False)
        print(f"\n  [saved] {segmented_dir / '05_was_blocked_dist.csv'}")

    # ── 6. scanner_triggered breakdown (Scenario B, adversarial) ─────────────
    print(f"\n  ADVERSARIAL — SCANNER_TRIGGERED BREAKDOWN (Scenario B)")
    scanner_rows = []
    for domain in domains:
        df = all_data[domain]["protected"]["adversarial"]
        if df.empty or "scanner_triggered" not in df.columns:
            continue
        total = len(df)
        print(f"\n    {domain.upper()}")
        print(f"    {'Scanner':40s} {'count':>7} {'%':>8}")
        print(f"    {'-'*58}")
        vc = df["scanner_triggered"].fillna("(none)").value_counts()
        for scanner, cnt in vc.items():
            pct = cnt / total * 100
            print(f"    {str(scanner):40s} {cnt:>7} {pct:>8.2f}%")
            scanner_rows.append({"domain": domain, "scanner": scanner,
                                 "count": int(cnt), "pct": round(pct / 100, 4)})
    if scanner_rows:
        pd.DataFrame(scanner_rows).to_csv(segmented_dir / "06_scanner_breakdown.csv", index=False)
        print(f"\n  [saved] {segmented_dir / '06_scanner_breakdown.csv'}")

    # ── 7. Legitimate: FPR ───────────────────────────────────────────────────
    print(f"\n  {'='*68}")
    print(f"  LEGITIMATE — FALSE POSITIVE RATE (blocked / total)")
    print(f"  {'='*68}")
    fpr_rows = []
    print(f"\n  {'Domain':30s} {'Scen':5s} {'total':>7} {'blocked':>9} {'FPR':>9}")
    print(f"  {'-'*62}")
    for domain in domains:
        for scenario in SCENARIOS:
            df = all_data[domain][scenario]["legitimate"]
            if df.empty:
                continue
            n  = len(df)
            nb = int(df["was_blocked"].sum()) if "was_blocked" in df.columns else 0
            fpr = round(nb / n, 4) if n else 0.0
            print(f"  {domain:30s} {SCEN_LABEL[scenario]:5s} {n:>7} {nb:>9} {fpr:>9.4f}")
            fpr_rows.append({"domain": domain, "scenario": scenario,
                             "scenario_label": SCEN_LABEL[scenario],
                             "total_legit": n, "blocked_legit": nb, "FPR": fpr})
    if fpr_rows:
        pd.DataFrame(fpr_rows).to_csv(segmented_dir / "07_fpr_legitimate.csv", index=False)
        print(f"\n  [saved] {segmented_dir / '07_fpr_legitimate.csv'}")

    # ── 8. Legitimate: latency distribution ──────────────────────────────────
    print(f"\n  LEGITIMATE — LATENCY DISTRIBUTION (ms)")
    lat_legit_rows = []
    print(f"\n  {'Domain':30s} {'Scen':5s} {'n':>6} {'median':>8} {'IQR':>8} {'p95':>8} {'p99':>8}")
    print(f"  {'-'*72}")
    for domain in domains:
        for scenario in SCENARIOS:
            df = all_data[domain][scenario]["legitimate"]
            if df.empty or "latency_ms" not in df.columns:
                continue
            lat = df["latency_ms"].dropna()
            if lat.empty:
                continue
            med = lat.median()
            iqr = lat.quantile(0.75) - lat.quantile(0.25)
            p95 = lat.quantile(0.95)
            p99 = lat.quantile(0.99)
            print(f"  {domain:30s} {SCEN_LABEL[scenario]:5s} {len(lat):>6} "
                  f"{med:>8.1f} {iqr:>8.1f} {p95:>8.1f} {p99:>8.1f}")
            lat_legit_rows.append({"domain": domain, "scenario": scenario,
                                   "n": len(lat), "median_ms": round(float(med), 2),
                                   "iqr_ms": round(float(iqr), 2),
                                   "p95_ms": round(float(p95), 2),
                                   "p99_ms": round(float(p99), 2)})
    if lat_legit_rows:
        pd.DataFrame(lat_legit_rows).to_csv(segmented_dir / "08_latency_legitimate.csv", index=False)
        print(f"\n  [saved] {segmented_dir / '08_latency_legitimate.csv'}")

    # ── 9. LAS: Mann-Whitney U (A vs B per domain) ───────────────────────────
    print(f"\n  {'='*68}")
    print(f"  LAS — MANN-WHITNEY U  (H₁: latency_A < latency_B, α=0.05)")
    print(f"  Non-parametric; both prompt types pooled per scenario.")
    print(f"  {'='*68}")
    mw_rows = []
    print(f"\n  {'Domain':30s} {'n_A':>7} {'n_B':>7} {'med_A':>8} {'med_B':>8} "
          f"{'IQR_A':>8} {'IQR_B':>8} {'U':>10} {'p':>9} {'sig':>5}")
    print(f"  {'-'*105}")
    for domain in domains:
        lat_by_scen: dict[str, pd.Series] = {}
        for scenario in SCENARIOS:
            frames = [all_data[domain][scenario][pt] for pt in PROMPT_TYPES
                      if not all_data[domain][scenario][pt].empty]
            if not frames:
                lat_by_scen[scenario] = pd.Series(dtype=float)
                continue
            combined = pd.concat(frames, ignore_index=True)
            lat_by_scen[scenario] = (combined["latency_ms"].dropna()
                                     if "latency_ms" in combined.columns
                                     else pd.Series(dtype=float))
        a_lat = lat_by_scen.get("unprotected", pd.Series(dtype=float))
        b_lat = lat_by_scen.get("protected",   pd.Series(dtype=float))
        if a_lat.empty or b_lat.empty:
            print(f"  {domain:30s}  [insufficient latency data]")
            continue
        med_a = a_lat.median()
        med_b = b_lat.median()
        iqr_a = a_lat.quantile(0.75) - a_lat.quantile(0.25)
        iqr_b = b_lat.quantile(0.75) - b_lat.quantile(0.25)
        u_stat, p_val = mannwhitneyu(a_lat.values, b_lat.values, alternative="less")
        sig = "✅" if p_val < 0.05 else "—"
        print(f"  {domain:30s} {len(a_lat):>7} {len(b_lat):>7} {med_a:>8.1f} {med_b:>8.1f} "
              f"{iqr_a:>8.1f} {iqr_b:>8.1f} {u_stat:>10.1f} {p_val:>9.4f} {sig:>5}")
        mw_rows.append({"domain": domain, "n_A": len(a_lat), "n_B": len(b_lat),
                        "median_A": round(float(med_a), 2), "median_B": round(float(med_b), 2),
                        "IQR_A": round(float(iqr_a), 2), "IQR_B": round(float(iqr_b), 2),
                        "delta_median": round(float(med_b - med_a), 2),
                        "U_stat": round(float(u_stat), 2), "p_value": round(float(p_val), 6),
                        "significant_005": p_val < 0.05})
    if mw_rows:
        pd.DataFrame(mw_rows).to_csv(segmented_dir / "09_las_mannwhitney.csv", index=False)
        print(f"\n  [saved] {segmented_dir / '09_las_mannwhitney.csv'}")

    # ── 10. TFA: Fisher's exact test (A vs B) per suite and per domain ────────
    print(f"\n  {'='*68}")
    print(f"  TFA — FISHER'S EXACT TEST  (H₁: TFA_A < TFA_B, alternative='less')")
    print(f"  {'='*68}")
    fisher_rows = []

    def _fisher_row(domain, level, group, n_a, pass_a, n_b, pass_b):
        """Compute Fisher exact and return a result dict."""
        fail_a = n_a - pass_a
        fail_b = n_b - pass_b
        tfa_a  = round(pass_a / n_a, 4) if n_a else None
        tfa_b  = round(pass_b / n_b, 4) if n_b else None
        p_val  = None
        sig    = False
        if tfa_a is not None and tfa_b is not None:
            _, p_val = fisher_exact([[pass_a, fail_a], [pass_b, fail_b]], alternative="less")
            sig = bool(p_val < 0.05)
        delta = round(tfa_b - tfa_a, 4) if (tfa_a is not None and tfa_b is not None) else None
        return {"domain": domain, "level": level, "group": group,
                "n_A": n_a, "passed_A": pass_a, "TFA_A": tfa_a,
                "n_B": n_b, "passed_B": pass_b, "TFA_B": tfa_b,
                "delta_TFA": delta, "p_value_fisher": p_val, "significant_005": sig}

    # Per suite
    print(f"\n  BY SUITE")
    print(f"  {'Domain':30s} {'Suite':6s} {'n_A':>5} {'p_A':>6} {'n_B':>5} {'p_B':>6} "
          f"{'TFA_A':>7} {'TFA_B':>7} {'ΔTFA':>7} {'p':>9} {'sig':>5}")
    print(f"  {'-'*100}")
    for domain in domains:
        da = all_data[domain]["unprotected"]["adversarial"]
        db = all_data[domain]["protected"]["adversarial"]
        if da.empty or "garak_passed" not in da.columns or "suite" not in da.columns:
            continue
        dav = da[da["garak_passed"].notna()].copy()
        dav["garak_passed"] = dav["garak_passed"].astype(int)
        suites = sorted(dav["suite"].dropna().unique())
        for suite in suites:
            sub_a = dav[dav["suite"] == suite]
            n_a   = len(sub_a)
            pa    = int(sub_a["garak_passed"].sum())
            n_b   = pb = 0
            if not db.empty and "garak_passed" in db.columns and "suite" in db.columns:
                dbv = db[db["garak_passed"].notna()].copy()
                dbv["garak_passed"] = dbv["garak_passed"].astype(int)
                sub_b = dbv[dbv["suite"] == suite]
                n_b = len(sub_b)
                pb  = int(sub_b["garak_passed"].sum())
            row = _fisher_row(domain, "suite", suite, n_a, pa, n_b, pb)
            fisher_rows.append(row)
            tfa_a_s = f"{row['TFA_A']:.4f}" if row["TFA_A"] is not None else "N/A"
            tfa_b_s = f"{row['TFA_B']:.4f}" if row["TFA_B"] is not None else "N/A"
            delta_s = f"{row['delta_TFA']:+.4f}" if row["delta_TFA"] is not None else "N/A"
            p_s     = f"{row['p_value_fisher']:.4f}" if row["p_value_fisher"] is not None else "N/A"
            sig_s   = "✅" if row["significant_005"] else "—"
            print(f"  {domain:30s} {suite:6s} {n_a:>5} {pa:>6} {n_b:>5} {pb:>6} "
                  f"{tfa_a_s:>7} {tfa_b_s:>7} {delta_s:>7} {p_s:>9} {sig_s:>5}")

    # Per domain (global)
    print(f"\n  BY DOMAIN (global aggregate)")
    print(f"  {'Domain':30s} {'n_A':>7} {'p_A':>7} {'n_B':>7} {'p_B':>7} "
          f"{'TFA_A':>7} {'TFA_B':>7} {'ΔTFA':>7} {'p':>9} {'sig':>5}")
    print(f"  {'-'*95}")
    for domain in domains:
        da = all_data[domain]["unprotected"]["adversarial"]
        db = all_data[domain]["protected"]["adversarial"]
        if da.empty or "garak_passed" not in da.columns:
            continue
        dav = da[da["garak_passed"].notna()].copy()
        dav["garak_passed"] = dav["garak_passed"].astype(int)
        n_a = len(dav)
        pa  = int(dav["garak_passed"].sum())
        n_b = pb = 0
        if not db.empty and "garak_passed" in db.columns:
            dbv = db[db["garak_passed"].notna()].copy()
            dbv["garak_passed"] = dbv["garak_passed"].astype(int)
            n_b = len(dbv)
            pb  = int(dbv["garak_passed"].sum())
        row = _fisher_row(domain, "domain", domain, n_a, pa, n_b, pb)
        fisher_rows.append(row)
        tfa_a_s = f"{row['TFA_A']:.4f}" if row["TFA_A"] is not None else "N/A"
        tfa_b_s = f"{row['TFA_B']:.4f}" if row["TFA_B"] is not None else "N/A"
        delta_s = f"{row['delta_TFA']:+.4f}" if row["delta_TFA"] is not None else "N/A"
        p_s     = f"{row['p_value_fisher']:.4f}" if row["p_value_fisher"] is not None else "N/A"
        sig_s   = "✅" if row["significant_005"] else "—"
        print(f"  {domain:30s} {n_a:>7} {pa:>7} {n_b:>7} {pb:>7} "
              f"{tfa_a_s:>7} {tfa_b_s:>7} {delta_s:>7} {p_s:>9} {sig_s:>5}")

    if fisher_rows:
        pd.DataFrame(fisher_rows).to_csv(segmented_dir / "10_fisher_tfa_ab.csv", index=False)
        print(f"\n  [saved] {segmented_dir / '10_fisher_tfa_ab.csv'}")

    # ── 11. Spearman: PCC (external input) vs aggregate TFA ──────────────────
    print(f"\n  {'='*68}")
    print(f"  SPEARMAN — PCC (Porcentaje de Controles Cumplidos) vs aggregate TFA")
    print(f"  PCC = C_verificados / C_aplicables × 100  (manually verified per subdim).")
    print(f"  TFA = garak_passed aggregate per (domain × subdimension).  Exploratory.")
    print(f"  {'='*68}")

    if pcc_values is None:
        print(f"\n  [WARN] PCC values not provided — Spearman NCP skipped.")
        print(f"  Supply pcc_values dict to segmented_analysis() after manual control verification.")
        print(f"  Expected format: {{domain: {{subdimension: pcc_float}}}}")
    else:
        spearman_rows: list[dict] = []
        for domain in domains:
            if domain not in pcc_values:
                print(f"\n  [WARN] No PCC entry for domain '{domain}' — skipping.")
                continue
            domain_pcc = pcc_values[domain]
            for scenario in SCENARIOS:
                df = all_data[domain][scenario]["adversarial"]
                if df.empty or "garak_passed" not in df.columns or "subdimension" not in df.columns:
                    continue
                dv = df[df["garak_passed"].notna()].copy()
                dv["garak_passed"] = dv["garak_passed"].astype(int)

                subdims   = sorted(dv["subdimension"].dropna().unique())
                pcc_vals: list[float] = []
                tfa_vals: list[float] = []

                print(f"\n  Domain: {domain.upper()}  Scenario {SCEN_LABEL[scenario]}")
                print(f"  {'Subdim':8s} {'PCC (input)':>12} {'TFA_agg':>10} {'n_att':>8}")
                print(f"  {'-'*42}")
                for subdim in subdims:
                    sub   = dv[dv["subdimension"] == subdim]
                    n_att = len(sub)
                    if n_att == 0:
                        continue
                    agg_tfa = round(float(sub["garak_passed"].sum()) / n_att, 4)
                    pcc     = domain_pcc.get(subdim)
                    pcc_s   = f"{pcc:.4f}" if pcc is not None else "not provided"
                    print(f"  {subdim:8s} {pcc_s:>12} {agg_tfa:>10.4f} {n_att:>8}")
                    if pcc is not None:
                        pcc_vals.append(pcc)
                        tfa_vals.append(agg_tfa)
                        spearman_rows.append({
                            "domain": domain, "scenario": scenario,
                            "scenario_label": SCEN_LABEL[scenario],
                            "subdimension": subdim, "n_attempts": n_att,
                            "PCC": pcc, "TFA": agg_tfa,
                        })

                if len(pcc_vals) >= 3:
                    rho, p_rho = spearmanr(pcc_vals, tfa_vals)
                    print(f"\n  → Spearman ρ={rho:.4f}  p={p_rho:.4f}  "
                          f"(n={len(pcc_vals)} subdims)")
                elif pcc_vals:
                    print(f"\n  → Spearman skipped: only {len(pcc_vals)} subdim(s) — need ≥ 3")

        if len(spearman_rows) >= 3:
            sp_df  = pd.DataFrame(spearman_rows)
            rho_g, p_g = spearmanr(sp_df["PCC"].values, sp_df["TFA"].values)
            print(f"\n  GLOBAL Spearman (all domains × subdims × scenarios pooled):")
            print(f"  ρ = {rho_g:.4f}  p = {p_g:.4f}  (n = {len(sp_df)} pairs)")
            sp_df.to_csv(segmented_dir / "11_spearman_pcc_tfa.csv", index=False)
            print(f"\n  [saved] {segmented_dir / '11_spearman_pcc_tfa.csv'}")
        elif spearman_rows:
            print(f"\n  [WARN] Spearman requires ≥ 3 (domain, subdim) pairs with PCC; "
                  f"only {len(spearman_rows)} found.")

    print(f"\n{'='*70}")
    print(f"  Segmented analysis complete. Outputs → {segmented_dir.resolve()}")
    print(f"{'='*70}")


# ─────────────────────────────────────────────
# Latency: adversarial vs legitimate comparison
# ─────────────────────────────────────────────

def latency_adv_vs_legit(artifacts_dir: Path, domains: list):
    """Compare latency distributions between adversarial and legitimate prompts.

    For each (domain × scenario) combination, reports prompt-type counts and
    proportions, descriptive latency statistics, and a Mann-Whitney U test
    comparing the latency distributions of adversarial versus legitimate prompts.
    Results are printed as formatted tables and exported to a single wide-format
    CSV with one row per (domain × scenario).

    Parameters
    ----------
    artifacts_dir : Path
        Root artifacts directory containing ``consolidated_<domain>_<scenario>.csv``
        files.
    domains : list
        Ordered list of corpus domain names to analyse.

    Notes
    -----
    **Primary measure — median:**
        Request latency in LLM inference pipelines is asymmetric and heavy-tailed
        (long tail from variable prompt length and GPU scheduling).  The median is
        resistant to extreme outliers and is the standard summary statistic for
        such distributions.  The mean is reported alongside it purely as a
        secondary reference; it should not be used for significance testing or
        cross-condition comparison.

    **Statistical test — Mann-Whitney U (two-sided):**
        The two-sided alternative is used because there is no directional prior:
        adversarial prompts may be longer (injection payloads) or shorter (simple
        direct attacks) than the control legitimate prompts, so both directions
        of difference are scientifically interesting.  Mann-Whitney U is preferred
        over Welch's t-test because it does not assume normality and is more
        powerful under the heavy-tailed latency distributions observed here.

    Outputs
    -------
    - artifacts/segmented/12_latency_adv_vs_legit.csv : wide-format table with
      one row per (domain × scenario); columns include per-type n, median, mean,
      IQR, p95, p99, and Mann-Whitney U statistic, p-value, and significance flag.
    """
    SCENARIOS  = ["unprotected", "protected"]
    SCEN_LABEL = {"unprotected": "A", "protected": "B"}
    PROMPT_TYPES = ["adversarial", "legitimate"]

    segmented_dir = artifacts_dir / "segmented"
    segmented_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n{'='*70}")
    print(f"  LATENCY: ADVERSARIAL vs LEGITIMATE PROMPTS")
    print(f"{'='*70}")

    # ── 1. Counts and proportions ──────────────────────────────────────────────
    print(f"\n  COUNTS AND PROPORTIONS (per domain × scenario)")
    print(f"\n  {'Domain':30s} {'Scen':5s} {'adv_n':>8} {'legit_n':>8} "
          f"{'total':>8} {'%adv':>8} {'%legit':>8}")
    print(f"  {'-'*78}")
    count_rows: list[dict] = []
    for domain in domains:
        for scenario in SCENARIOS:
            path = artifacts_dir / f"consolidated_{domain}_{scenario}.csv"
            if not path.exists():
                continue
            df = pd.read_csv(path, usecols=lambda c: c == "prompt_type")
            n_adv   = int((df["prompt_type"] == "adversarial").sum())
            n_legit = int((df["prompt_type"] == "legitimate").sum())
            total   = n_adv + n_legit
            pct_adv   = n_adv   / total if total else 0.0
            pct_legit = n_legit / total if total else 0.0
            print(f"  {domain:30s} {SCEN_LABEL[scenario]:5s} {n_adv:>8} {n_legit:>8} "
                  f"{total:>8} {pct_adv*100:>7.1f}% {pct_legit*100:>7.1f}%")
            count_rows.append({"domain": domain, "scenario": scenario,
                               "n_adversarial": n_adv, "n_legitimate": n_legit, "total": total,
                               "pct_adversarial": round(pct_adv, 4),
                               "pct_legitimate": round(pct_legit, 4)})

    if count_rows:
        all_adv   = sum(r["n_adversarial"] for r in count_rows)
        all_legit = sum(r["n_legitimate"]  for r in count_rows)
        all_total = all_adv + all_legit
        print(f"  {'-'*78}")
        print(f"  {'TOTAL (all domains × scenarios)':30s} {'':5s} {all_adv:>8} {all_legit:>8} "
              f"{all_total:>8} {all_adv/all_total*100:>7.1f}% {all_legit/all_total*100:>7.1f}%")

    # ── 2. Latency statistics per prompt_type × domain × scenario ─────────────
    print(f"\n  LATENCY STATISTICS PER PROMPT TYPE (ms)")
    print(f"  Median is the primary measure. Mean is shown for reference only —")
    print(f"  it is non-representative due to asymmetric, heavy-tailed distribution.")
    print(f"\n  {'Domain':30s} {'Scen':5s} {'Type':12s} {'n':>6} "
          f"{'median':>8} {'mean*':>8} {'IQR':>8} {'p95':>8} {'p99':>8}")
    sep = f"  {'-'*90}"
    print(sep)

    stat_rows: list[dict] = []
    for domain in domains:
        for scenario in SCENARIOS:
            path = artifacts_dir / f"consolidated_{domain}_{scenario}.csv"
            if not path.exists():
                continue
            df_raw = pd.read_csv(path)
            if "latency_ms" not in df_raw.columns or "prompt_type" not in df_raw.columns:
                continue
            df_raw["latency_ms"] = pd.to_numeric(df_raw["latency_ms"], errors="coerce")
            for pt in PROMPT_TYPES:
                lat = df_raw[df_raw["prompt_type"] == pt]["latency_ms"].dropna()
                if lat.empty:
                    continue
                med  = float(lat.median())
                mean = float(lat.mean())
                iqr  = float(lat.quantile(0.75) - lat.quantile(0.25))
                p95  = float(lat.quantile(0.95))
                p99  = float(lat.quantile(0.99))
                print(f"  {domain:30s} {SCEN_LABEL[scenario]:5s} {pt:12s} {len(lat):>6} "
                      f"{med:>8.1f} {mean:>8.1f} {iqr:>8.1f} {p95:>8.1f} {p99:>8.1f}")
                stat_rows.append({
                    "domain": domain, "scenario": scenario,
                    "scenario_label": SCEN_LABEL[scenario], "prompt_type": pt,
                    "n": len(lat), "median_ms": round(med, 2), "mean_ms": round(mean, 2),
                    "iqr_ms": round(iqr, 2), "p95_ms": round(p95, 2), "p99_ms": round(p99, 2),
                })
        print(sep)

    # ── 3. Mann-Whitney U: adversarial vs legitimate per domain × scenario ─────
    print(f"\n  MANN-WHITNEY U — adversarial vs legitimate latency (two-sided, α=0.05)")
    print(f"\n  {'Domain':30s} {'Scen':5s} {'n_adv':>7} {'n_legit':>8} "
          f"{'med_adv':>9} {'med_leg':>9} {'Δmed':>8} {'U':>10} {'p':>9} {'sig':>5}")
    print(f"  {'-'*102}")

    mw_rows: list[dict] = []
    for domain in domains:
        for scenario in SCENARIOS:
            path = artifacts_dir / f"consolidated_{domain}_{scenario}.csv"
            if not path.exists():
                continue
            df_raw = pd.read_csv(path)
            if "latency_ms" not in df_raw.columns or "prompt_type" not in df_raw.columns:
                continue
            df_raw["latency_ms"] = pd.to_numeric(df_raw["latency_ms"], errors="coerce")
            lat_adv   = df_raw[df_raw["prompt_type"] == "adversarial"]["latency_ms"].dropna()
            lat_legit = df_raw[df_raw["prompt_type"] == "legitimate"]["latency_ms"].dropna()
            if lat_adv.empty or lat_legit.empty:
                print(f"  {domain:30s} {SCEN_LABEL[scenario]:5s}  [insufficient data]")
                continue
            med_adv   = float(lat_adv.median())
            med_legit = float(lat_legit.median())
            delta     = round(med_adv - med_legit, 2)
            u_stat, p_val = mannwhitneyu(lat_adv.values, lat_legit.values, alternative="two-sided")
            sig = "✅" if p_val < 0.05 else "—"
            print(f"  {domain:30s} {SCEN_LABEL[scenario]:5s} {len(lat_adv):>7} {len(lat_legit):>8} "
                  f"{med_adv:>9.1f} {med_legit:>9.1f} {delta:>+8.1f} "
                  f"{u_stat:>10.1f} {p_val:>9.4f} {sig:>5}")
            mw_rows.append({
                "domain": domain, "scenario": scenario,
                "scenario_label": SCEN_LABEL[scenario],
                "n_adversarial": len(lat_adv), "n_legitimate": len(lat_legit),
                "median_adversarial_ms": round(med_adv, 2),
                "median_legitimate_ms": round(med_legit, 2),
                "delta_median_adv_minus_legit_ms": delta,
                "U_stat": round(float(u_stat), 2),
                "p_value_mw": round(float(p_val), 6),
                "significant_005": p_val < 0.05,
            })

    if not stat_rows:
        print(f"\n  [WARN] No latency data found in consolidated CSVs.")
        return

    # ── Export ─────────────────────────────────────────────────────────────────
    # Build a wide-format CSV: one row per (domain × scenario) with stats for
    # both prompt types side by side, plus Mann-Whitney results.
    export_rows: list[dict] = []
    for domain in domains:
        for scenario in SCENARIOS:
            adv_stats   = next((r for r in stat_rows
                                if r["domain"] == domain and r["scenario"] == scenario
                                and r["prompt_type"] == "adversarial"), None)
            legit_stats = next((r for r in stat_rows
                                if r["domain"] == domain and r["scenario"] == scenario
                                and r["prompt_type"] == "legitimate"), None)
            mw = next((r for r in mw_rows
                       if r["domain"] == domain and r["scenario"] == scenario), None)
            if adv_stats is None and legit_stats is None:
                continue
            row: dict = {"domain": domain, "scenario": scenario,
                         "scenario_label": SCEN_LABEL[scenario]}
            for prefix, stats in (("adv", adv_stats), ("legit", legit_stats)):
                for col in ("n", "median_ms", "mean_ms", "iqr_ms", "p95_ms", "p99_ms"):
                    row[f"{prefix}_{col}"] = stats[col] if stats else None
            if mw:
                row["delta_median_adv_minus_legit_ms"] = mw["delta_median_adv_minus_legit_ms"]
                row["U_stat"]          = mw["U_stat"]
                row["p_value_mw"]      = mw["p_value_mw"]
                row["significant_005"] = mw["significant_005"]
            export_rows.append(row)

    if export_rows:
        out = segmented_dir / "12_latency_adv_vs_legit.csv"
        pd.DataFrame(export_rows).to_csv(out, index=False)
        print(f"\n  [saved] {out}")

    print(f"\n{'='*70}")


# ─────────────────────────────────────────────
# Visualization
# ─────────────────────────────────────────────

def setup_style():
    """Apply the shared matplotlib style for all experiment figures."""
    import matplotlib.pyplot as plt
    plt.rcParams.update({
        "figure.dpi":        150,
        "figure.facecolor":  "white",
        "axes.spines.top":   False,
        "axes.spines.right": False,
        "axes.grid":         True,
        "axes.grid.axis":    "y",
        "grid.alpha":        0.4,
        "font.size":         10,
        "axes.titlesize":    11,
        "axes.titleweight":  "bold",
    })


def _save(fig, figures_dir: Path, filename: str):
    """Save a matplotlib figure to ``figures_dir/filename`` and print the path."""
    figures_dir.mkdir(parents=True, exist_ok=True)
    path = figures_dir / filename
    fig.savefig(path, bbox_inches="tight")
    print(f"  [saved] {path}")


def plot_tfa_by_probe(tfa_a: dict, tfa_b: dict, domain: str, figures_dir: Path):
    """Bar chart of TFA per probe, coloured by OWASP suite, with optional Scenario B overlay.

    Args:
        tfa_a: TFA dict for Scenario A.
        tfa_b: TFA dict for Scenario B, or an empty dict when unavailable.
        domain: Domain name used in the figure title and output filename.
        figures_dir: Directory where the PNG is saved.
    """
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    import numpy as np
    setup_style()

    probes  = sorted(tfa_a["per_probe"].keys())
    labels  = [PROBE_SHORT.get(p, p) for p in probes]
    suites  = [tfa_a["per_probe"][p]["suite"] for p in probes]
    vals_a  = [tfa_a["per_probe"][p]["TFA"] or 0 for p in probes]
    vals_b  = [tfa_b["per_probe"][p]["TFA"] or 0 for p in probes] if tfa_b else None

    x     = np.arange(len(probes))
    width = 0.35 if vals_b else 0.6
    fig, ax = plt.subplots(figsize=(13, 5))

    ax.bar(x - width/2 if vals_b else x, vals_a, width,
           label="Scenario A",
           color=[SUITE_COLORS.get(s, "#888") for s in suites],
           alpha=0.85, edgecolor="white")
    if vals_b:
        ax.bar(x + width/2, vals_b, width, label="Scenario B",
               color=[SUITE_COLORS.get(s, "#888") for s in suites],
               alpha=0.45, edgecolor="white", hatch="//")

    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=35, ha="right", fontsize=9)
    ax.set_ylim(0, 1.08)
    ax.set_ylabel("TFA (Attack Filtering Rate)")
    ax.set_title(f"TFA per Probe — {domain.replace('_', ' ').title()}")
    ax.axhline(1.0, color="gray", linewidth=0.8, linestyle="--", alpha=0.5)

    suite_patches = [mpatches.Patch(color=c, label=s) for s, c in SUITE_COLORS.items()]
    legend1 = ax.legend(handles=suite_patches, title="OWASP Suite",
                        loc="lower left", fontsize=8)
    ax.add_artist(legend1)
    if vals_b:
        ax.legend(loc="lower right", fontsize=8)

    _save(fig, figures_dir, f"tfa_by_probe_{domain}.png")
    plt.close(fig)


def plot_tfa_by_suite(tfa_a: dict, tfa_b: dict, domain: str, figures_dir: Path):
    """Bar chart of TFA per OWASP suite with optional Scenario B overlay.

    Args:
        tfa_a: TFA dict for Scenario A.
        tfa_b: TFA dict for Scenario B, or an empty dict when unavailable.
        domain: Domain name used in the figure title and output filename.
        figures_dir: Directory where the PNG is saved.
    """
    import matplotlib.pyplot as plt
    import numpy as np
    setup_style()

    suites  = list(VECTOR_MAP.keys())
    labels  = [f"{s}\n{VECTOR_MAP[s].split('—')[1].strip()}" for s in suites]
    vals_a  = [tfa_a["per_suite"].get(s, {}).get("TFA") or 0 for s in suites]
    vals_b  = [tfa_b["per_suite"].get(s, {}).get("TFA") or 0 for s in suites] if tfa_b else None

    x     = np.arange(len(suites))
    width = 0.35 if vals_b else 0.5
    fig, ax = plt.subplots(figsize=(8, 5))

    ax.bar(x - width/2 if vals_b else x, vals_a, width, label="Scenario A",
           color=[SUITE_COLORS[s] for s in suites], alpha=0.85, edgecolor="white")
    if vals_b:
        ax.bar(x + width/2, vals_b, width, label="Scenario B",
               color=[SUITE_COLORS[s] for s in suites], alpha=0.45,
               edgecolor="white", hatch="//")

    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=9)
    ax.set_ylim(0, 1.08)
    ax.set_ylabel("TFA (Attack Filtering Rate)")
    ax.set_title(f"TFA per OWASP Suite — {domain.replace('_', ' ').title()}")
    ax.axhline(1.0, color="gray", linewidth=0.8, linestyle="--", alpha=0.5)
    if vals_b:
        ax.legend(fontsize=9)

    _save(fig, figures_dir, f"tfa_by_suite_{domain}.png")
    plt.close(fig)


def plot_tfa_domains_combined(tfa_by_domain: dict, figures_dir: Path):
    """Side-by-side per-suite TFA bar chart for all domains in a single figure.

    Args:
        tfa_by_domain: Mapping of ``{domain: {"A": tfa_dict, "B": tfa_dict}}``.
        figures_dir: Directory where the PNG is saved.
    """
    import matplotlib.pyplot as plt
    import numpy as np
    setup_style()

    domains  = list(tfa_by_domain.keys())
    suites   = list(VECTOR_MAP.keys())
    n_suites = len(suites)

    fig, axes = plt.subplots(1, len(domains), figsize=(7 * len(domains), 5), sharey=True)
    if len(domains) == 1:
        axes = [axes]

    for ax, domain in zip(axes, domains):
        tfa_a = tfa_by_domain[domain]["A"]
        tfa_b = tfa_by_domain[domain]["B"]
        vals_a = [tfa_a["per_suite"].get(s, {}).get("TFA") or 0 for s in suites]
        vals_b = [tfa_b["per_suite"].get(s, {}).get("TFA") or 0 for s in suites] if tfa_b else None

        x     = np.arange(n_suites)
        width = 0.35 if vals_b else 0.5

        ax.bar(x - width/2 if vals_b else x, vals_a, width, label="Scenario A",
               color=[SUITE_COLORS[s] for s in suites], alpha=0.85, edgecolor="white")
        if vals_b:
            ax.bar(x + width/2, vals_b, width, label="Scenario B",
                   color=[SUITE_COLORS[s] for s in suites], alpha=0.45,
                   edgecolor="white", hatch="//")

        ax.set_xticks(x)
        ax.set_xticklabels(suites, fontsize=9)
        ax.set_ylim(0, 1.08)
        ax.set_title(domain.replace("_", " ").title(), fontsize=10)
        ax.axhline(1.0, color="gray", linewidth=0.8, linestyle="--", alpha=0.5)
        if vals_b:
            ax.legend(fontsize=8)

    axes[0].set_ylabel("TFA (Attack Filtering Rate)")
    fig.suptitle("TFA per OWASP Suite — Both Domains", fontweight="bold")
    fig.tight_layout()
    _save(fig, figures_dir, "tfa_by_suite_combined.png")
    plt.close(fig)

def plot_tfa_heatmap(tfa_by_domain: dict, figures_dir: Path):
    """Heatmap: TFA_A per probe × domain."""
    import matplotlib.pyplot as plt
    import numpy as np
    setup_style()

    domains = list(tfa_by_domain.keys())
    probes  = sorted(next(iter(tfa_by_domain.values()))["A"]["per_probe"].keys())
    labels  = [PROBE_SHORT.get(p, p) for p in probes]

    matrix = []
    for domain in domains:
        tfa_a = tfa_by_domain[domain]["A"]
        row = [tfa_a["per_probe"].get(p, {}).get("TFA") or 0 for p in probes]
        matrix.append(row)

    data = np.array(matrix)
    fig, ax = plt.subplots(figsize=(13, 3 + len(domains)))
    im = ax.imshow(data, cmap="RdYlGn", vmin=0, vmax=1, aspect="auto")

    ax.set_xticks(range(len(probes)))
    ax.set_xticklabels(labels, rotation=35, ha="right", fontsize=9)
    ax.set_yticks(range(len(domains)))
    ax.set_yticklabels([d.replace("_", " ").title() for d in domains], fontsize=9)

    # Annotate cells
    for i in range(len(domains)):
        for j in range(len(probes)):
            ax.text(j, i, f"{data[i, j]:.2f}", ha="center", va="center",
                    fontsize=8, color="black")

    plt.colorbar(im, ax=ax, label="TFA")
    ax.set_title("TFA Heatmap — Scenario A (per Probe × Domain)")
    fig.tight_layout()
    _save(fig, figures_dir, "tfa_heatmap_probe_domain.png")
    plt.close(fig)

def plot_delta_tfa(tfa_by_domain: dict, figures_dir: Path):
    """Bar chart of ΔTFA per probe (Scenario B − Scenario A) for each domain.

    Skipped automatically when no Scenario B data is available.

    Args:
        tfa_by_domain: Mapping of ``{domain: {"A": tfa_dict, "B": tfa_dict}}``.
        figures_dir: Directory where the PNG is saved.
    """
    import matplotlib.pyplot as plt
    import numpy as np
    has_b = any(tfa_by_domain[d]["B"] for d in tfa_by_domain)
    if not has_b:
        print("  [skip] ΔTFA plot requires Scenario B data.")
        return
    setup_style()

    probes = sorted(next(iter(tfa_by_domain.values()))["A"]["per_probe"].keys())
    labels = [PROBE_SHORT.get(p, p) for p in probes]
    fig, ax = plt.subplots(figsize=(13, 5))
    x = np.arange(len(probes))
    width = 0.35
    domain_colors = ["#4C72B0", "#DD8452"]

    for i, (domain, color) in enumerate(zip(tfa_by_domain.keys(), domain_colors)):
        tfa_a = tfa_by_domain[domain]["A"]
        tfa_b = tfa_by_domain[domain]["B"]
        if not tfa_b:
            continue
        deltas = []
        for p in probes:
            va = tfa_a["per_probe"].get(p, {}).get("TFA")
            vb = tfa_b["per_probe"].get(p, {}).get("TFA")
            deltas.append((vb - va) if (va is not None and vb is not None) else 0)
        offset = (i - 0.5) * width
        ax.bar(x + offset, deltas, width,
               label=domain.replace("_", " ").title(),
               color=color, alpha=0.8, edgecolor="white")

    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=35, ha="right", fontsize=9)
    ax.axhline(0, color="black", linewidth=0.8)
    ax.set_ylabel("ΔTFA (Scenario B − Scenario A)")
    ax.set_title("ΔTFA per Probe — LLM Guard Net Contribution")
    ax.legend(fontsize=9)
    _save(fig, figures_dir, "delta_tfa_by_probe.png")
    plt.close(fig)

def plot_pvalue_by_suite(tfa_by_domain: dict, figures_dir: Path):
    """Bar chart of -log10(p-value) per suite — Fisher exact test A vs B."""
    import matplotlib.pyplot as plt
    import numpy as np
    has_b = any(tfa_by_domain[d]["B"] for d in tfa_by_domain)
    if not has_b:
        print("  [skip] p-value plot requires Scenario B data.")
        return
    setup_style()

    fig, ax = plt.subplots(figsize=(9, 5))
    x = np.arange(len(VECTOR_MAP))
    width = 0.8 / max(len(tfa_by_domain), 1)
    domain_colors = ["#4C72B0", "#DD8452", "#55A868", "#C44E52"]

    for i, (domain, color) in enumerate(zip(tfa_by_domain.keys(), domain_colors)):
        tfa_a = tfa_by_domain[domain]["A"]
        tfa_b = tfa_by_domain[domain]["B"]
        if not tfa_b:
            continue
        pvals = []
        for suite in VECTOR_MAP:
            va = tfa_a["per_suite"].get(suite)
            vb = tfa_b["per_suite"].get(suite)
            if va and vb:
                fn_a = va["total"] - va["passed"]
                fn_b = vb["total"] - vb["passed"]
                _, p = fisher_exact(
                    [[va["passed"], fn_a], [vb["passed"], fn_b]],
                    alternative="less"
                )
                pvals.append(-np.log10(p) if p > 0 else 0)
            else:
                pvals.append(0)

        offset = (i - len(tfa_by_domain) / 2 + 0.5) * width
        ax.bar(x + offset, pvals, width,
               label=domain.replace("_", " ").title(),
               color=color, alpha=0.8, edgecolor="white")

    # Significance threshold line: -log10(0.05) ≈ 1.301
    ax.axhline(-np.log10(0.05), color="red", linewidth=1.2,
               linestyle="--", label="α = 0.05")

    ax.set_xticks(x)
    ax.set_xticklabels(list(VECTOR_MAP.keys()), fontsize=10)
    ax.set_ylabel("-log₁₀(p-value)")
    ax.set_title("Statistical Significance per OWASP Suite (Fisher Exact, A vs B)")
    ax.legend(fontsize=9)
    _save(fig, figures_dir, "pvalue_by_suite.png")
    plt.close(fig)

def plot_confidential_exposure(artifacts_dir: Path, domains: list, figures_dir: Path):
    """Bar chart: confidential exposure rate per subdimension per domain."""
    import matplotlib.pyplot as plt
    import numpy as np
    setup_style()

    subdims = ["D1", "D2", "D3", "D4"]
    x = np.arange(len(subdims))
    width = 0.8 / max(len(domains), 1)
    fig, ax = plt.subplots(figsize=(9, 5))
    domain_colors = list(SCENARIO_COLORS.values()) + ["#55A868", "#C44E52"]

    for i, (domain, color) in enumerate(zip(domains, domain_colors)):
        df = load_consolidated(artifacts_dir, domain, "unprotected")
        if df.empty:
            continue
        rates = []
        for subdim in subdims:
            sub = df[df["subdimension"] == subdim]
            rate = sub["response_has_confidential"].sum() / len(sub) if len(sub) > 0 else 0
            rates.append(rate)
        offset = (i - len(domains) / 2 + 0.5) * width
        ax.bar(x + offset, rates, width,
               label=domain.replace("_", " ").title(),
               color=color, alpha=0.8, edgecolor="white")

    ax.set_xticks(x)
    ax.set_xticklabels(subdims, fontsize=10)
    ax.set_ylabel("Confidential Exposure Rate")
    ax.set_title("Confidential Data Exposure per Subdimension — Scenario A")
    ax.legend(fontsize=9)
    _save(fig, figures_dir, "confidential_exposure_by_subdim.png")
    plt.close(fig)


def plot_las_boxplot(lat_a: pd.DataFrame, lat_b: pd.DataFrame, figures_dir: Path,
                     by_domain: bool = False):
    """Latency boxplot — global (by_domain=False) or one subplot per domain (by_domain=True)."""
    import matplotlib.pyplot as plt
    if lat_a.empty or lat_b.empty:
        suffix = "domain boxplot" if by_domain else "boxplot"
        print(f"  [skip] LAS {suffix} requires both scenarios.")
        return
    setup_style()

    if by_domain:
        domains = sorted(set(lat_a["domain"].dropna()) | set(lat_b["domain"].dropna()))
        n = len(domains)
        fig, axes = plt.subplots(1, n, figsize=(6 * n, 5), sharey=True)
        if n == 1:
            axes = [axes]
        for ax, domain in zip(axes, domains):
            sub_a = lat_a[lat_a["domain"] == domain]["latency_ms"].values
            sub_b = lat_b[lat_b["domain"] == domain]["latency_ms"].values
            bp = ax.boxplot([sub_a, sub_b], labels=["Scenario A", "Scenario B"],
                            patch_artist=True,
                            medianprops={"color": "black", "linewidth": 2},
                            flierprops={"marker": ".", "markersize": 3, "alpha": 0.3})
            for patch, color in zip(bp["boxes"], [SCENARIO_COLORS["A"], SCENARIO_COLORS["B"]]):
                patch.set_facecolor(color)
                patch.set_alpha(0.6)
            ax.set_title(domain.replace("_", " ").title(), fontsize=10)
            ax.set_ylabel("Latency (ms)" if ax == axes[0] else "")
        fig.suptitle("Latency Distribution per Domain", fontweight="bold")
        fig.tight_layout()
        _save(fig, figures_dir, "las_boxplot_by_domain.png")
    else:
        fig, ax = plt.subplots(figsize=(6, 5))
        data   = [lat_a["latency_ms"].values, lat_b["latency_ms"].values]
        labels = ["Scenario A\n(unprotected)", "Scenario B\n(LLM Guard)"]
        colors = [SCENARIO_COLORS["A"], SCENARIO_COLORS["B"]]
        bp = ax.boxplot(data, labels=labels, patch_artist=True,
                        medianprops={"color": "black", "linewidth": 2},
                        flierprops={"marker": ".", "markersize": 3, "alpha": 0.3})
        for patch, color in zip(bp["boxes"], colors):
            patch.set_facecolor(color)
            patch.set_alpha(0.6)
        ax.set_ylabel("Latency (ms)")
        ax.set_title("Latency Distribution — Scenario A vs B")
        _save(fig, figures_dir, "las_boxplot_global.png")

    plt.close(fig)

def plot_latency_histogram(lat_a: pd.DataFrame, lat_b: pd.DataFrame, figures_dir: Path):
    """Latency histogram with KDE — Scenario A vs B."""
    import matplotlib.pyplot as plt
    if lat_a.empty:
        return
    setup_style()

    fig, ax = plt.subplots(figsize=(11, 6))

    vals_a = lat_a["latency_ms"].dropna()
    ax.hist(vals_a, bins=80, alpha=0.4, color=SCENARIO_COLORS["A"],
            label="Scenario A", density=True)
    vals_a.plot.kde(color=SCENARIO_COLORS["A"], linewidth=2, ax=ax, label="_nolegend_")

    # Mean lines and stats text
    mean_a = vals_a.mean()
    std_a  = vals_a.std()
    ax.axvline(mean_a, color=SCENARIO_COLORS["A"], linewidth=1.5,
               linestyle="--", alpha=0.8)

    stats_text = f"Scenario A\n  mean={mean_a:.0f} ms\n  std={std_a:.0f} ms"

    if not lat_b.empty:
        vals_b = lat_b["latency_ms"].dropna()
        ax.hist(vals_b, bins=80, alpha=0.4, color=SCENARIO_COLORS["B"],
                label="Scenario B", density=True)
        vals_b.plot.kde(color=SCENARIO_COLORS["B"], linewidth=2, ax=ax, label="_nolegend_")

        mean_b = vals_b.mean()
        std_b  = vals_b.std()
        ax.axvline(mean_b, color=SCENARIO_COLORS["B"], linewidth=1.5,
                   linestyle="--", alpha=0.8)

        # Mann-Whitney p-value
        _, p_val = mannwhitneyu(vals_a.values, vals_b.values, alternative="less")
        sig = "significant" if p_val < 0.05 else "not significant"
        stats_text += (
            f"\n\nScenario B\n  mean={mean_b:.0f} ms\n  std={std_b:.0f} ms"
            f"\n\nMann-Whitney U\n  p={p_val:.2e}\n  ({sig}, α=0.05)"
        )
        xmax = max(vals_a.quantile(0.999), vals_b.quantile(0.999))
    else:
        xmax = vals_a.quantile(0.999)

    # Annotation box top-right
    ax.text(0.97, 0.97, stats_text,
            transform=ax.transAxes,
            fontsize=8.5, verticalalignment="top", horizontalalignment="right",
            bbox=dict(boxstyle="round,pad=0.5", facecolor="white",
                      edgecolor="gray", alpha=0.85))

    ax.set_xlim(left=0, right=xmax * 1.05)
    ax.set_xlabel("Latency (ms)")
    ax.set_ylabel("Density")
    ax.set_title("Latency Distribution — Histogram + KDE")
    ax.legend(fontsize=9)
    _save(fig, figures_dir, "las_histogram_kde.png")
    plt.close(fig)

def plot_las_by_suite(lat_a: pd.DataFrame, lat_b: pd.DataFrame, figures_dir: Path):
    """Bar chart of median latency per OWASP suite with optional Scenario B overlay.

    Args:
        lat_a: Latency DataFrame for Scenario A.
        lat_b: Latency DataFrame for Scenario B (may be empty).
        figures_dir: Directory where the PNG is saved.
    """
    import matplotlib.pyplot as plt
    import numpy as np
    if lat_a.empty:
        print("  [skip] LAS by suite requires Scenario A latency data.")
        return
    setup_style()

    lat_a = lat_a.copy()
    lat_a["suite"] = lat_a["suite_probe"].apply(_extract_suite)
    suites_present = [s for s in VECTOR_MAP if s in lat_a["suite"].values]
    if not suites_present:
        print("  [skip] No suite information found in latency CSV.")
        return

    meds_a, meds_b, labels = [], [], []
    for suite in suites_present:
        sub_a = lat_a[lat_a["suite"] == suite]["latency_ms"]
        meds_a.append(sub_a.median())
        labels.append(suite)
        if not lat_b.empty:
            lat_b_copy = lat_b.copy()
            lat_b_copy["suite"] = lat_b_copy["suite_probe"].apply(_extract_suite)
            sub_b = lat_b_copy[lat_b_copy["suite"] == suite]["latency_ms"]
            meds_b.append(sub_b.median() if not sub_b.empty else None)
        else:
            meds_b.append(None)

    x     = np.arange(len(labels))
    has_b = any(v is not None for v in meds_b)
    width = 0.35 if has_b else 0.5
    fig, ax = plt.subplots(figsize=(8, 5))

    ax.bar(x - width/2 if has_b else x, meds_a, width, label="Scenario A",
           color=[SUITE_COLORS.get(s, "#888") for s in labels],
           alpha=0.85, edgecolor="white")
    if has_b:
        valid_b = [v or 0 for v in meds_b]
        ax.bar(x + width/2, valid_b, width, label="Scenario B",
               color=[SUITE_COLORS.get(s, "#888") for s in labels],
               alpha=0.45, edgecolor="white", hatch="//")

    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=9, ha="center")
    ax.set_ylabel("Median Latency (ms)")
    ax.set_title("Median Latency per OWASP Suite")
    if has_b:
        ax.legend(fontsize=9)
    _save(fig, figures_dir, "las_median_by_suite.png")
    plt.close(fig)


def plot_latency_distribution_by_suite(lat_a: pd.DataFrame, figures_dir: Path):
    """Boxplot of latency distribution per suite — Scenario A."""
    import matplotlib.pyplot as plt
    if lat_a.empty:
        return
    setup_style()

    lat_a = lat_a.copy()
    lat_a["suite"] = lat_a["suite_probe"].apply(_extract_suite)
    suites = [s for s in VECTOR_MAP if s in lat_a["suite"].values]
    data   = [lat_a[lat_a["suite"] == s]["latency_ms"].values for s in suites]

    fig, ax = plt.subplots(figsize=(9, 5))
    bp = ax.boxplot(data, labels=suites, patch_artist=True,
                    medianprops={"color": "black", "linewidth": 2},
                    flierprops={"marker": ".", "markersize": 2, "alpha": 0.3})
    for patch, suite in zip(bp["boxes"], suites):
        patch.set_facecolor(SUITE_COLORS.get(suite, "#888"))
        patch.set_alpha(0.7)
    ax.set_ylabel("Latency (ms)")
    ax.set_title("Latency Distribution per OWASP Suite — Scenario A")
    _save(fig, figures_dir, "las_distribution_by_suite_A.png")
    plt.close(fig)

def plot_confusion_matrix(artifacts_dir: Path, domains: list, figures_dir: Path):
    """
    Heatmap confusion matrix for LLM Guard — Scenario B.
    One subplot per domain.
    """
    import matplotlib.pyplot as plt
    import numpy as np
    setup_style()

    valid_domains = []
    matrices = []

    for domain in domains:
        df_b = load_consolidated(artifacts_dir, domain, "protected")
        if df_b.empty:
            print(f"  [skip] confusion matrix: no Scenario B data for {domain}")
            continue
        adv   = df_b[df_b["prompt_type"] == "adversarial"]
        legit = df_b[df_b["prompt_type"] == "legitimate"]
        counts = _confusion_counts(adv, legit)
        TP, FN, FP, TN = counts["TP"], counts["FN"], counts["FP"], counts["TN"]
        valid_domains.append(domain)
        matrices.append(np.array([[TP, FN], [FP, TN]]))

    if not valid_domains:
        print("  [skip] confusion matrix: no Scenario B data available yet.")
        return

    n = len(valid_domains)
    fig, axes = plt.subplots(1, n, figsize=(5 * n, 4))
    if n == 1:
        axes = [axes]

    labels = ["BLOCK", "PASS"]
    row_labels = ["Actual\nATTACK", "Actual\nLEGIT"]

    for ax, domain, matrix in zip(axes, valid_domains, matrices):
        total = matrix.sum()
        # Normalize for color, show raw counts as annotation
        norm = matrix / total if total > 0 else matrix

        im = ax.imshow(norm, cmap="Blues", vmin=0, vmax=1)

        ax.set_xticks([0, 1])
        ax.set_xticklabels(["Predicted\nBLOCK", "Predicted\nPASS"], fontsize=9)
        ax.set_yticks([0, 1])
        ax.set_yticklabels(row_labels, fontsize=9)

        cell_labels = [["TP", "FN"], ["FP", "TN"]]
        colors_text  = [["white", "black"], ["black", "white"]]

        for i in range(2):
            for j in range(2):
                val  = matrix[i, j]
                pct  = val / total * 100 if total > 0 else 0
                label = cell_labels[i][j]
                color = "white" if norm[i, j] > 0.4 else "black"
                ax.text(j, i,
                        f"{label}\n{val:,}\n({pct:.1f}%)",
                        ha="center", va="center",
                        fontsize=10, fontweight="bold", color=color)

        # Derived metrics annotation
        TP, FN, FP, TN = matrix[0,0], matrix[0,1], matrix[1,0], matrix[1,1]
        precision   = TP/(TP+FP) if (TP+FP) > 0 else 0
        recall      = TP/(TP+FN) if (TP+FN) > 0 else 0
        f1          = 2*precision*recall/(precision+recall) if (precision+recall) > 0 else 0
        specificity = TN/(TN+FP) if (TN+FP) > 0 else 0

        stats = (f"Precision: {precision:.3f}\n"
                 f"Recall (TFA): {recall:.3f}\n"
                 f"F1: {f1:.3f}\n"
                 f"Specificity: {specificity:.3f}")
        ax.text(1.35, 0.5, stats,
                transform=ax.transAxes,
                fontsize=8.5, va="center",
                bbox=dict(boxstyle="round,pad=0.4", facecolor="white",
                          edgecolor="gray", alpha=0.85))

        ax.set_title(domain.replace("_", " ").title(), fontsize=10)

    fig.suptitle("Confusion Matrix — LLM Guard (Scenario B)", fontweight="bold")
    fig.tight_layout()
    _save(fig, figures_dir, "confusion_matrix_scenario_b.png")
    plt.close(fig)


def plot_detector_heatmap(runs_dir: Path, domains: list, figures_dir: Path):
    """
    Heatmap: TFA per probe × detector for Scenario A.
    Highlights primary detector and gap between detectors.
    """
    import matplotlib.pyplot as plt
    import numpy as np
    setup_style()

    # Collect all (probe, detector) pairs across domains
    all_keys: set[tuple] = set()
    domain_data: dict[str, dict] = {}

    for domain in domains:
        run_a = find_run_dir(runs_dir, domain, "unprotected")
        if not run_a:
            continue
        results: dict[tuple, dict] = defaultdict(lambda: {"passed": 0, "total": 0})
        for probe, detector, passed, total in _load_jsonl_eval_entries(run_a / "garak"):
            results[(probe, detector)]["passed"] += passed
            results[(probe, detector)]["total"]  += total

        domain_data[domain] = {
            k: v["passed"] / v["total"] if v["total"] > 0 else 0
            for k, v in results.items()
        }
        all_keys.update(results.keys())

    if not domain_data:
        print("  [skip] detector heatmap: no data available.")
        return

    # Build sorted axes
    all_keys_sorted = sorted(all_keys, key=lambda x: (x[0], x[1]))
    row_labels = [f"{PROBE_SHORT.get(p, p)}\n{d.split('.')[-1]}"
                  for p, d in all_keys_sorted]
    col_labels = [dom.replace("_", " ").title() for dom in domain_data]

    matrix = np.array([
        [domain_data[dom].get(key, float("nan")) for dom in domain_data]
        for key in all_keys_sorted
    ])

    fig, ax = plt.subplots(figsize=(4 + len(domain_data) * 2, 1.5 + len(all_keys_sorted) * 0.5))
    im = ax.imshow(matrix, cmap="RdYlGn", vmin=0, vmax=1, aspect="auto")

    ax.set_xticks(range(len(col_labels)))
    ax.set_xticklabels(col_labels, fontsize=9)
    ax.set_yticks(range(len(row_labels)))
    ax.set_yticklabels(row_labels, fontsize=8)

    # Annotate cells
    for i in range(len(all_keys_sorted)):
        for j in range(len(domain_data)):
            val = matrix[i, j]
            if not np.isnan(val):
                color = "white" if val < 0.4 else "black"
                # Mark primary detector with bold
                probe, detector = all_keys_sorted[i]
                is_primary = (PRIMARY_DETECTOR.get(probe) == detector
                              or probe not in PRIMARY_DETECTOR)
                weight = "bold" if is_primary else "normal"
                ax.text(j, i, f"{val:.3f}",
                        ha="center", va="center",
                        fontsize=8, color=color, fontweight=weight)

    plt.colorbar(im, ax=ax, label="TFA", shrink=0.6)
    ax.set_title("TFA per Probe × Detector — Scenario A\n"
                 "(bold = primary detector used for TFA calculation)",
                 fontsize=10)
    fig.tight_layout()
    _save(fig, figures_dir, "detector_heatmap_scenario_a.png")
    plt.close(fig)

def plot_confusion_matrix_scenario_a(artifacts_dir: Path, domains: list, figures_dir: Path):
    """
    Partial confusion matrix for Scenario A (no active classifier).
    TP/FN from garak_passed (adversarial), TN from legitimate prompts.
    FP does not exist: no blocking mechanism is active.
    """
    import matplotlib.pyplot as plt
    import numpy as np
    setup_style()

    valid_domains = []
    matrices = []
    tn_counts = []

    for domain in domains:
        df_a_adv = load_consolidated(artifacts_dir, domain, "unprotected")
        if df_a_adv.empty:
            print(f"  [skip] confusion matrix A: no data for {domain}")
            continue

        df_legit = _load_consolidated_legit(artifacts_dir, domain, "unprotected")

        # TP / FN from garak_passed
        df_adv_valid = df_a_adv[df_a_adv["garak_passed"].notna()].copy()
        df_adv_valid["garak_passed"] = df_adv_valid["garak_passed"].astype(int)
        TP = int((df_adv_valid["garak_passed"] == 1).sum())
        FN = int((df_adv_valid["garak_passed"] == 0).sum())

        # TN: legitimate prompts that did not expose confidential data
        TN = int((df_legit["response_has_confidential"] == 0).sum())
        # Legitimate that leaked confidential → also a failure, not FP
        legit_leaked = int((df_legit["response_has_confidential"] == 1).sum())

        valid_domains.append(domain)
        matrices.append((TP, FN, TN, legit_leaked))

    if not valid_domains:
        print("  [skip] confusion matrix A: no data available.")
        return

    n = len(valid_domains)
    fig, axes = plt.subplots(1, n, figsize=(6 * n, 5))
    if n == 1:
        axes = [axes]

    for ax, domain, (TP, FN, TN, legit_leaked) in zip(axes, valid_domains, matrices):
        total_adv   = TP + FN
        total_legit = TN + legit_leaked

        # 2×2 matrix: rows=actual, cols=resisted/failed
        # [TP, FN]
        # [TN, N/A] ← FP does not exist
        matrix_display = np.array([
            [TP,           FN],
            [TN,           float("nan")],
        ])

        # Color only defined cells
        color_matrix = np.array([
            [TP / total_adv if total_adv > 0 else 0,
             FN / total_adv if total_adv > 0 else 0],
            [1.0,  float("nan")],  # TN always green-ish
        ])

        cmap = plt.cm.RdYlGn
        cmap.set_bad(color="#eeeeee")  # gray for N/A cell

        im = ax.imshow(
            np.ma.masked_invalid(color_matrix),
            cmap=cmap, vmin=0, vmax=1, aspect="auto"
        )

        ax.set_xticks([0, 1])
        ax.set_xticklabels(["Resisted", "Failed"], fontsize=10)
        ax.set_yticks([0, 1])
        ax.set_yticklabels(["Actual\nATTACK", "Actual\nLEGIT"], fontsize=10)

        # Cell annotations
        cell_meta = [
            (0, 0, f"TP\n{TP:,}\n({TP/total_adv*100:.1f}%)",   "black"),
            (0, 1, f"FN\n{FN:,}\n({FN/total_adv*100:.1f}%)",   "black"),
            (1, 0, f"TN\n{TN:,}\n({TN/total_legit*100:.1f}%)", "black"),
            (1, 1, "FP\nN/A\n(no classifier)", "gray"),
        ]
        for row, col, text, color in cell_meta:
            weight = "bold" if text.startswith("FP") is False else "normal"
            ax.text(col, row, text,
                    ha="center", va="center",
                    fontsize=9, color=color, fontweight=weight)

        # Metrics annotation
        recall      = TP / total_adv if total_adv > 0 else 0
        fnr         = FN / total_adv if total_adv > 0 else 0
        tn_rate     = TN / total_legit if total_legit > 0 else 0
        legit_leak_rate = legit_leaked / total_legit if total_legit > 0 else 0

        stats = (
            f"Model resistance (TFA_A)\n"
            f"  Recall = {recall:.4f}\n"
            f"  FNR    = {fnr:.4f}\n\n"
            f"Legitimate prompts\n"
            f"  TN rate = {tn_rate:.4f}\n"
            f"  Leaked  = {legit_leaked} ({legit_leak_rate*100:.1f}%)\n\n"
            f"FP = N/A\n"
            f"(no active classifier)"
        )
        ax.text(1.38, 0.5, stats,
                transform=ax.transAxes,
                fontsize=8, va="center",
                bbox=dict(boxstyle="round,pad=0.4", facecolor="white",
                          edgecolor="gray", alpha=0.85))

        ax.set_title(domain.replace("_", " ").title(), fontsize=10)

    fig.suptitle(
        "Partial Confusion Matrix — Scenario A (no active classifier)\n"
        "FP cell grayed out: blocking mechanism absent by design",
        fontweight="bold", fontsize=10
    )
    fig.tight_layout()
    _save(fig, figures_dir, "confusion_matrix_scenario_a.png")
    plt.close(fig)

def generate_all_plots(tfa_by_domain: dict, lat_a: pd.DataFrame,
                       lat_b: pd.DataFrame, artifacts_dir: Path, runs_dir: Path, figures_dir: Path):
    print(f"\n{'='*70}")
    print(f"  GENERATING FIGURES → {figures_dir}")
    print(f"{'='*70}")

    try:
        import matplotlib
        matplotlib.use("Agg")
    except ImportError:
        print("  [ERROR] matplotlib not installed. Run: pip install matplotlib")
        return

    domains = list(tfa_by_domain.keys())

    for domain, data in tfa_by_domain.items():
        tfa_a, tfa_b = data["A"], data["B"]
        if not tfa_a:
            continue
        plot_tfa_by_probe(tfa_a, tfa_b, domain, figures_dir)
        plot_tfa_by_suite(tfa_a, tfa_b, domain, figures_dir)

    plot_tfa_domains_combined(tfa_by_domain, figures_dir)
    plot_tfa_heatmap(tfa_by_domain, figures_dir)
    plot_delta_tfa(tfa_by_domain, figures_dir)
    plot_pvalue_by_suite(tfa_by_domain, figures_dir)
    plot_confidential_exposure(artifacts_dir, domains, figures_dir)
    plot_las_boxplot(lat_a, lat_b, figures_dir)
    plot_las_boxplot(lat_a, lat_b, figures_dir, by_domain=True)
    plot_latency_histogram(lat_a, lat_b, figures_dir)
    plot_las_by_suite(lat_a, lat_b, figures_dir)
    plot_latency_distribution_by_suite(lat_a, figures_dir)
    plot_confusion_matrix_scenario_a(artifacts_dir, domains, figures_dir)
    plot_confusion_matrix(artifacts_dir, domains, figures_dir)
    plot_detector_heatmap(runs_dir, domains, figures_dir)

    n = len(list(figures_dir.glob("*.png")))
    print(f"\n  Done. {n} figures saved.\n")


# ─────────────────────────────────────────────
# Segmented figures (new)
# ─────────────────────────────────────────────

def plot_latency_adv_vs_legit_boxplot(artifacts_dir: Path, domains: list, figures_dir: Path):
    """Side-by-side boxplots comparing adversarial and legitimate latency per scenario.

    Produces one subplot per domain.  Within each subplot, four boxes are arranged
    at fixed x-positions grouped by scenario, with a visual gap separating Scenario A
    from Scenario B:

        [Scen A / Adv.] [Scen A / Legit.]  |  [Scen B / Adv.] [Scen B / Legit.]

    Missing scenario data (e.g. Scenario B not yet collected) causes the
    corresponding boxes to be omitted silently without breaking the figure.

    Parameters
    ----------
    artifacts_dir : Path
        Root artifacts directory containing ``consolidated_<domain>_<scenario>.csv``
        files.
    domains : list
        Ordered list of domain names; one subplot is created per domain.
    figures_dir : Path
        Directory where the output PNG is saved.

    Notes
    -----
    **Log scale on the y-axis:**
        LLM inference latency spans two to three orders of magnitude (tens of ms
        for cached token generation up to several seconds for long contexts).  A
        linear scale compresses the bulk of the distribution into a narrow band
        at the bottom and makes the median almost invisible.  A log scale gives
        equal visual weight to each order of magnitude and preserves the shape of
        the IQR and whiskers for both fast and slow requests.

    Outputs
    -------
    - artifacts/figures/latency_adv_vs_legit_boxplot.png : boxplot figure, dpi=150.
    """
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    setup_style()

    SCENARIOS  = ["unprotected", "protected"]
    SCEN_LABEL = {"unprotected": "A", "protected": "B"}
    PT_COLORS  = {"adversarial": "#C44E52", "legitimate": "#4C72B0"}
    # Fixed positions: gap between the two scenario groups
    ALL_POS    = [1.0, 2.0, 3.5, 4.5]
    ALL_LABS   = ["Scen A\nAdv.", "Scen A\nLegit.", "Scen B\nAdv.", "Scen B\nLegit."]

    n = len(domains)
    if n == 0:
        print("  [skip] latency_adv_vs_legit_boxplot: no domains.")
        return

    fig, axes = plt.subplots(1, n, figsize=(7 * n, 6))
    if n == 1:
        axes = [axes]

    for ax, domain in zip(axes, domains):
        box_data, used_pos, used_labs, colors = [], [], [], []
        for idx, (scenario, pt) in enumerate(
            [(s, p) for s in SCENARIOS for p in ("adversarial", "legitimate")]
        ):
            path = artifacts_dir / f"consolidated_{domain}_{scenario}.csv"
            if path.exists():
                df  = pd.read_csv(path)
                if "latency_ms" in df.columns and "prompt_type" in df.columns:
                    lat = (pd.to_numeric(df[df["prompt_type"] == pt]["latency_ms"],
                                         errors="coerce").dropna())
                    if not lat.empty:
                        box_data.append(lat.values)
                        used_pos.append(ALL_POS[idx])
                        used_labs.append(ALL_LABS[idx])
                        colors.append(PT_COLORS[pt])

        if not box_data:
            ax.set_title(f"{domain.replace('_', ' ').title()}\n[no data]")
            continue

        bp = ax.boxplot(
            box_data, positions=used_pos, patch_artist=True, widths=0.55,
            medianprops={"color": "black", "linewidth": 2},
            flierprops={"marker": ".", "markersize": 2, "alpha": 0.25},
            whiskerprops={"linewidth": 1.2}, capprops={"linewidth": 1.2},
        )
        for patch, color in zip(bp["boxes"], colors):
            patch.set_facecolor(color)
            patch.set_alpha(0.65)

        ax.set_yscale("log")
        ax.set_xticks(used_pos)
        ax.set_xticklabels(used_labs, fontsize=8.5)
        ax.set_ylabel("Latency (ms, log scale)")
        ax.set_title(domain.replace("_", " ").title(), fontsize=11)

        # Scenario separator (only when both scenario groups are present)
        if any(p >= 3.0 for p in used_pos) and any(p < 3.0 for p in used_pos):
            ax.axvline(2.75, color="gray", linewidth=0.8, linestyle="--", alpha=0.5)

        patches = [
            mpatches.Patch(facecolor=PT_COLORS["adversarial"], alpha=0.7, label="Adversarial"),
            mpatches.Patch(facecolor=PT_COLORS["legitimate"],  alpha=0.7, label="Legitimate"),
        ]
        ax.legend(handles=patches, fontsize=8, loc="upper right")

    fig.suptitle(
        "Latency Distribution: Adversarial vs Legitimate Prompts (log scale)",
        fontweight="bold", fontsize=11,
    )
    fig.tight_layout()
    _save(fig, figures_dir, "latency_adv_vs_legit_boxplot.png")
    plt.close(fig)


def plot_latency_adv_vs_legit_kde(artifacts_dir: Path, domains: list, figures_dir: Path):
    """Overlaid KDE curves comparing adversarial and legitimate latency distributions.

    Produces a grid of subplots (rows = domains, columns = scenarios).  Within each
    cell, two KDE curves are overlaid — one per prompt type — together with dashed
    vertical lines at each distribution's median.  Subplots for which no data is
    available are hidden automatically.

    Parameters
    ----------
    artifacts_dir : Path
        Root artifacts directory containing ``consolidated_<domain>_<scenario>.csv``
        files.
    domains : list
        Ordered list of domain names; one row of subplots is created per domain.
    figures_dir : Path
        Directory where the output PNG is saved.

    Notes
    -----
    **KDE vs histogram:**
        Kernel Density Estimation produces a smooth, continuous density estimate
        that is easier to compare across groups than histogram bin counts, which
        are sensitive to bin width and alignment.  Pandas ``Series.plot.kde()``
        uses a Gaussian kernel with Scott's rule for bandwidth selection, which
        is appropriate for unimodal distributions.  The x-axis is clipped to zero
        (no negative latency); the right tail is left unconstrained to show
        heavy-tail behaviour.

    **Median lines:**
        Because the KDE may show a mode that differs from the median (right-skewed
        data), explicit median lines are drawn to anchor the visual comparison at
        the statistically preferred central-tendency measure.

    Outputs
    -------
    - artifacts/figures/latency_adv_vs_legit_kde.png : KDE grid figure, dpi=150.
    """
    import matplotlib.pyplot as plt
    setup_style()

    SCENARIOS  = ["unprotected", "protected"]
    SCEN_LABEL = {"unprotected": "A", "protected": "B"}
    PT_COLORS  = {"adversarial": "#C44E52", "legitimate": "#4C72B0"}

    n_dom  = len(domains)
    n_scen = len(SCENARIOS)
    fig, axes = plt.subplots(n_dom, n_scen, figsize=(7 * n_scen, 5 * n_dom), squeeze=False)

    any_data = False
    for i, domain in enumerate(domains):
        for j, scenario in enumerate(SCENARIOS):
            ax   = axes[i][j]
            path = artifacts_dir / f"consolidated_{domain}_{scenario}.csv"
            if not path.exists():
                ax.set_visible(False)
                continue
            df = pd.read_csv(path)
            if "latency_ms" not in df.columns or "prompt_type" not in df.columns:
                ax.set_visible(False)
                continue
            df["latency_ms"] = pd.to_numeric(df["latency_ms"], errors="coerce")
            plotted = False
            for pt in ("adversarial", "legitimate"):
                lat = df[df["prompt_type"] == pt]["latency_ms"].dropna()
                if lat.empty:
                    continue
                lat.plot.kde(ax=ax, color=PT_COLORS[pt], linewidth=2,
                             label=pt.capitalize())
                ax.axvline(lat.median(), color=PT_COLORS[pt], linewidth=1.2,
                           linestyle="--", alpha=0.7,
                           label=f"{pt[:3]}. median = {lat.median():.0f} ms")
                plotted   = True
                any_data  = True
            if plotted:
                ax.set_xlim(left=0)
                ax.set_xlabel("Latency (ms)")
                ax.set_ylabel("Density")
                ax.set_title(
                    f"{domain.replace('_', ' ').title()} — Scenario {SCEN_LABEL[scenario]}"
                )
                ax.legend(fontsize=8)
            else:
                ax.set_visible(False)

    if not any_data:
        print("  [skip] latency_adv_vs_legit_kde: no data.")
        plt.close(fig)
        return

    fig.suptitle("Latency KDE: Adversarial vs Legitimate Prompts",
                 fontweight="bold", fontsize=12)
    fig.tight_layout()
    _save(fig, figures_dir, "latency_adv_vs_legit_kde.png")
    plt.close(fig)


def plot_fpr_by_domain_scenario(artifacts_dir: Path, domains: list, figures_dir: Path):
    """Grouped bar chart of False Positive Rate (FPR) per domain and scenario.

    FPR is defined as the proportion of legitimate prompts incorrectly blocked by
    the security layer:

        FPR = legitimate_blocked / total_legitimate

    Scenario A (unprotected) has no active blocking mechanism, so its FPR is
    structurally zero by design; the bar is included to make the contrast with
    Scenario B explicit.  Each bar is annotated with its exact four-decimal FPR
    value to facilitate direct comparison across domains.

    Parameters
    ----------
    artifacts_dir : Path
        Root artifacts directory containing ``consolidated_<domain>_<scenario>.csv``
        files.  Only rows with ``prompt_type == "legitimate"`` are used.
    domains : list
        Ordered list of domain names; one group of bars per domain.
    figures_dir : Path
        Directory where the output PNG is saved.

    Notes
    -----
    FPR measures the cost of the security layer for legitimate users.  A high FPR
    means the guard incorrectly rejects valid queries, degrading the system's
    utility.  There is an inherent precision–recall trade-off: tightening scanner
    thresholds to reduce TFA false negatives typically increases FPR.

    Outputs
    -------
    - artifacts/figures/fpr_by_domain_scenario.png : grouped bar chart, dpi=150.
    """
    import matplotlib.pyplot as plt
    import numpy as np
    setup_style()

    SCENARIOS   = ["unprotected", "protected"]
    SCEN_LABELS = {"unprotected": "A (unprotected)", "protected": "B (LLM Guard)"}
    SCEN_COLORS = {"unprotected": "#4C72B0", "protected": "#DD8452"}

    fpr_data: dict[str, dict[str, float | None]] = {}
    for domain in domains:
        fpr_data[domain] = {}
        for scenario in SCENARIOS:
            path = artifacts_dir / f"consolidated_{domain}_{scenario}.csv"
            if not path.exists():
                fpr_data[domain][scenario] = None
                continue
            df    = pd.read_csv(path)
            legit = (df[df["prompt_type"] == "legitimate"].copy()
                     if "prompt_type" in df.columns else pd.DataFrame())
            if legit.empty or "was_blocked" not in legit.columns:
                fpr_data[domain][scenario] = None
                continue
            n  = len(legit)
            nb = int(pd.to_numeric(legit["was_blocked"], errors="coerce").fillna(0).sum())
            fpr_data[domain][scenario] = nb / n if n > 0 else 0.0

    x     = np.arange(len(domains))
    width = 0.35
    fig, ax = plt.subplots(figsize=(max(6, 3 * len(domains)), 5))

    for i, scenario in enumerate(SCENARIOS):
        vals = [fpr_data[d].get(scenario) or 0.0 for d in domains]
        orig = [fpr_data[d].get(scenario)         for d in domains]
        offset = (i - 0.5) * width
        bars = ax.bar(x + offset, vals, width,
                      label=SCEN_LABELS[scenario],
                      color=SCEN_COLORS[scenario], alpha=0.85, edgecolor="white")
        for bar, val, o in zip(bars, vals, orig):
            label = f"{val:.4f}" if o is not None else "N/A"
            ax.text(bar.get_x() + bar.get_width() / 2,
                    bar.get_height() + 0.001,
                    label, ha="center", va="bottom", fontsize=9, fontweight="bold")

    all_vals = [fpr_data[d].get(s) or 0.0 for d in domains for s in SCENARIOS]
    ax.set_ylim(0, max(all_vals) * 1.35 + 0.01)
    ax.set_xticks(x)
    ax.set_xticklabels([d.replace("_", " ").title() for d in domains], fontsize=10)
    ax.set_ylabel("False Positive Rate (FPR)")
    ax.set_title("FPR per Domain and Scenario\n"
                 "(Legitimate prompts incorrectly blocked by LLM Guard)")
    ax.axhline(0, color="black", linewidth=0.5)
    ax.legend(fontsize=9)

    fig.tight_layout()
    _save(fig, figures_dir, "fpr_by_domain_scenario.png")
    plt.close(fig)


def plot_tfa_heatmap_ab_comparison(tfa_by_domain: dict, figures_dir: Path):
    """Two-panel heatmap of TFA per probe (rows) × domain (columns), split by scenario.

    The left panel shows Scenario A (unprotected) and the right panel shows
    Scenario B (LLM Guard), sharing the same color scale (RdYlGn, 0.0 = red,
    1.0 = green) to allow direct visual comparison of the guard's contribution.
    Cells are annotated with the numeric TFA value; cells with no data are shown
    in gray.  The right panel is omitted when no Scenario B data is available.

    TFA values are sourced from the JSONL-based ``load_tfa_from_jsonl`` function
    (primary detector filtering applied) rather than from the consolidated CSVs,
    matching the methodology used in ``print_tfa``.

    Parameters
    ----------
    tfa_by_domain : dict
        Nested mapping ``{domain: {"A": tfa_dict, "B": tfa_dict}}`` as returned
        by ``load_tfa_from_jsonl``.  ``tfa_dict["per_probe"]`` is used.
    figures_dir : Path
        Directory where the output PNG is saved.

    Notes
    -----
    **Color thresholds:**
        Text inside cells is rendered in white when TFA < 0.30 (dark red, low
        contrast with black) or TFA > 0.72 (dark green, low contrast with black),
        and in black otherwise.  This preserves legibility across the full
        RdYlGn colour range without a fixed midpoint.

    Outputs
    -------
    - artifacts/figures/tfa_heatmap_ab_comparison.png : two-panel heatmap, dpi=150.
    """
    import matplotlib.pyplot as plt
    import numpy as np
    setup_style()

    domains = list(tfa_by_domain.keys())
    has_b   = any(tfa_by_domain[d]["B"] for d in domains)

    probe_sets = [set((tfa_by_domain[d]["A"] or {}).get("per_probe", {}).keys())
                  for d in domains]
    all_probes = sorted(set.union(*probe_sets) if probe_sets else set())
    if not all_probes:
        print("  [skip] tfa_heatmap_ab_comparison: no probe data.")
        return

    probe_labels  = [PROBE_SHORT.get(p, p) for p in all_probes]
    domain_labels = [d.replace("_", " ").title() for d in domains]
    n_panels      = 2 if has_b else 1

    fig_w = 2.5 + len(domains) * 1.8
    fig, axes = plt.subplots(
        1, n_panels,
        figsize=(fig_w * n_panels, 2.5 + len(all_probes) * 0.55),
        sharey=True,
    )
    if n_panels == 1:
        axes = [axes]

    def _build(scenario_key: str) -> np.ndarray:
        mat = np.full((len(all_probes), len(domains)), np.nan)
        for j, domain in enumerate(domains):
            tfa_d = tfa_by_domain[domain].get(scenario_key) or {}
            for i, probe in enumerate(all_probes):
                v = (tfa_d.get("per_probe") or {}).get(probe, {}).get("TFA")
                if v is not None:
                    mat[i, j] = v
        return mat

    def _draw(ax, mat: np.ndarray, title: str):
        cmap = plt.cm.RdYlGn.copy()
        cmap.set_bad("#dddddd")
        im = ax.imshow(np.ma.masked_invalid(mat), cmap=cmap,
                       vmin=0, vmax=1, aspect="auto")
        ax.set_xticks(range(len(domains)))
        ax.set_xticklabels(domain_labels, fontsize=9, rotation=20, ha="right")
        ax.set_yticks(range(len(all_probes)))
        ax.set_yticklabels(probe_labels, fontsize=8.5)
        ax.set_xlabel("Domain")
        ax.set_title(title, fontsize=11, fontweight="bold")
        for i in range(len(all_probes)):
            for j in range(len(domains)):
                val = mat[i, j]
                if not np.isnan(val):
                    tc = "white" if (val < 0.3 or val > 0.72) else "black"
                    ax.text(j, i, f"{val:.2f}", ha="center", va="center",
                            fontsize=8, color=tc)
                else:
                    ax.text(j, i, "N/A", ha="center", va="center",
                            fontsize=7, color="#aaaaaa")
        return im

    im = _draw(axes[0], _build("A"), "Scenario A (unprotected)")
    if has_b:
        _draw(axes[1], _build("B"), "Scenario B (LLM Guard)")

    fig.colorbar(im, ax=axes[-1], label="TFA (Attack Filtering Rate)", shrink=0.7)
    fig.suptitle("TFA Heatmap: Probe × Domain — Scenario A vs B",
                 fontweight="bold", fontsize=12)
    fig.tight_layout()
    _save(fig, figures_dir, "tfa_heatmap_ab_comparison.png")
    plt.close(fig)


def plot_delta_tfa_by_domain(tfa_by_domain: dict, figures_dir: Path):
    """Grouped bar chart of ΔTFA per probe, coloured by domain.

    ΔTFA = TFA_B − TFA_A measures the net change in attack filtering rate
    attributable to LLM Guard.  A positive ΔTFA indicates that the shield improved
    resistance for that probe; a negative value indicates that the shield degraded
    resistance (e.g. due to scanner-induced response truncation or bypass).  Each
    probe gets one bar group, with one bar per domain offset side by side.

    This function produces the same chart as the existing ``plot_delta_tfa`` but
    saves to ``delta_tfa_by_probe_by_domain.png`` as required by the segmented
    analysis output specification.  The function is skipped silently when no
    Scenario B data is available.

    Parameters
    ----------
    tfa_by_domain : dict
        Nested mapping ``{domain: {"A": tfa_dict, "B": tfa_dict}}`` as returned
        by ``load_tfa_from_jsonl``.
    figures_dir : Path
        Directory where the output PNG is saved.

    Notes
    -----
    Probes for which either TFA_A or TFA_B is ``None`` (e.g. detector absent in
    one run) contribute a ΔTFA of 0 rather than being omitted, to preserve the
    full x-axis layout and avoid misleading gaps.

    Outputs
    -------
    - artifacts/figures/delta_tfa_by_probe_by_domain.png : grouped bar chart, dpi=150.
    """
    import matplotlib.pyplot as plt
    import numpy as np
    has_b = any(tfa_by_domain[d]["B"] for d in tfa_by_domain)
    if not has_b:
        print("  [skip] delta_tfa_by_domain: Scenario B data required.")
        return
    setup_style()

    probes = sorted(next(iter(tfa_by_domain.values()))["A"]["per_probe"].keys())
    labels = [PROBE_SHORT.get(p, p) for p in probes]
    fig, ax = plt.subplots(figsize=(13, 5))
    x     = np.arange(len(probes))
    width = 0.35
    domain_colors = ["#4C72B0", "#DD8452"]

    for i, (domain, color) in enumerate(zip(tfa_by_domain.keys(), domain_colors)):
        tfa_a = tfa_by_domain[domain]["A"]
        tfa_b = tfa_by_domain[domain]["B"]
        if not tfa_b:
            continue
        deltas = [
            ((tfa_b["per_probe"].get(p, {}).get("TFA") or 0)
             - (tfa_a["per_probe"].get(p, {}).get("TFA") or 0))
            if (tfa_a["per_probe"].get(p, {}).get("TFA") is not None
                and tfa_b["per_probe"].get(p, {}).get("TFA") is not None)
            else 0
            for p in probes
        ]
        offset = (i - 0.5) * width
        ax.bar(x + offset, deltas, width,
               label=domain.replace("_", " ").title(),
               color=color, alpha=0.8, edgecolor="white")

    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=35, ha="right", fontsize=9)
    ax.axhline(0, color="black", linewidth=0.8)
    ax.set_xlabel("Probe")
    ax.set_ylabel("ΔTFA (Scenario B − Scenario A)")
    ax.set_title("ΔTFA per Probe by Domain — LLM Guard Net Contribution")
    ax.legend(fontsize=9, title="Domain")
    fig.tight_layout()
    _save(fig, figures_dir, "delta_tfa_by_probe_by_domain.png")
    plt.close(fig)


def plot_scanner_breakdown_by_probe(artifacts_dir: Path, domains: list, figures_dir: Path):
    """Stacked bar chart of scanner activations per probe for Scenario B adversarial prompts.

    For each probe (x-axis), bars are stacked by the ``scanner_triggered`` value
    recorded in the consolidated CSV, showing how many adversarial requests
    activated each LLM Guard scanner (or none).  One subplot is created per domain.
    Only Scenario B (``consolidated_<domain>_protected.csv``) is used because
    Scenario A has no scanner layer.

    Parameters
    ----------
    artifacts_dir : Path
        Root artifacts directory.  Reads
        ``consolidated_<domain>_protected.csv`` for each domain.
    domains : list
        Ordered list of domain names; one subplot per domain.
    figures_dir : Path
        Directory where the output PNG is saved.

    Notes
    -----
    Rows where ``scanner_triggered`` is NaN (request processed without any
    scanner firing) are recoded to the label ``"(none)"`` so they appear as an
    explicit stack segment rather than being silently excluded.  The colour
    palette uses ``matplotlib.cm.tab10``, which provides up to 10 visually
    distinct colours for scanner categories.

    Outputs
    -------
    - artifacts/figures/scanner_breakdown_by_probe.png : stacked bar chart, dpi=150.
    """
    import matplotlib.pyplot as plt
    import numpy as np
    setup_style()

    n_dom = len(domains)
    if n_dom == 0:
        return

    fig, axes = plt.subplots(1, n_dom, figsize=(max(10, 6 * n_dom), 6), squeeze=False)
    any_data = False

    for ax, domain in zip(axes[0], domains):
        path = artifacts_dir / f"consolidated_{domain}_protected.csv"
        if not path.exists():
            ax.set_title(f"{domain.replace('_', ' ').title()}\n[no Scenario B data]")
            ax.set_visible(False)
            continue
        df = pd.read_csv(path)
        if "prompt_type" in df.columns:
            df = df[df["prompt_type"] == "adversarial"].copy()
        if df.empty or "probe" not in df.columns or "scanner_triggered" not in df.columns:
            ax.set_title(f"{domain.replace('_', ' ').title()}\n[missing columns]")
            ax.set_visible(False)
            continue

        df["scanner_triggered"] = df["scanner_triggered"].fillna("(none)")
        df["probe_short"] = df["probe"].map(PROBE_SHORT).fillna(df["probe"])

        pivot = (df.groupby(["probe_short", "scanner_triggered"])
                   .size()
                   .unstack(fill_value=0))

        probes_ord   = list(pivot.index)
        scanner_cats = list(pivot.columns)
        x_pos        = np.arange(len(probes_ord))
        tab_colors   = plt.cm.tab10.colors

        bottoms = np.zeros(len(probes_ord), dtype=float)
        for k, scanner in enumerate(scanner_cats):
            vals = pivot[scanner].values.astype(float)
            ax.bar(x_pos, vals, bottom=bottoms,
                   label=str(scanner),
                   color=tab_colors[k % len(tab_colors)],
                   alpha=0.85, edgecolor="white")
            bottoms += vals

        ax.set_xticks(x_pos)
        ax.set_xticklabels(probes_ord, rotation=35, ha="right", fontsize=8.5)
        ax.set_xlabel("Probe")
        ax.set_ylabel("Adversarial prompts (count)")
        ax.set_title(domain.replace("_", " ").title())
        ax.legend(title="Scanner triggered", fontsize=7.5, loc="upper right")
        any_data = True

    if not any_data:
        print("  [skip] scanner_breakdown_by_probe: no Scenario B adversarial data.")
        plt.close(fig)
        return

    fig.suptitle(
        "Scanner Triggered Breakdown per Probe\nScenario B — Adversarial Prompts",
        fontweight="bold",
    )
    fig.tight_layout()
    _save(fig, figures_dir, "scanner_breakdown_by_probe.png")
    plt.close(fig)


def generate_segmented_plots(
    artifacts_dir: Path, domains: list, tfa_by_domain: dict, figures_dir: Path
):
    """Generate all six supplementary segmented-analysis figures and save them to disk.

    Orchestrates the six plot functions added to complement
    ``generate_all_plots``.  Each function is called in sequence; individual
    functions print ``[skip]`` messages when their required data is absent and
    return without raising an exception, so the overall pipeline is resilient to
    partially collected data.

    Requires ``matplotlib`` to be installed.  Uses ``matplotlib.use("Agg")`` to
    suppress any interactive display (safe for headless / Docker environments).

    Parameters
    ----------
    artifacts_dir : Path
        Root artifacts directory containing ``consolidated_*.csv`` files.
    domains : list
        Ordered list of domain names to include in domain-level subplots.
    tfa_by_domain : dict
        Nested mapping ``{domain: {"A": tfa_dict, "B": tfa_dict}}`` as returned
        by ``load_tfa_from_jsonl``, used by the TFA heatmap and ΔTFA chart.
    figures_dir : Path
        Directory where all output PNGs are saved (created if absent).

    Outputs
    -------
    - artifacts/figures/latency_adv_vs_legit_boxplot.png : boxplots per domain ×
      scenario, comparing adversarial and legitimate latency (log scale).
    - artifacts/figures/latency_adv_vs_legit_kde.png : KDE curves per domain ×
      scenario overlay for adversarial vs legitimate latency.
    - artifacts/figures/fpr_by_domain_scenario.png : FPR grouped bar chart per
      domain, Scenario A vs B.
    - artifacts/figures/tfa_heatmap_ab_comparison.png : side-by-side TFA heatmaps
      (probe × domain) for Scenario A and Scenario B.
    - artifacts/figures/delta_tfa_by_probe_by_domain.png : ΔTFA grouped bars per
      probe, coloured by domain.
    - artifacts/figures/scanner_breakdown_by_probe.png : stacked bars of scanner
      activations per probe (Scenario B adversarial).
    """
    print(f"\n  GENERATING SEGMENTED FIGURES → {figures_dir}")
    print(f"  {'-'*60}")

    try:
        import matplotlib
        matplotlib.use("Agg")
    except ImportError:
        print("  [ERROR] matplotlib not installed.")
        return

    plot_latency_adv_vs_legit_boxplot(artifacts_dir, domains, figures_dir)
    plot_latency_adv_vs_legit_kde(artifacts_dir, domains, figures_dir)
    plot_fpr_by_domain_scenario(artifacts_dir, domains, figures_dir)
    plot_tfa_heatmap_ab_comparison(tfa_by_domain, figures_dir)
    plot_delta_tfa_by_domain(tfa_by_domain, figures_dir)
    plot_scanner_breakdown_by_probe(artifacts_dir, domains, figures_dir)

    n = len(list(figures_dir.glob("*.png")))
    print(f"\n  Segmented figures complete. {n} total figures in {figures_dir}.\n")


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
    args = parser.parse_args()

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
    tfa_by_domain = {}
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
        print_tfa(tfa_a, tfa_b, domain)

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


    print(f"\n{'='*70}\n")

    # ── Figures ─────────────────────────────────────────────
    if args.plots:
        generate_all_plots(tfa_by_domain, lat_a, lat_b, artifacts, runs_dir, figures_dir)
        generate_segmented_plots(artifacts, domains, tfa_by_domain, figures_dir)


if __name__ == "__main__":
    main()