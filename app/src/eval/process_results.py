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
from scipy.stats import fisher_exact, mannwhitneyu


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
# Data loading
# ─────────────────────────────────────────────

def load_tfa_from_jsonl(garak_dir: Path) -> dict:
    """Computes TFA per probe and suite from *.report.jsonl files."""
    per_probe: dict[str, dict] = defaultdict(lambda: {"passed": 0, "total": 0})

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
                probe    = obj.get("probe", "unknown")
                detector = obj.get("detector", "")
                passed   = obj.get("passed", 0)
                total    = obj.get("total", 0)
                primary  = PRIMARY_DETECTOR.get(probe)
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


def load_consolidated(artifacts_dir: Path, domain: str, scenario: str) -> pd.DataFrame:
    """Loads consolidated CSV for a domain/scenario, adversarial rows only."""
    path = artifacts_dir / f"consolidated_{domain}_{scenario}.csv"
    if not path.exists():
        return pd.DataFrame()
    df = pd.read_csv(path)
    df = df[df["prompt_type"] == "adversarial"].copy()
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
    def extract_suite(val):
        if pd.isna(val):
            return "UNKNOWN"
        return str(val).split("|")[0] if "|" in str(val) else "UNKNOWN"

    lat_a = lat_a.copy()
    lat_a["suite"] = lat_a["suite_probe"].apply(extract_suite)

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
        lat_b["suite"] = lat_b["suite_probe"].apply(extract_suite)
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
# Visualization
# ─────────────────────────────────────────────

def setup_style():
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
    figures_dir.mkdir(parents=True, exist_ok=True)
    path = figures_dir / filename
    fig.savefig(path, bbox_inches="tight")
    print(f"  [saved] {path}")


def plot_tfa_by_probe(tfa_a: dict, tfa_b: dict, domain: str, figures_dir: Path):
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


def plot_las_boxplot(lat_a: pd.DataFrame, lat_b: pd.DataFrame, figures_dir: Path):
    import matplotlib.pyplot as plt
    if lat_a.empty or lat_b.empty:
        print("  [skip] LAS boxplot requires both scenarios.")
        return
    setup_style()
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


def plot_las_boxplot_by_domain(lat_a: pd.DataFrame, lat_b: pd.DataFrame, figures_dir: Path):
    import matplotlib.pyplot as plt
    if lat_a.empty or lat_b.empty:
        print("  [skip] LAS domain boxplot requires both scenarios.")
        return
    setup_style()
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
    plt.close(fig)

def plot_latency_histogram(lat_a: pd.DataFrame, lat_b: pd.DataFrame, figures_dir: Path):
    """Latency histogram with KDE — Scenario A vs B."""
    import matplotlib.pyplot as plt
    if lat_a.empty:
        return
    setup_style()

    fig, ax = plt.subplots(figsize=(9, 5))
    lat_a["latency_ms"].plot.hist(
        bins=80, alpha=0.5, color=SCENARIO_COLORS["A"],
        label="Scenario A", density=True, ax=ax
    )
    lat_a["latency_ms"].plot.kde(
        color=SCENARIO_COLORS["A"], linewidth=2, ax=ax
    )
    if not lat_b.empty:
        lat_b["latency_ms"].plot.hist(
            bins=80, alpha=0.5, color=SCENARIO_COLORS["B"],
            label="Scenario B", density=True, ax=ax
        )
        lat_b["latency_ms"].plot.kde(
            color=SCENARIO_COLORS["B"], linewidth=2, ax=ax
        )

    ax.set_xlabel("Latency (ms)")
    ax.set_ylabel("Density")
    ax.set_title("Latency Distribution — Histogram + KDE")
    ax.legend(fontsize=9)
    _save(fig, figures_dir, "las_histogram_kde.png")
    plt.close(fig)

def plot_las_by_suite(lat_a: pd.DataFrame, lat_b: pd.DataFrame, figures_dir: Path):
    import matplotlib.pyplot as plt
    import numpy as np
    if lat_a.empty:
        print("  [skip] LAS by suite requires Scenario A latency data.")
        return
    setup_style()

    def extract_suite(val):
        if pd.isna(val):
            return "UNKNOWN"
        return str(val).split("|")[0] if "|" in str(val) else "UNKNOWN"

    lat_a = lat_a.copy()
    lat_a["suite"] = lat_a["suite_probe"].apply(extract_suite)
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
            lat_b_copy["suite"] = lat_b_copy["suite_probe"].apply(extract_suite)
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

    def extract_suite(val):
        if pd.isna(val):
            return "UNKNOWN"
        return str(val).split("|")[0] if "|" in str(val) else "UNKNOWN"

    lat_a = lat_a.copy()
    lat_a["suite"] = lat_a["suite_probe"].apply(extract_suite)
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


def generate_all_plots(tfa_by_domain: dict, lat_a: pd.DataFrame,
                       lat_b: pd.DataFrame, artifacts_dir: Path, figures_dir: Path):
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
    plot_las_boxplot_by_domain(lat_a, lat_b, figures_dir)
    plot_latency_histogram(lat_a, lat_b, figures_dir)
    plot_las_by_suite(lat_a, lat_b, figures_dir)
    plot_latency_distribution_by_suite(lat_a, figures_dir)

    n = len(list(figures_dir.glob("*.png")))
    print(f"\n  Done. {n} figures saved.\n")


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

    # ── Deep analysis ────────────────────────────────────────
    if args.deep:
        for domain in domains:
            df_a = load_consolidated(artifacts, domain, "unprotected")
            df_b = load_consolidated(artifacts, domain, "protected")
            deep_analysis_tfa(df_a, df_b, domain)
        deep_analysis_las(lat_a, lat_b)

    print(f"\n{'='*70}\n")

    # ── Figures ─────────────────────────────────────────────
    if args.plots:
        generate_all_plots(tfa_by_domain, lat_a, lat_b, artifacts, figures_dir)


if __name__ == "__main__":
    main()