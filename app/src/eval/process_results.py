#!/usr/bin/env python3
"""
process_results.py
==================
Computes TFA and LAS metrics from LLM-Sec experiment artifacts.

Sources:
  - TFA : artifacts/consolidated_<domain>_<scenario>.csv
  - LAS : artifacts/latency/latency_unprotected_direct.csv
           artifacts/latency/latency_protected.csv

garak_passed convention:
  1 → system resisted the attack (defensive TP)
  0 → attack succeeded           (defensive FN)

TFA = count(garak_passed == 1) / count(adversarial) per vector

Usage:
  python process_results.py --artifacts artifacts/

Requires: pandas, scipy
  pip install pandas scipy --break-system-packages
"""

import argparse
from pathlib import Path

import pandas as pd
from scipy.stats import fisher_exact, mannwhitneyu


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def load_consolidated(artifacts_dir: Path, domain: str, scenario: str) -> pd.DataFrame:
    path = artifacts_dir / f"consolidated_{domain}_{scenario}.csv"
    if not path.exists():
        print(f"  [WARN] Not found: {path}")
        return pd.DataFrame()
    df = pd.read_csv(path)
    # Keep only adversarial rows with garak_passed filled
    df = df[df["prompt_type"] == "adversarial"].copy()
    df = df[df["garak_passed"].notna() & (df["garak_passed"] != "")].copy()
    df["garak_passed"] = df["garak_passed"].astype(int)
    return df


def load_latency(latency_dir: Path, filename: str) -> pd.DataFrame:
    path = latency_dir / filename
    if not path.exists():
        print(f"  [WARN] Not found: {path}")
        return pd.DataFrame()
    df = pd.read_csv(path, header=None, names=[
        "timestamp", "scenario", "domain", "method",
        "endpoint", "status_code", "latency_ms",
        "col8", "suite_probe", "prompt_tokens", "response_tokens"
    ])
    # Keep only /generate requests, exclude healthchecks
    df = df[df["endpoint"] == "/generate"].copy()
    df["latency_ms"] = pd.to_numeric(df["latency_ms"], errors="coerce")
    df = df[df["latency_ms"].notna()]
    return df


# ─────────────────────────────────────────────
# TFA
# ─────────────────────────────────────────────

VECTOR_MAP = {
    "LLM01": "D1 — Input protection",
    "LLM02": "D2 — RAG context control",
    "LLM07": "D3 — Output management",
    "LLM08": "D4 — Monitoring & traceability",
}


def compute_tfa(df: pd.DataFrame, label: str) -> dict:
    """
    Computes TFA globally and per OWASP vector.
    TFA = TP / (TP + FN) = garak_passed==1 / total_adversarial
    """
    if df.empty:
        return {}

    results = {"label": label}

    # Global TFA
    total = len(df)
    tp = (df["garak_passed"] == 1).sum()
    fn = (df["garak_passed"] == 0).sum()
    results["global"] = {
        "total": int(total),
        "TP": int(tp),
        "FN": int(fn),
        "TFA": round(tp / total, 4) if total > 0 else None,
    }

    # TFA per vector
    results["per_vector"] = {}
    for suite, desc in VECTOR_MAP.items():
        sub = df[df["suite"] == suite]
        if sub.empty:
            continue
        t = len(sub)
        p = (sub["garak_passed"] == 1).sum()
        f = (sub["garak_passed"] == 0).sum()
        results["per_vector"][suite] = {
            "description": desc,
            "total": int(t),
            "TP": int(p),
            "FN": int(f),
            "TFA": round(p / t, 4) if t > 0 else None,
        }

    return results


def print_tfa(tfa_a: dict, tfa_b: dict, domain: str):
    print(f"\n{'='*65}")
    print(f"  TFA — {domain.upper()}")
    print(f"{'='*65}")

    if not tfa_a:
        print("  [WARN] Insufficient data.")
        return

    g_a = tfa_a["global"]
    g_b = tfa_b.get("global") if tfa_b else None

    print(f"\n  GLOBAL")
    print(f"  {'':30s} {'Scenario A':>12} {'Scenario B':>12}")
    print(f"  {'Total adversarial':30s} {g_a['total']:>12}", end="")
    print(f" {g_b['total']:>12}" if g_b else "")
    print(f"  {'TP (resisted)':30s} {g_a['TP']:>12}", end="")
    print(f" {g_b['TP']:>12}" if g_b else "")
    print(f"  {'FN (attack succeeded)':30s} {g_a['FN']:>12}", end="")
    print(f" {g_b['FN']:>12}" if g_b else "")
    print(f"  {'TFA':30s} {g_a['TFA']:>12.4f}", end="")
    if g_b:
        delta = round(g_b["TFA"] - g_a["TFA"], 4)
        print(f" {g_b['TFA']:>12.4f}  ΔTFA={delta:+.4f}")
    else:
        print()

    # Fisher exact test A vs B
    if g_b:
        table = [[g_a["TP"], g_a["FN"]], [g_b["TP"], g_b["FN"]]]
        odds, p_val = fisher_exact(table, alternative="less")
        sig = "✅ significant (α=0.05)" if p_val < 0.05 else "⚠️  not significant"
        print(f"\n  Fisher exact (global): OR={odds:.4f}  p={p_val:.6f}  {sig}")

    # Per vector
    print(f"\n  PER VECTOR")
    print(f"  {'Description':28s} {'Suite':6s} {'TFA_A':>8} {'TFA_B':>8} {'ΔTFA':>8} {'p-value':>10}")
    print(f"  {'-'*62}")

    for suite, desc in VECTOR_MAP.items():
        va = tfa_a["per_vector"].get(suite)
        vb = tfa_b["per_vector"].get(suite) if tfa_b else None
        if va is None:
            continue
        tfa_a_str = f"{va['TFA']:.4f}" if va["TFA"] is not None else "N/A"
        tfa_b_str = f"{vb['TFA']:.4f}" if (vb and vb["TFA"] is not None) else "N/A"
        delta_str = ""
        p_str = ""
        if vb and va["TFA"] is not None and vb["TFA"] is not None:
            delta = vb["TFA"] - va["TFA"]
            delta_str = f"{delta:+.4f}"
            _, p = fisher_exact([[va["TP"], va["FN"]], [vb["TP"], vb["FN"]]], alternative="less")
            p_str = f"{p:.6f}"
        print(f"  {desc[:28]:28s} {suite:6s} {tfa_a_str:>8} {tfa_b_str:>8} {delta_str:>8} {p_str:>10}")


# ─────────────────────────────────────────────
# LAS
# ─────────────────────────────────────────────

def compute_las(lat_a: pd.DataFrame, lat_b: pd.DataFrame):
    """
    LAS = median latency difference between Scenario B and Scenario A.
    Statistical test: Mann-Whitney U (non-parametric).
    """
    if lat_a.empty or lat_b.empty:
        print("  [WARN] Insufficient latency data.")
        return

    a_vals = lat_a["latency_ms"].values
    b_vals = lat_b["latency_ms"].values

    med_a = pd.Series(a_vals).median()
    med_b = pd.Series(b_vals).median()
    std_a = pd.Series(a_vals).std()
    std_b = pd.Series(b_vals).std()
    las = med_b - med_a

    stat, p_val = mannwhitneyu(a_vals, b_vals, alternative="less")
    sig = "✅ significant (α=0.05)" if p_val < 0.05 else "⚠️  not significant"

    print(f"\n{'='*65}")
    print(f"  LAS — Aggregate Security Latency")
    print(f"{'='*65}")
    print(f"\n  {'':30s} {'Scenario A':>12} {'Scenario B':>12}")
    print(f"  {'n requests':30s} {len(a_vals):>12} {len(b_vals):>12}")
    print(f"  {'Median (ms)':30s} {med_a:>12.3f} {med_b:>12.3f}")
    print(f"  {'Std deviation (ms)':30s} {std_a:>12.3f} {std_b:>12.3f}")
    print(f"\n  LAS (Δmedian B - A) = {las:+.3f} ms")
    print(f"  Mann-Whitney U = {stat:.1f}  p = {p_val:.6f}  {sig}")


def compute_las_by_domain(lat_a: pd.DataFrame, lat_b: pd.DataFrame):
    """LAS broken down by domain (exploratory, complementary analysis)."""
    if lat_a.empty or lat_b.empty:
        return
    print(f"\n  LAS BY DOMAIN (exploratory)")
    print(f"  {'Domain':35s} {'Med_A':>8} {'Med_B':>8} {'Δ':>8}")
    print(f"  {'-'*60}")
    domains = set(lat_a["domain"].dropna().unique()) | set(lat_b["domain"].dropna().unique())
    for domain in sorted(domains):
        sub_a = lat_a[lat_a["domain"] == domain]["latency_ms"]
        sub_b = lat_b[lat_b["domain"] == domain]["latency_ms"]
        if sub_a.empty or sub_b.empty:
            continue
        delta = sub_b.median() - sub_a.median()
        print(f"  {domain:35s} {sub_a.median():>8.3f} {sub_b.median():>8.3f} {delta:>+8.3f}")


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

DOMAINS = ["regulatory_technical", "academic_institutional"]


def main():
    parser = argparse.ArgumentParser(description="LLM-Sec results processing")
    parser.add_argument("--artifacts", type=Path, default=Path("artifacts"),
                        help="Path to artifacts/ directory (default: artifacts/)")
    args = parser.parse_args()

    artifacts = args.artifacts
    latency_dir = artifacts / "latency"

    print(f"\n{'='*65}")
    print(f"  LLM-Sec RESULTS PROCESSING")
    print(f"  Artifacts: {artifacts.resolve()}")
    print(f"{'='*65}")

    # ── TFA per domain ───────────────────────────────────────
    for domain in DOMAINS:
        df_a = load_consolidated(artifacts, domain, "unprotected")
        df_b = load_consolidated(artifacts, domain, "protected")

        tfa_a = compute_tfa(df_a, "Scenario A") if not df_a.empty else {}
        tfa_b = compute_tfa(df_b, "Scenario B") if not df_b.empty else {}

        print_tfa(tfa_a, tfa_b, domain)

    # ── LAS global ──────────────────────────────────────────
    lat_a = load_latency(latency_dir, "latency_unprotected_direct.csv")
    lat_b = load_latency(latency_dir, "latency_protected.csv")

    compute_las(lat_a, lat_b)
    compute_las_by_domain(lat_a, lat_b)

    print(f"\n{'='*65}\n")


if __name__ == "__main__":
    main()