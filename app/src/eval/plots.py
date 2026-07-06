"""Figure generation for evaluation results.

Renders the experiment's matplotlib figures (TFA/LAS comparisons, confusion
matrices, latency distributions, scanner/detector breakdowns, etc.) and
saves them as PNGs under ``artifacts/figures/``. ``generate_all_plots`` and
``generate_segmented_plots`` are the entry points used by ``main()``.
"""

from collections import defaultdict
from pathlib import Path

import pandas as pd
from scipy.stats import fisher_exact, mannwhitneyu

from eval.constants import (
    PRIMARY_DETECTOR,
    PROBE_SHORT,
    PROBE_TO_SUITE,
    SCENARIO_COLORS,
    SUITE_COLORS,
    SUITE_TO_SUBDIM,
    VECTOR_MAP,
)
from eval.loaders import (
    _confusion_counts,
    _confusion_counts_system,
    _extract_suite,
    _load_consolidated_legit,
    _load_jsonl_eval_entries,
    find_run_dir,
    load_consolidated,
    load_tfa_from_jsonl,
)
from eval.metrics import (
    compute_tfa_by_suite,
    compute_tfa_global,
    compute_tfa_per_probe,
    compute_probe_timings,
    print_tfa,
)


# ─────────────────────────────────────────────
# Spanish display labels (figures only — data/column names stay in English)
# ─────────────────────────────────────────────

_DOMAIN_LABELS_ES = {
    "academic_institutional": "Académico-Institucional",
    "regulatory_technical": "Regulatorio-Técnico",
}

_SUBDIM_LABELS_ES = {
    "LLM01": "D1 — Protección de entradas",
    "LLM02": "D2 — Control del contexto RAG",
    "LLM07": "D3 — Gestión de salidas",
    "LLM08": "D4 — Monitoreo y trazabilidad",
}

# Ground-truth source per suite, shown as a footnote on suite-level TFA bar
# charts when CSV-based (compute_tfa_by_suite) values are plotted, since
# garak_passed alone is only a valid ground truth for LLM01.
_TFA_GT_SOURCE_NOTE = (
    "Fuente GT: LLM01=garak_passed | LLM02=response_has_confidential | "
    "LLM07=response_has_system_prompt | LLM08=injection_followed"
)


def _domain_label(domain: str) -> str:
    """Spanish display label for a domain name (figure titles/ticks)."""
    return _DOMAIN_LABELS_ES.get(domain, domain.replace("_", " ").title())


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


_SUITE_GT_COL = {
    "LLM01": "rogue_string_found",
    "LLM02": "response_has_confidential",
    "LLM07": "response_has_system_prompt",
    "LLM08": "injection_followed",
}


def _build_corrected_tfa(artifacts_dir: Path, tfa_by_domain: dict) -> dict:
    """Build a tfa_by_domain-shaped dict with per-probe and per-suite TFA values
    sourced from consolidated CSVs using the correct ground-truth column per suite.

    The JSONL-based tfa_by_domain uses garak_passed as TFA proxy. This is wrong
    for non-LLM01 suites (Garak lacks corpus/system-prompt access) and also wrong
    for Scenario B LLM01 (LLM Guard blocks produce garak_passed=0 but the absence
    of a rogue string means the attack failed, so TFA=1). This function replaces
    those values with correct CSV-based computations via compute_tfa_per_probe and
    compute_tfa_by_suite, preserving the same nested dict structure so callers
    need no structural changes.

    Returns:
        {domain: {"A": corrected_tfa_dict, "B": corrected_tfa_dict}} where each
        corrected_tfa_dict has per_probe, per_suite (with total/passed counts for
        Fisher tests), and global=None.
    """
    corrected: dict = {}
    scenario_map = {"A": "unprotected", "B": "protected"}

    for domain, data in tfa_by_domain.items():
        corrected[domain] = {}
        for scenario_key, scenario_tag in scenario_map.items():
            jsonl_d = data.get(scenario_key) or {}
            if not jsonl_d:
                corrected[domain][scenario_key] = {}
                continue

            df = load_consolidated(artifacts_dir, domain, scenario_tag)

            # Per-probe TFA with correct GT column per suite
            per_probe: dict = {}
            for probe in jsonl_d.get("per_probe", {}):
                if df.empty:
                    tfa_val = float("nan")
                else:
                    tfa_val = compute_tfa_per_probe(df, probe)
                per_probe[probe] = {
                    "TFA": round(float(tfa_val), 4) if not pd.isna(tfa_val) else None,
                    "suite": PROBE_TO_SUITE.get(probe, "UNKNOWN"),
                }

            # Per-suite TFA with exact TP/FN counts for Fisher tests
            per_suite: dict = {}
            for suite, gt_col in _SUITE_GT_COL.items():
                if df.empty or gt_col not in df.columns:
                    per_suite[suite] = {"TFA": None, "total": 0, "passed": 0, "suite": suite}
                    continue
                adv = df[df["suite"] == suite] if "suite" in df.columns else pd.DataFrame()
                total = len(adv)
                if total == 0:
                    per_suite[suite] = {"TFA": None, "total": 0, "passed": 0, "suite": suite}
                    continue
                try:
                    tfa_val = compute_tfa_by_suite(df, suite)
                except (KeyError, ValueError):
                    tfa_val = float("nan")
                if pd.isna(tfa_val):
                    per_suite[suite] = {"TFA": None, "total": total, "passed": 0, "suite": suite}
                else:
                    # Exact TP count: 1 - mean(gt_col) → passed = total - sum(gt_col)
                    passed = int(total - adv[gt_col].astype(float).fillna(0).sum())
                    per_suite[suite] = {
                        "TFA": round(float(tfa_val), 4),
                        "total": total,
                        "passed": passed,
                        "suite": suite,
                    }

            corrected[domain][scenario_key] = {
                "per_probe": per_probe,
                "per_suite": per_suite,
                "global": None,
            }

    return corrected


def plot_tfa_by_probe(tfa_a: dict, tfa_b: dict, domain: str, figures_dir: Path):
    """Bar chart of TFA per probe, coloured by OWASP suite, with optional Scenario B overlay.

    Receives corrected per-probe TFA values (computed via ``compute_tfa_per_probe``
    from consolidated CSVs) rather than the JSONL-based garak_passed proxy. The
    corrected values use suite-specific ground truth columns so that Scenario B
    values are accurate even when LLM Guard blocks requests before they reach the
    model (blocking → garak_passed=0 but TFA=1 for LLM01; non-LLM01 suites also
    require their own GT columns).

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
           label="Escenario A",
           color=[SUITE_COLORS.get(s, "#888") for s in suites],
           alpha=0.85, edgecolor="white")
    if vals_b:
        ax.bar(x + width/2, vals_b, width, label="Escenario B",
               color=[SUITE_COLORS.get(s, "#888") for s in suites],
               alpha=0.45, edgecolor="white", hatch="//")

    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=35, ha="right", fontsize=9)
    ax.set_ylim(0, 1.08)
    ax.set_ylabel("TFA (Tasa de Filtrado de Ataques)")
    ax.set_title(f"TFA por sonda — {_domain_label(domain)}")
    ax.axhline(1.0, color="gray", linewidth=0.8, linestyle="--", alpha=0.5)

    suite_patches = [mpatches.Patch(color=c, label=s) for s, c in SUITE_COLORS.items()]
    legend1 = ax.legend(handles=suite_patches, title="Suite OWASP",
                        loc="lower left", fontsize=8)
    ax.add_artist(legend1)
    if vals_b:
        ax.legend(loc="lower right", fontsize=8)

    fig.text(0.5, -0.04,
             "Nota: TFA por sonda usa la columna de verdad-terreno correcta por suite OWASP "
             "(rogue_string_found / response_has_confidential / response_has_system_prompt / injection_followed).",
             ha="center", va="top", fontsize=7.5, style="italic", color="#555555")

    _save(fig, figures_dir, f"tfa_by_probe_{domain}.png")
    plt.close(fig)


def plot_tfa_by_suite(tfa_a: dict, tfa_b: dict, domain: str, figures_dir: Path,
                      tfa_csv_a: dict | None = None, tfa_csv_b: dict | None = None):
    """Bar chart of TFA per OWASP suite with optional Scenario B overlay.

    Args:
        tfa_a: TFA dict for Scenario A.
        tfa_b: TFA dict for Scenario B, or an empty dict when unavailable.
        domain: Domain name used in the figure title and output filename.
        figures_dir: Directory where the PNG is saved.
        tfa_csv_a: Optional per-suite TFA dict for Scenario A as returned by
            ``load_tfa_from_csv``, computed with the correct ground truth per
            OWASP suite. When provided, its ``per_suite`` values are used
            instead of ``tfa_a["per_suite"]`` (which is only a valid ground
            truth for LLM01). Falls back to ``tfa_a["per_suite"]`` when None.
        tfa_csv_b: Same as tfa_csv_a, for Scenario B.
    """
    import matplotlib.pyplot as plt
    import numpy as np
    setup_style()

    suites  = list(VECTOR_MAP.keys())
    labels  = [f"{s}\n{_SUBDIM_LABELS_ES[s].split('—')[1].strip()}" for s in suites]
    per_suite_a = tfa_csv_a["per_suite"] if tfa_csv_a else tfa_a["per_suite"]
    vals_a = [per_suite_a.get(s, {}).get("TFA") or 0 for s in suites]
    vals_b = None
    if tfa_b:
        per_suite_b = tfa_csv_b["per_suite"] if tfa_csv_b else tfa_b["per_suite"]
        vals_b = [per_suite_b.get(s, {}).get("TFA") or 0 for s in suites]

    x     = np.arange(len(suites))
    width = 0.35 if vals_b else 0.5
    fig, ax = plt.subplots(figsize=(8, 5))

    ax.bar(x - width/2 if vals_b else x, vals_a, width, label="Escenario A",
           color=[SUITE_COLORS[s] for s in suites], alpha=0.85, edgecolor="white")
    if vals_b:
        ax.bar(x + width/2, vals_b, width, label="Escenario B",
               color=[SUITE_COLORS[s] for s in suites], alpha=0.45,
               edgecolor="white", hatch="//")

    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=9)
    ax.set_ylim(0, 1.08)
    ax.set_ylabel("TFA (Tasa de Filtrado de Ataques)")
    ax.set_title(f"TFA por suite OWASP — {_domain_label(domain)}")
    ax.axhline(1.0, color="gray", linewidth=0.8, linestyle="--", alpha=0.5)
    if vals_b:
        ax.legend(fontsize=9)
    if tfa_csv_a:
        fig.text(0.5, -0.04, _TFA_GT_SOURCE_NOTE, ha="center", va="top",
                 fontsize=7.5, style="italic", color="#555555")

    _save(fig, figures_dir, f"tfa_by_suite_{domain}.png")
    plt.close(fig)


def plot_tfa_domains_combined(tfa_by_domain: dict, figures_dir: Path,
                              tfa_csv_by_domain: dict | None = None):
    """Side-by-side per-suite TFA bar chart for all domains in a single figure.

    Args:
        tfa_by_domain: Mapping of ``{domain: {"A": tfa_dict, "B": tfa_dict}}``.
        figures_dir: Directory where the PNG is saved.
        tfa_csv_by_domain: Optional mapping with the same shape, sourced from
            ``load_tfa_from_csv``, computed with the correct ground truth per
            OWASP suite. When provided, a domain's ``per_suite`` values are
            used instead of ``tfa_by_domain[domain]["A"/"B"]["per_suite"]``
            (which is only a valid ground truth for LLM01). Falls back to
            ``tfa_by_domain`` per domain when None or when a domain is absent.
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

    used_csv_gt = False
    for ax, domain in zip(axes, domains):
        tfa_a = tfa_by_domain[domain]["A"]
        tfa_b = tfa_by_domain[domain]["B"]
        csv_d = (tfa_csv_by_domain or {}).get(domain, {})
        tfa_csv_a = csv_d.get("A")
        tfa_csv_b = csv_d.get("B")

        if not tfa_a:
            # No Scenario A data for this domain yet: render a placeholder so
            # the figure still has one panel per domain (matching the title)
            # instead of raising on tfa_a["per_suite"] and aborting before
            # _save() — which previously left a stale single-panel PNG.
            ax.set_title(f"{_domain_label(domain)}\n[sin datos]", fontsize=10)
            ax.set_xticks([])
            continue

        per_suite_a = tfa_csv_a["per_suite"] if tfa_csv_a else tfa_a["per_suite"]
        vals_a = [per_suite_a.get(s, {}).get("TFA") or 0 for s in suites]
        vals_b = None
        if tfa_b:
            per_suite_b = tfa_csv_b["per_suite"] if tfa_csv_b else tfa_b["per_suite"]
            vals_b = [per_suite_b.get(s, {}).get("TFA") or 0 for s in suites]
        if tfa_csv_a:
            used_csv_gt = True

        x     = np.arange(n_suites)
        width = 0.35 if vals_b else 0.5

        ax.bar(x - width/2 if vals_b else x, vals_a, width, label="Escenario A",
               color=[SUITE_COLORS[s] for s in suites], alpha=0.85, edgecolor="white")
        if vals_b:
            ax.bar(x + width/2, vals_b, width, label="Escenario B",
                   color=[SUITE_COLORS[s] for s in suites], alpha=0.45,
                   edgecolor="white", hatch="//")

        ax.set_xticks(x)
        ax.set_xticklabels(suites, fontsize=9)
        ax.set_ylim(0, 1.08)
        ax.set_title(_domain_label(domain), fontsize=10)
        ax.axhline(1.0, color="gray", linewidth=0.8, linestyle="--", alpha=0.5)
        if vals_b:
            ax.legend(fontsize=8)

    axes[0].set_ylabel("TFA (Tasa de Filtrado de Ataques)")
    if len(domains) == 2:
        title = "TFA por suite OWASP — Ambos dominios"
    elif len(domains) == 1:
        title = f"TFA por suite OWASP — {_domain_label(domains[0])}"
    else:
        title = "TFA por suite OWASP — Todos los dominios"
    fig.suptitle(title, fontweight="bold")
    if used_csv_gt:
        fig.text(0.5, -0.02, _TFA_GT_SOURCE_NOTE, ha="center", va="top",
                 fontsize=7.5, style="italic", color="#555555")
    fig.tight_layout()
    _save(fig, figures_dir, "tfa_by_suite_combined.png")
    plt.close(fig)


def plot_tfa_csv_by_suite_grouped(
    tfa_csv_by_domain: dict,
    figures_dir: Path,
    color_a: str = "#e07b39",
    color_b: str = "#1e5eff",
):
    """Grouped bar chart of CSV-based per-suite TFA, one subplot per domain.

    Unlike ``plot_tfa_by_suite``/``plot_tfa_domains_combined`` (which fall
    back to the garak_passed-based ``per_suite`` when no CSV TFA is given),
    this function is CSV-only: every value plotted comes from
    ``tfa_csv_by_domain``, i.e. from ``load_tfa_from_csv`` /
    ``compute_tfa_by_suite``, which picks the correct ground-truth column
    per OWASP suite (``garak_passed`` for LLM01, direct response inspection
    for LLM02/LLM07/LLM08).

    Args:
        tfa_csv_by_domain: Mapping of ``{domain: {"A": tfa_csv_dict,
            "B": tfa_csv_dict}}``, where each ``tfa_csv_dict`` has the shape
            returned by ``load_tfa_from_csv`` (``{"per_suite": {suite:
            {"TFA": float | None, "suite": suite}}, ...}``). Suites plotted
            are exactly the keys present in ``tfa_csv_dict["per_suite"]``,
            in their given order — no suite names are hardcoded.
        figures_dir: Directory where the PNG is saved.
        color_a: Bar color for Scenario A.
        color_b: Bar color for Scenario B.

    Outputs:
        - artifacts/figures/tfa_csv_by_suite_both_domains.png
    """
    import matplotlib.pyplot as plt
    import numpy as np
    setup_style()

    domains = list(tfa_csv_by_domain.keys())
    fig, axes = plt.subplots(1, len(domains), figsize=(7 * len(domains), 5), sharey=True)
    if len(domains) == 1:
        axes = [axes]

    for ax, domain in zip(axes, domains):
        tfa_csv_a = tfa_csv_by_domain[domain].get("A") or {}
        tfa_csv_b = tfa_csv_by_domain[domain].get("B") or {}
        per_suite_a = tfa_csv_a.get("per_suite", {})
        per_suite_b = tfa_csv_b.get("per_suite", {})
        suites = list(per_suite_a.keys()) or list(per_suite_b.keys())
        if not suites:
            ax.set_title(f"{_domain_label(domain)}\n[sin datos]", fontsize=10)
            ax.set_xticks([])
            continue

        vals_a = [per_suite_a.get(s, {}).get("TFA") or 0 for s in suites]
        vals_b = [per_suite_b.get(s, {}).get("TFA") or 0 for s in suites]
        has_b  = any(per_suite_b.get(s, {}).get("TFA") is not None for s in suites)

        x     = np.arange(len(suites))
        width = 0.35 if has_b else 0.5

        bars_a = ax.bar(x - width/2 if has_b else x, vals_a, width, label="Escenario A",
                         color=color_a, alpha=0.85, edgecolor="white")
        for bar, val in zip(bars_a, vals_a):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.015,
                    f"{val:.3f}", ha="center", va="bottom", fontsize=7.5)

        if has_b:
            bars_b = ax.bar(x + width/2, vals_b, width, label="Escenario B",
                             color=color_b, alpha=0.85, edgecolor="white")
            for bar, val in zip(bars_b, vals_b):
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.015,
                        f"{val:.3f}", ha="center", va="bottom", fontsize=7.5)

        ax.set_xticks(x)
        ax.set_xticklabels(suites, fontsize=9)
        ax.set_ylim(0, 1.12)
        ax.set_title(_domain_label(domain), fontsize=10)
        ax.axhline(1.0, color="gray", linewidth=0.8, linestyle="--", alpha=0.5)
        ax.legend(fontsize=8)

    axes[0].set_ylabel("TFA (Tasa de Filtrado de Ataques, base CSV)")
    fig.suptitle("TFA por suite OWASP (base CSV) — Escenario A vs B", fontweight="bold")
    fig.text(0.5, -0.02, _TFA_GT_SOURCE_NOTE, ha="center", va="top",
             fontsize=7.5, style="italic", color="#555555")
    fig.tight_layout()
    _save(fig, figures_dir, "tfa_csv_by_suite_both_domains.png")
    plt.close(fig)


def plot_tfa_global_weighted(
    global_tfa_by_domain: dict,
    figures_dir: Path,
    color_a: str = "#e07b39",
    color_b: str = "#1e5eff",
):
    """Grouped bar chart of weighted global TFA per domain, Scenario A vs B.

    One bar group per domain, with bars for ``TFA_A``/``TFA_B`` taken from
    the top-level ``"TFA"`` key of each ``global_dict`` (the output of
    :func:`eval.metrics.compute_tfa_global`), i.e. the suite-weighted
    aggregate that uses the correct ground-truth column per OWASP suite
    rather than raw ``garak_passed``. ΔTFA (B − A) is annotated above each
    domain's bar pair when both scenarios are present.

    Args:
        global_tfa_by_domain: Mapping of ``{domain: {"A": global_dict,
            "B": global_dict}}``, where each ``global_dict`` is the output
            of ``compute_tfa_global(df)``: ``{"TFA": float, "total_tp": int,
            "total_n": int, "per_suite": {...}}``. ``"B"`` may be ``None`` or
            an empty dict when Scenario B data is unavailable for a domain.
        figures_dir: Directory where the PNG is saved.
        color_a: Bar color for Scenario A.
        color_b: Bar color for Scenario B.

    Outputs:
        - artifacts/figures/tfa_global_weighted.png
    """
    import matplotlib.pyplot as plt
    import numpy as np
    setup_style()

    domains = list(global_tfa_by_domain.keys())
    if not domains:
        print("  [skip] tfa_global_weighted: no domains.")
        return

    vals_a, vals_b, has_b_flags = [], [], []
    for domain in domains:
        g_a = global_tfa_by_domain[domain].get("A") or {}
        g_b = global_tfa_by_domain[domain].get("B") or {}
        tfa_a = g_a.get("TFA")
        tfa_b = g_b.get("TFA")
        vals_a.append(tfa_a if tfa_a is not None and not pd.isna(tfa_a) else 0)
        has_b = tfa_b is not None and not pd.isna(tfa_b)
        vals_b.append(tfa_b if has_b else 0)
        has_b_flags.append(has_b)

    x     = np.arange(len(domains))
    width = 0.35
    fig, ax = plt.subplots(figsize=(4 + 2.5 * len(domains), 5.5))

    bars_a = ax.bar(x - width/2, vals_a, width, label="Escenario A",
                     color=color_a, alpha=0.85, edgecolor="white")
    bars_b = ax.bar(x + width/2, vals_b, width, label="Escenario B",
                     color=color_b, alpha=0.85, edgecolor="white")

    for bar, val in zip(bars_a, vals_a):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.01,
                f"{val:.4f}", ha="center", va="bottom", fontsize=8)
    for bar, val, has_b in zip(bars_b, vals_b, has_b_flags):
        label = f"{val:.4f}" if has_b else "N/D"
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.01,
                label, ha="center", va="bottom", fontsize=8)

    for xi, va, vb, has_b in zip(x, vals_a, vals_b, has_b_flags):
        if has_b:
            delta = vb - va
            y_top = max(va, vb) + 0.06
            ax.text(xi, y_top, f"ΔTFA={delta:+.4f}", ha="center", va="bottom",
                    fontsize=8.5, fontweight="bold", color="#333333")

    ax.set_xticks(x)
    ax.set_xticklabels([_domain_label(d) for d in domains], fontsize=10)
    ax.set_ylim(0, 1.18)
    ax.set_ylabel("TFA global ponderado por suite")
    ax.set_title("TFA global ponderado por suite — Escenario A vs B")
    ax.axhline(1.0, color="gray", linewidth=0.8, linestyle="--", alpha=0.5)
    ax.legend(fontsize=9)
    fig.text(0.5, -0.03, _TFA_GT_SOURCE_NOTE, ha="center", va="top",
             fontsize=7.5, style="italic", color="#555555")

    fig.tight_layout()
    _save(fig, figures_dir, "tfa_global_weighted.png")
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
    ax.set_yticklabels([_domain_label(d) for d in domains], fontsize=9)

    # Annotate cells
    for i in range(len(domains)):
        for j in range(len(probes)):
            ax.text(j, i, f"{data[i, j]:.2f}", ha="center", va="center",
                    fontsize=8, color="black")

    plt.colorbar(im, ax=ax, label="TFA")
    ax.set_title("Mapa de calor de TFA — Escenario A (sonda × dominio)")
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
               label=_domain_label(domain),
               color=color, alpha=0.8, edgecolor="white")

    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=35, ha="right", fontsize=9)
    ax.axhline(0, color="black", linewidth=0.8)
    ax.set_ylabel("ΔTFA (Escenario B − Escenario A)")
    ax.set_title("ΔTFA por sonda — Contribución neta de LLM Guard")
    ax.legend(fontsize=9)
    _save(fig, figures_dir, "delta_tfa_by_probe.png")
    plt.close(fig)

def plot_pvalue_by_suite(tfa_by_domain: dict, figures_dir: Path):
    """Bar chart of -log10(p-value) per suite — Fisher exact test A vs B.

    Contingency table per suite is ``[[TP_A, FN_A], [TP_B, FN_B]]``, built from
    the per-suite ``passed``/``total`` totals of Scenario A and B (TP = passed
    = resisted, FN = total - passed = attack succeeded). Tables are printed to
    console before each Fisher exact call so the inputs can be verified.

    scipy's ``fisher_exact`` underflows to exactly ``p == 0.0`` for very large,
    highly significant tables (common here with ~32k samples per suite). The
    old ``-log10(p) if p > 0 else 0`` guard mapped that underflow to a bar of
    height 0 — visually indistinguishable from a *non-significant* p == 1.0.
    p is floored to the smallest representable double before taking -log10 so
    highly significant results render as tall bars instead of disappearing.
    """
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
    p_floor = np.finfo(float).tiny

    print("\n  Fisher exact contingency tables — [[TP_A, FN_A], [TP_B, FN_B]]")
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
                table = [[va["passed"], fn_a], [vb["passed"], fn_b]]
                _, p = fisher_exact(table, alternative="less")
                print(f"    {domain:25s} {suite}: {table}  p={p:.3e}")
                pvals.append(-np.log10(max(p, p_floor)))
            else:
                pvals.append(0)

        offset = (i - len(tfa_by_domain) / 2 + 0.5) * width
        ax.bar(x + offset, pvals, width,
               label=_domain_label(domain),
               color=color, alpha=0.8, edgecolor="white")

    # Significance threshold line: -log10(0.05) ≈ 1.301
    ax.axhline(-np.log10(0.05), color="red", linewidth=1.2,
               linestyle="--", label="α = 0.05")

    ax.set_xticks(x)
    ax.set_xticklabels(list(VECTOR_MAP.keys()), fontsize=10)
    ax.set_ylabel("-log₁₀(valor p)")
    ax.set_title("Significancia estadística por suite OWASP (test exacto de Fisher, A vs B)")
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
               label=_domain_label(domain),
               color=color, alpha=0.8, edgecolor="white")

    ax.set_xticks(x)
    ax.set_xticklabels(subdims, fontsize=10)
    ax.set_ylabel("Tasa de exposición confidencial")
    ax.set_title("Exposición de datos confidenciales por subdimensión — Escenario A")
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
            bp = ax.boxplot([sub_a, sub_b], tick_labels=["Escenario A", "Escenario B"],
                            patch_artist=True,
                            medianprops={"color": "black", "linewidth": 2},
                            flierprops={"marker": ".", "markersize": 3, "alpha": 0.3})
            for patch, color in zip(bp["boxes"], [SCENARIO_COLORS["A"], SCENARIO_COLORS["B"]]):
                patch.set_facecolor(color)
                patch.set_alpha(0.6)
            ax.set_title(_domain_label(domain), fontsize=10)
            ax.set_ylabel("Latencia (ms)" if ax == axes[0] else "")
            ax.set_yscale("log")
        fig.suptitle(
            "Distribución de latencia por dominio\n"
            "(eje y en escala logarítmica; se muestran valores atípicos extremos)",
            fontweight="bold")
        fig.tight_layout()
        _save(fig, figures_dir, "las_boxplot_by_domain.png")
    else:
        fig, ax = plt.subplots(figsize=(6, 5))
        data   = [lat_a["latency_ms"].values, lat_b["latency_ms"].values]
        labels = ["Escenario A\n(sin protección)", "Escenario B\n(LLM Guard)"]
        colors = [SCENARIO_COLORS["A"], SCENARIO_COLORS["B"]]
        bp = ax.boxplot(data, tick_labels=labels, patch_artist=True,
                        medianprops={"color": "black", "linewidth": 2},
                        flierprops={"marker": ".", "markersize": 3, "alpha": 0.3})
        for patch, color in zip(bp["boxes"], colors):
            patch.set_facecolor(color)
            patch.set_alpha(0.6)
        ax.set_yscale("log")
        ax.set_ylabel("Latencia (ms)")
        ax.set_title(
            "Distribución de latencia — Escenario A vs B\n"
            "(eje y en escala logarítmica; se muestran valores atípicos extremos)")
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
            label="Escenario A", density=True)
    vals_a.plot.kde(color=SCENARIO_COLORS["A"], linewidth=2, ax=ax, label="_nolegend_")

    # Mean lines and stats text
    mean_a = vals_a.mean()
    std_a  = vals_a.std()
    ax.axvline(mean_a, color=SCENARIO_COLORS["A"], linewidth=1.5,
               linestyle="--", alpha=0.8)

    stats_text = f"Escenario A\n  media={mean_a:.0f} ms\n  desv. est.={std_a:.0f} ms"

    if not lat_b.empty:
        vals_b = lat_b["latency_ms"].dropna()
        ax.hist(vals_b, bins=80, alpha=0.4, color=SCENARIO_COLORS["B"],
                label="Escenario B", density=True)
        vals_b.plot.kde(color=SCENARIO_COLORS["B"], linewidth=2, ax=ax, label="_nolegend_")

        mean_b = vals_b.mean()
        std_b  = vals_b.std()
        ax.axvline(mean_b, color=SCENARIO_COLORS["B"], linewidth=1.5,
                   linestyle="--", alpha=0.8)

        # Mann-Whitney p-value
        _, p_val = mannwhitneyu(vals_a.values, vals_b.values, alternative="less")
        sig = "significativo" if p_val < 0.05 else "no significativo"
        stats_text += (
            f"\n\nEscenario B\n  media={mean_b:.0f} ms\n  desv. est.={std_b:.0f} ms"
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
    ax.set_xlabel("Latencia (ms)")
    ax.set_ylabel("Densidad")
    ax.set_title("Distribución de latencia — Histograma + KDE")
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

    ax.bar(x - width/2 if has_b else x, meds_a, width, label="Escenario A",
           color=[SUITE_COLORS.get(s, "#888") for s in labels],
           alpha=0.85, edgecolor="white")
    if has_b:
        valid_b = [v or 0 for v in meds_b]
        ax.bar(x + width/2, valid_b, width, label="Escenario B",
               color=[SUITE_COLORS.get(s, "#888") for s in labels],
               alpha=0.45, edgecolor="white", hatch="//")

    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=9, ha="center")
    ax.set_ylabel("Latencia mediana (ms)")
    ax.set_title("Latencia mediana por suite OWASP")
    if has_b:
        ax.legend(fontsize=9)
        fig.text(0.5, -0.02,
                 "Nota: una mediana menor en el Escenario B para algunas suites (p. ej., "
                 "LLM01, LLM08) refleja el bloqueo temprano de LLM Guard antes de la "
                 "inferencia del modelo.",
                 ha="center", va="top", fontsize=8.5, style="italic", color="#555555")
    fig.tight_layout()
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
    bp = ax.boxplot(data, tick_labels=suites, patch_artist=True,
                    medianprops={"color": "black", "linewidth": 2},
                    flierprops={"marker": ".", "markersize": 2, "alpha": 0.3})
    for patch, suite in zip(bp["boxes"], suites):
        patch.set_facecolor(SUITE_COLORS.get(suite, "#888"))
        patch.set_alpha(0.7)
    ax.set_ylabel("Latencia (ms)")
    ax.set_title("Distribución de latencia por suite OWASP — Escenario A")
    _save(fig, figures_dir, "las_distribution_by_suite_A.png")
    plt.close(fig)

def _render_confusion_matrices(
    matrices: list,
    valid_domains: list,
    title: str,
    filename: str,
    figures_dir: Path,
    recall_label: str = "Sensibilidad",
):
    """Renders one confusion-matrix heatmap subplot per domain and saves the figure.

    Shared by ``plot_confusion_matrix`` (system-level, two-layer) and
    ``plot_confusion_matrix_guard_only`` (single-layer, LLM Guard only) so
    both Scenario B perspectives are rendered identically.

    Args:
        matrices: 2x2 arrays ``[[TP, FN], [FP, TN]]``, one per domain.
        valid_domains: Domain names corresponding to ``matrices``.
        title: Figure suptitle.
        filename: Output PNG filename, saved under ``figures_dir``.
        figures_dir: Output directory for figures.
        recall_label: Label used for the recall row in the per-subplot stats box.
    """
    import matplotlib.pyplot as plt
    setup_style()

    n = len(valid_domains)
    fig, axes = plt.subplots(1, n, figsize=(5 * n, 4))
    if n == 1:
        axes = [axes]

    row_labels = ["Real\nATAQUE", "Real\nLEGÍTIMO"]

    for ax, domain, matrix in zip(axes, valid_domains, matrices):
        total = matrix.sum()
        # Normalize for color, show raw counts as annotation
        norm = matrix / total if total > 0 else matrix

        ax.imshow(norm, cmap="Blues", vmin=0, vmax=1)

        ax.set_xticks([0, 1])
        ax.set_xticklabels(["Predicción\nBLOQUEO", "Predicción\nPASE"], fontsize=9)
        ax.set_yticks([0, 1])
        ax.set_yticklabels(row_labels, fontsize=9)

        cell_labels = [["VP", "FN"], ["FP", "VN"]]

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

        stats = (f"Precisión: {precision:.3f}\n"
                 f"{recall_label}: {recall:.3f}\n"
                 f"F1: {f1:.3f}\n"
                 f"Especificidad: {specificity:.3f}")
        ax.text(1.35, 0.5, stats,
                transform=ax.transAxes,
                fontsize=8.5, va="center",
                bbox=dict(boxstyle="round,pad=0.4", facecolor="white",
                          edgecolor="gray", alpha=0.85))

        ax.set_title(_domain_label(domain), fontsize=10)

    fig.suptitle(title, fontweight="bold")
    fig.tight_layout()
    _save(fig, figures_dir, filename)
    plt.close(fig)


def plot_confusion_matrix(artifacts_dir: Path, domains: list, figures_dir: Path):
    """
    Heatmap confusion matrix for Scenario B — SYSTEM-LEVEL (two-layer, PRIMARY) view.

    TP/FN account for BOTH defensive layers: LLM Guard (``was_blocked``) and
    the model's own intrinsic resistance (``garak_passed``). A prompt that
    LLM Guard passed but the model resisted naturally is a system-level TP,
    NOT an FN — see ``_confusion_counts_system`` in ``loaders.py`` for the
    full two-layer definition. This is the PRIMARY Scenario B matrix; use
    ``plot_confusion_matrix_guard_only`` for LLM Guard's contribution in
    isolation. One subplot per domain.
    """
    import numpy as np

    valid_domains = []
    matrices = []

    for domain in domains:
        adv = load_consolidated(artifacts_dir, domain, "protected")
        if adv.empty:
            print(f"  [skip] confusion matrix: no Scenario B data for {domain}")
            continue
        legit = _load_consolidated_legit(artifacts_dir, domain, "protected")
        counts = _confusion_counts_system(adv, legit)
        TP, FN, FP, TN = counts["TP"], counts["FN"], counts["FP"], counts["TN"]
        valid_domains.append(domain)
        matrices.append(np.array([[TP, FN], [FP, TN]]))

    if not valid_domains:
        print("  [skip] confusion matrix: no Scenario B data available yet.")
        return

    _render_confusion_matrices(
        matrices, valid_domains,
        title="Matriz de confusión — Escenario B, nivel de sistema (dos capas)",
        filename="confusion_matrix_scenario_b.png",
        figures_dir=figures_dir,
        recall_label="Sensibilidad (TFA_B)",
    )


def plot_confusion_matrix_guard_only(artifacts_dir: Path, domains: list, figures_dir: Path):
    """
    Heatmap confusion matrix for Scenario B — LLM GUARD ONLY (single-layer) view.

    TP/FN depend only on ``was_blocked`` vs. ``should_block``, i.e. LLM
    Guard's blocking decision in isolation, ignoring whether the model would
    have resisted the attack on its own — see ``_confusion_counts`` in
    ``loaders.py``. Provided alongside the system-level matrix
    (``plot_confusion_matrix``) so both perspectives are available for
    analysis. One subplot per domain.
    """
    import numpy as np

    valid_domains = []
    matrices = []

    for domain in domains:
        adv = load_consolidated(artifacts_dir, domain, "protected")
        if adv.empty:
            print(f"  [skip] confusion matrix (guard-only): no Scenario B data for {domain}")
            continue
        legit = _load_consolidated_legit(artifacts_dir, domain, "protected")
        counts = _confusion_counts(adv, legit)
        TP, FN, FP, TN = counts["TP"], counts["FN"], counts["FP"], counts["TN"]
        valid_domains.append(domain)
        matrices.append(np.array([[TP, FN], [FP, TN]]))

    if not valid_domains:
        print("  [skip] confusion matrix (guard-only): no Scenario B data available yet.")
        return

    _render_confusion_matrices(
        matrices, valid_domains,
        title="Matriz de confusión — Escenario B, solo LLM Guard (una capa)",
        filename="confusion_matrix_scenario_b_llmguard_only.png",
        figures_dir=figures_dir,
        recall_label="Sensibilidad",
    )


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
    col_labels = [_domain_label(dom) for dom in domain_data]

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
    ax.set_title("TFA por sonda × detector — Escenario A\n"
                 "(negrita = detector primario usado para el cálculo de TFA)",
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
        ax.set_xticklabels(["Resistido", "Fallido"], fontsize=10)
        ax.set_yticks([0, 1])
        ax.set_yticklabels(["Real\nATAQUE", "Real\nLEGÍTIMO"], fontsize=10)

        # Cell annotations
        cell_meta = [
            (0, 0, f"VP\n{TP:,}\n({TP/total_adv*100:.1f}%)",   "black"),
            (0, 1, f"FN\n{FN:,}\n({FN/total_adv*100:.1f}%)",   "black"),
            (1, 0, f"VN\n{TN:,}\n({TN/total_legit*100:.1f}%)", "black"),
            (1, 1, "FP\nN/D\n(sin clasificador)", "gray"),
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
            f"Resistencia del modelo (TFA_A)\n"
            f"  Sensibilidad = {recall:.4f}\n"
            f"  FNR    = {fnr:.4f}\n\n"
            f"Prompts legítimos\n"
            f"  Tasa de VN = {tn_rate:.4f}\n"
            f"  Filtrados  = {legit_leaked} ({legit_leak_rate*100:.1f}%)\n\n"
            f"FP = N/D\n"
            f"(sin clasificador activo)"
        )
        ax.text(1.38, 0.5, stats,
                transform=ax.transAxes,
                fontsize=8, va="center",
                bbox=dict(boxstyle="round,pad=0.4", facecolor="white",
                          edgecolor="gray", alpha=0.85))

        ax.set_title(_domain_label(domain), fontsize=10)

    fig.suptitle(
        "Matriz de confusión parcial — Escenario A (sin clasificador activo)\n"
        "Celda FP en gris: mecanismo de bloqueo ausente por diseño",
        fontweight="bold", fontsize=10
    )
    fig.tight_layout()
    _save(fig, figures_dir, "confusion_matrix_scenario_a.png")
    plt.close(fig)


def plot_security_posture_radar(tfa_by_domain: dict, figures_dir: Path):
    """Radar chart of system-level TFA per subdimension (D1-D4), Scenario A vs B.

    Overlays four polygons — one per (scenario, domain) combination — on a
    shared D1-D4 axis layout (LLM01->D1, LLM02->D2, LLM07->D3, LLM08->D4 via
    ``SUITE_TO_SUBDIM``). Scenario A is drawn in gray, Scenario B in blue;
    the academic domain uses a solid line and the regulatory domain a dashed
    line. Each vertex is annotated with its TFA value.

    Args:
        tfa_by_domain: Mapping of ``{domain: {"A": tfa_dict, "B": tfa_dict}}``
            as returned by ``load_tfa_from_jsonl``.
        figures_dir: Directory where the PNG is saved.

    Outputs:
        - artifacts/figures/fig_security_posture_radar.png
    """
    import matplotlib.pyplot as plt
    import numpy as np
    setup_style()

    suites  = list(SUITE_TO_SUBDIM.keys())
    subdims = [SUITE_TO_SUBDIM[s] for s in suites]

    domains    = list(tfa_by_domain.keys())
    academic   = next((d for d in domains if "academic" in d), None)
    regulatory = next((d for d in domains if "regulatory" in d), None)

    series = [
        ("A", academic,   "Escenario A — Académico",   "#888780", "solid"),
        ("A", regulatory, "Escenario A — Regulatorio", "#888780", "dashed"),
        ("B", academic,   "Escenario B — Académico",   "#185FA5", "solid"),
        ("B", regulatory, "Escenario B — Regulatorio", "#185FA5", "dashed"),
    ]

    angles = np.linspace(0, 2 * np.pi, len(subdims), endpoint=False).tolist()
    angles += angles[:1]

    fig, ax = plt.subplots(figsize=(8, 8), subplot_kw={"projection": "polar"})
    ax.set_theta_offset(np.pi / 2)
    ax.set_theta_direction(-1)

    any_series = False
    for i, (scenario, domain, label, color, style) in enumerate(series):
        if not domain:
            continue
        tfa_d     = tfa_by_domain.get(domain, {}).get(scenario) or {}
        per_suite = tfa_d.get("per_suite", {})
        vals      = [per_suite.get(s, {}).get("TFA") or 0 for s in suites]
        vals_closed = vals + vals[:1]

        ax.plot(angles, vals_closed, color=color, linewidth=2,
                linestyle=style, label=label)
        ax.fill(angles, vals_closed, color=color, alpha=0.08)

        # Annotate each axis in a fixed outer "ring" per series (r = 1.05 +
        # 0.18*i) rather than just outside each vertex — this guarantees
        # consistent spacing between series even when their TFA values are
        # nearly identical at a given axis (e.g. D2/D4).
        ring_r = 1.05 + 0.18 * i
        for angle, val in zip(angles[:-1], vals):
            ax.text(angle, ring_r, f"{val:.2f}",
                    ha="center", va="center", fontsize=7,
                    color=color, fontweight="bold")
        any_series = True

    if not any_series:
        print("  [skip] security posture radar: no TFA data available.")
        plt.close(fig)
        return

    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(subdims, fontsize=11, fontweight="bold")
    ax.set_ylim(0, 1.85)
    ax.set_yticks([0.25, 0.50, 0.75, 1.00])
    ax.set_yticklabels(["0.25", "0.50", "0.75", "1.00"], fontsize=8)

    ax.set_title("Postura de seguridad por subdimensión — D1–D4 (TFA, nivel de sistema)",
                  fontweight="bold", pad=20)
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.06), ncol=2, fontsize=8.5)
    fig.text(0.5, -0.02,
             "Solo referencia visual — la escala es TFA [0,1] por subdimensión",
             ha="center", fontsize=8.5, style="italic", color="#555555")

    fig.tight_layout()
    _save(fig, figures_dir, "fig_security_posture_radar.png")
    plt.close(fig)


def plot_tfa_suite_all_combos(tfa_by_domain: dict, figures_dir: Path):
    """Single-panel TFA bar chart with all 4 scenario x domain combos per suite.

    For each OWASP suite (LLM01/02/07/08), draws four bars side by side:
    Scenario A/B for the academic domain (solid) and Scenario A/B for the
    regulatory domain (hatched). Complements ``plot_tfa_domains_combined``,
    which uses one subplot per domain instead of a single grouped panel.

    Args:
        tfa_by_domain: Mapping of ``{domain: {"A": tfa_dict, "B": tfa_dict}}``
            as returned by ``load_tfa_from_jsonl``.
        figures_dir: Directory where the PNG is saved.

    Outputs:
        - artifacts/figures/fig_tfa_suite_all_combos.png
    """
    import matplotlib.pyplot as plt
    import numpy as np
    setup_style()

    suites  = list(VECTOR_MAP.keys())
    domains = list(tfa_by_domain.keys())
    academic   = next((d for d in domains if "academic" in d), None)
    regulatory = next((d for d in domains if "regulatory" in d), None)

    series = [
        ("A", academic,   "Acad A", "#888780", False),
        ("B", academic,   "Acad B", "#185FA5", False),
        ("A", regulatory, "Reg A",  "#888780", True),
        ("B", regulatory, "Reg B",  "#185FA5", True),
    ]

    x     = np.arange(len(suites))
    width = 0.8 / len(series)
    fig, ax = plt.subplots(figsize=(10, 6))

    for i, (scenario, domain, label, color, hatched) in enumerate(series):
        if not domain:
            continue
        tfa_d     = tfa_by_domain.get(domain, {}).get(scenario) or {}
        per_suite = tfa_d.get("per_suite", {})
        vals      = [per_suite.get(s, {}).get("TFA") or 0 for s in suites]

        offset = (i - (len(series) - 1) / 2) * width
        bars = ax.bar(x + offset, vals, width, label=label, color=color,
                       alpha=0.85, edgecolor="white",
                       hatch="//" if hatched else None)
        rotation = 90 if width < 0.18 else 0
        for bar, val in zip(bars, vals):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.015,
                    f"{val:.2f}", ha="center", va="bottom",
                    fontsize=7, rotation=rotation)

    ax.set_xticks(x)
    ax.set_xticklabels(suites, fontsize=10)
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("TFA (Tasa de Filtrado de Ataques)")
    ax.set_title("TFA por suite OWASP — todas las combinaciones de escenario × dominio")
    ax.axhline(1.0, color="gray", linewidth=0.8, linestyle="--", alpha=0.5)
    ax.legend(fontsize=9)

    _save(fig, figures_dir, "fig_tfa_suite_all_combos.png")
    plt.close(fig)


def plot_garak_vs_ground_truth(
    summary_df: pd.DataFrame,
    domain: str,
    figures_dir: Path,
    color_a: str = "#e07b39",
    color_b: str = "#1e5eff",
):
    """Grouped bar chart comparing Garak TFA vs ground truth TFA per probe.

    Three bars per probe: Garak TFA Scenario A (orange, error bars = IQR across
    5 repetitions), Garak TFA Scenario B (blue, error bars), and Ground Truth
    TFA Scenario B (blue hatched, no error bars — single value from consolidated
    CSV).  Probes are ordered by OWASP suite with dashed vertical separators
    between suite groups.

    Args:
        summary_df: Summary DataFrame as returned by
            :func:`eval.metrics.compute_garak_asr_by_repetition` (i.e. the
            rows saved to ``garak_asr_summary.csv``).
        domain: Domain name — used to filter ``summary_df`` and label the title.
        figures_dir: Directory where the PNG is saved.
        color_a: Bar fill color for Scenario A.
        color_b: Bar fill color for Scenario B.

    Outputs:
        - artifacts/figures/garak_vs_ground_truth_{domain}.png
    """
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    import numpy as np
    setup_style()

    df = summary_df[summary_df["domain"] == domain].copy()
    if df.empty:
        print(f"  [skip] plot_garak_vs_ground_truth: no data for {domain}")
        return

    suite_order = ["LLM01", "LLM02", "LLM07", "LLM08"]
    probes_all  = df["probe"].unique().tolist()
    probes_sorted = sorted(
        probes_all,
        key=lambda p: (
            suite_order.index(PROBE_TO_SUITE.get(p, ""))
            if PROBE_TO_SUITE.get(p, "") in suite_order else 99,
            p,
        ),
    )
    labels = [PROBE_SHORT.get(p, p) for p in probes_sorted]
    n      = len(probes_sorted)
    x      = np.arange(n)
    width  = 0.24

    df_a = df[df["scenario"] == "unprotected"].set_index("probe")
    df_b = df[df["scenario"] == "protected"].set_index("probe")

    fig, ax = plt.subplots(figsize=(max(10, n * 1.3), 5.5))

    for i, probe in enumerate(probes_sorted):
        xi = x[i]

        if probe in df_a.index:
            r       = df_a.loc[probe]
            med     = float(r["garak_tfa_median"])
            err_lo  = max(med - float(r["garak_tfa_q1"]), 0.0)
            err_hi  = max(float(r["garak_tfa_q3"]) - med, 0.0)
            ax.bar(xi - width, med, width, color=color_a, alpha=0.85, edgecolor="white")
            ax.errorbar(xi - width, med, yerr=[[err_lo], [err_hi]],
                        color="#333333", capsize=3, linewidth=1.2, zorder=4)

        if probe in df_b.index:
            r       = df_b.loc[probe]
            med     = float(r["garak_tfa_median"])
            err_lo  = max(med - float(r["garak_tfa_q1"]), 0.0)
            err_hi  = max(float(r["garak_tfa_q3"]) - med, 0.0)
            ax.bar(xi, med, width, color=color_b, alpha=0.85, edgecolor="white")
            ax.errorbar(xi, med, yerr=[[err_lo], [err_hi]],
                        color="#333333", capsize=3, linewidth=1.2, zorder=4)

            gt = r["ground_truth_tfa"]
            if pd.notna(gt):
                ax.bar(xi + width, float(gt), width,
                       color=color_b, alpha=0.45, edgecolor=color_b,
                       hatch="//", linewidth=0.8)

    # Dashed separators between OWASP suite groups
    prev_suite = None
    for i, probe in enumerate(probes_sorted):
        suite = PROBE_TO_SUITE.get(probe, "")
        if prev_suite is not None and suite != prev_suite:
            ax.axvline(x[i] - 0.5, color="#aaaaaa", linewidth=1.0,
                       linestyle="--", alpha=0.7)
        prev_suite = suite

    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=35, ha="right", fontsize=9)
    ax.set_ylim(0, 1.10)
    ax.set_ylabel("TFA (Tasa de Filtrado de Ataques)")
    ax.set_title(f"Comparación TFA: Garak vs Ground Truth — {_domain_label(domain)}")
    ax.axhline(1.0, color="gray", linewidth=0.8, linestyle="--", alpha=0.5)

    legend_handles = [
        mpatches.Patch(facecolor=color_a, alpha=0.85,
                       label="TFA Garak — Escenario A"),
        mpatches.Patch(facecolor=color_b, alpha=0.85,
                       label="TFA Garak — Escenario B"),
        mpatches.Patch(facecolor=color_b, alpha=0.45, hatch="//",
                       edgecolor=color_b,
                       label="Ground Truth TFA — Escenario B"),
    ]
    ax.legend(handles=legend_handles, fontsize=8.5, loc="lower right")

    fig.text(
        0.5, -0.06,
        "TFA Garak: mediana ± IQR sobre 5 repeticiones. "
        "Ground Truth: columna diferenciada por suite.",
        ha="center", va="top", fontsize=7.5, style="italic", color="#555555",
    )

    fig.tight_layout()
    _save(fig, figures_dir, f"garak_vs_ground_truth_{domain}.png")
    plt.close(fig)


def plot_garak_asr_boxplot(
    detail_df: pd.DataFrame,
    domain: str,
    figures_dir: Path,
    color_a: str = "#e07b39",
    color_b: str = "#1e5eff",
):
    """Box plot of Garak's ASR distribution across repetitions per probe.

    Two side-by-side boxes per probe: Scenario A (orange) and Scenario B
    (blue).  ASR = 1 − garak_tfa.  Probes sorted by OWASP suite, with dashed
    vertical separators between suite groups.  Probes for which a scenario has
    fewer than two repetitions are omitted from the corresponding box.

    Args:
        detail_df: Detailed DataFrame as returned by
            :func:`eval.metrics.compute_garak_asr_by_repetition` (i.e. the
            rows saved to ``garak_asr_by_repetition.csv``).
        domain: Domain name — used to filter ``detail_df`` and label the title.
        figures_dir: Directory where the PNG is saved.
        color_a: Box face color for Scenario A.
        color_b: Box face color for Scenario B.

    Outputs:
        - artifacts/figures/garak_asr_boxplot_{domain}.png
    """
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    import numpy as np
    setup_style()

    df = detail_df[detail_df["domain"] == domain].copy()
    if df.empty:
        print(f"  [skip] plot_garak_asr_boxplot: no data for {domain}")
        return

    df["garak_asr"] = 1.0 - df["garak_tfa"]

    suite_order = ["LLM01", "LLM02", "LLM07", "LLM08"]
    probes_all  = df["probe"].unique().tolist()
    probes_sorted = sorted(
        probes_all,
        key=lambda p: (
            suite_order.index(PROBE_TO_SUITE.get(p, ""))
            if PROBE_TO_SUITE.get(p, "") in suite_order else 99,
            p,
        ),
    )
    labels = [PROBE_SHORT.get(p, p) for p in probes_sorted]
    n      = len(probes_sorted)

    spacing    = 3.0
    gap        = 0.7
    pos_a      = [i * spacing for i in range(n)]
    pos_b      = [p + gap for p in pos_a]
    tick_pos   = [(pos_a[i] + pos_b[i]) / 2 for i in range(n)]

    fig, ax = plt.subplots(figsize=(max(12, n * 1.6), 5.5))

    prev_suite = None
    for i, probe in enumerate(probes_sorted):
        vals_a = (
            df[(df["probe"] == probe) & (df["scenario"] == "unprotected")]
            ["garak_asr"].dropna().values
        )
        vals_b = (
            df[(df["probe"] == probe) & (df["scenario"] == "protected")]
            ["garak_asr"].dropna().values
        )

        box_data   = []
        box_pos    = []
        box_colors = []
        if len(vals_a) >= 2:
            box_data.append(vals_a)
            box_pos.append(pos_a[i])
            box_colors.append(color_a)
        if len(vals_b) >= 2:
            box_data.append(vals_b)
            box_pos.append(pos_b[i])
            box_colors.append(color_b)

        if not box_data:
            continue

        bp = ax.boxplot(
            box_data, positions=box_pos, widths=0.55,
            patch_artist=True,
            medianprops={"color": "black", "linewidth": 2},
            flierprops={"marker": ".", "markersize": 4, "alpha": 0.5},
            whiskerprops={"linewidth": 1.2},
            capprops={"linewidth": 1.2},
        )
        for patch, color in zip(bp["boxes"], box_colors):
            patch.set_facecolor(color)
            patch.set_alpha(0.65)

        # Suite separator between groups
        suite = PROBE_TO_SUITE.get(probe, "")
        if prev_suite is not None and suite != prev_suite:
            sep_x = (pos_b[i - 1] + pos_a[i]) / 2
            ax.axvline(sep_x, color="#aaaaaa", linewidth=1.0,
                       linestyle="--", alpha=0.7)
        prev_suite = suite

    ax.set_xticks(tick_pos)
    ax.set_xticklabels(labels, rotation=35, ha="right", fontsize=9)
    ax.set_ylim(-0.05, 1.10)
    ax.set_ylabel("ASR Garak (1 − TFA Garak)")
    ax.set_title(f"Distribución ASR Garak por sonda — {_domain_label(domain)}")
    ax.axhline(0.0, color="gray", linewidth=0.8, linestyle="--", alpha=0.4)

    patch_a = mpatches.Patch(facecolor=color_a, alpha=0.65, label="Escenario A")
    patch_b = mpatches.Patch(facecolor=color_b, alpha=0.65, label="Escenario B")
    ax.legend(handles=[patch_a, patch_b], fontsize=9, loc="upper right")

    fig.tight_layout()
    _save(fig, figures_dir, f"garak_asr_boxplot_{domain}.png")
    plt.close(fig)


def generate_all_plots(tfa_by_domain: dict, lat_a: pd.DataFrame,
                       lat_b: pd.DataFrame, artifacts_dir: Path, runs_dir: Path, figures_dir: Path,
                       tfa_csv_by_domain: dict | None = None):
    """Generate all primary figures and save them to ``figures_dir``.

    Args:
        tfa_by_domain: Mapping of ``{domain: {"A": tfa_dict, "B": tfa_dict}}``
            as returned by ``load_tfa_from_jsonl`` (garak_passed-based).
        lat_a: Latency DataFrame for Scenario A.
        lat_b: Latency DataFrame for Scenario B.
        artifacts_dir: Root artifacts directory.
        runs_dir: Root runs directory (``artifacts_dir / "runs"``).
        figures_dir: Directory where all output PNGs are saved.
        tfa_csv_by_domain: Optional mapping with the same shape as
            ``tfa_by_domain``, sourced from ``load_tfa_from_csv``, used by the
            suite-level TFA charts (``plot_tfa_by_suite``,
            ``plot_tfa_domains_combined``) in place of the garak_passed-based
            values, which are only a valid ground truth for LLM01. When
            provided, also triggers ``plot_tfa_csv_by_suite_grouped`` and
            ``plot_tfa_global_weighted`` (the latter computed here from
            ``load_consolidated`` + ``compute_tfa_global`` per domain).
    """
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

    # Corrected TFA dict: per-probe and per-suite values use suite-specific GT columns
    # from consolidated CSVs (compute_tfa_per_probe / compute_tfa_by_suite), replacing
    # the JSONL garak_passed proxy that is wrong for non-LLM01 suites and for Scenario B
    # LLM01 when LLM Guard blocks requests before they reach the model.
    corrected_tfa_by_domain = _build_corrected_tfa(artifacts_dir, tfa_by_domain)

    for domain, data in tfa_by_domain.items():
        tfa_a, tfa_b = data["A"], data["B"]
        if not tfa_a:
            continue
        csv_d  = (tfa_csv_by_domain or {}).get(domain, {})
        corr_d = corrected_tfa_by_domain.get(domain, {})
        plot_tfa_by_probe(corr_d.get("A") or tfa_a, corr_d.get("B") or tfa_b, domain, figures_dir)
        plot_tfa_by_suite(tfa_a, tfa_b, domain, figures_dir,
                          tfa_csv_a=csv_d.get("A"), tfa_csv_b=csv_d.get("B"))

    plot_tfa_domains_combined(tfa_by_domain, figures_dir, tfa_csv_by_domain=tfa_csv_by_domain)

    if tfa_csv_by_domain:
        plot_tfa_csv_by_suite_grouped(tfa_csv_by_domain, figures_dir)

        global_tfa_by_domain = {}
        for domain in domains:
            df_a = load_consolidated(artifacts_dir, domain, "unprotected")
            df_b = load_consolidated(artifacts_dir, domain, "protected")
            global_a = compute_tfa_global(df_a) if not df_a.empty else None
            global_b = compute_tfa_global(df_b) if not df_b.empty else None
            global_tfa_by_domain[domain] = {"A": global_a, "B": global_b}
        plot_tfa_global_weighted(global_tfa_by_domain, figures_dir)

    # Use corrected dict for all per-probe and per-suite charts
    plot_tfa_heatmap(corrected_tfa_by_domain, figures_dir)
    plot_delta_tfa(corrected_tfa_by_domain, figures_dir)
    plot_pvalue_by_suite(corrected_tfa_by_domain, figures_dir)
    plot_confidential_exposure(artifacts_dir, domains, figures_dir)
    plot_las_boxplot(lat_a, lat_b, figures_dir)
    plot_las_boxplot(lat_a, lat_b, figures_dir, by_domain=True)
    plot_latency_histogram(lat_a, lat_b, figures_dir)
    plot_las_by_suite(lat_a, lat_b, figures_dir)
    plot_latency_distribution_by_suite(lat_a, figures_dir)
    plot_confusion_matrix_scenario_a(artifacts_dir, domains, figures_dir)
    plot_confusion_matrix(artifacts_dir, domains, figures_dir)
    plot_confusion_matrix_guard_only(artifacts_dir, domains, figures_dir)
    plot_detector_heatmap(runs_dir, domains, figures_dir)
    plot_security_posture_radar(tfa_by_domain, figures_dir)
    plot_tfa_suite_all_combos(corrected_tfa_by_domain, figures_dir)

    timings_df = compute_probe_timings(artifacts_dir)
    if not timings_df.empty:
        plot_probe_timings(timings_df, figures_dir)
    plot_probe_execution_time_total(artifacts_dir, domains, figures_dir)

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
    ALL_LABS   = ["Esc A\nAdv.", "Esc A\nLegít.", "Esc B\nAdv.", "Esc B\nLegít."]

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
            ax.set_title(f"{_domain_label(domain)}\n[sin datos]")
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
        ax.set_ylabel("Latencia (ms, escala log)")
        ax.set_title(_domain_label(domain), fontsize=11)

        # Scenario separator (only when both scenario groups are present)
        if any(p >= 3.0 for p in used_pos) and any(p < 3.0 for p in used_pos):
            ax.axvline(2.75, color="gray", linewidth=0.8, linestyle="--", alpha=0.5)

        patches = [
            mpatches.Patch(facecolor=PT_COLORS["adversarial"], alpha=0.7, label="Adversarial"),
            mpatches.Patch(facecolor=PT_COLORS["legitimate"],  alpha=0.7, label="Legítimo"),
        ]
        ax.legend(handles=patches, fontsize=8, loc="upper right")

    fig.suptitle(
        "Distribución de latencia: prompts adversariales vs legítimos (escala log)",
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
        on the left (no negative latency).

    **Per-subplot 99th-percentile x-axis clip:**
        Latency outliers (e.g. cold-start or retry spikes) can extend the x-axis
        by orders of magnitude and compress the bulk of the distribution into an
        unreadable sliver. Each subplot independently clips its right x-limit at
        ``np.percentile(latencies, 99)``, computed over all rows (adversarial +
        legitimate combined) for that domain × scenario combination. The KDE
        itself is still fit on the full (unclipped) data — only the displayed
        x-range is limited. A footnote on each subplot reports how many rows
        fall beyond the clip.

    **Median lines:**
        Because the KDE may show a mode that differs from the median (right-skewed
        data), explicit median lines are drawn to anchor the visual comparison at
        the statistically preferred central-tendency measure.

    Outputs
    -------
    - artifacts/figures/latency_adv_vs_legit_kde.png : KDE grid figure, dpi=150.
    """
    import matplotlib.pyplot as plt
    import numpy as np
    setup_style()

    SCENARIOS  = ["unprotected", "protected"]
    SCEN_LABEL = {"unprotected": "A", "protected": "B"}
    PT_COLORS  = {"adversarial": "#C44E52", "legitimate": "#4C72B0"}
    PT_LABEL_ES = {"adversarial": "Adversarial", "legitimate": "Legítimo"}

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

            all_lat = df["latency_ms"].dropna()
            if all_lat.empty:
                ax.set_visible(False)
                continue

            xmax       = np.percentile(all_lat.values, 99)
            n_outliers = int((all_lat > xmax).sum())

            plotted = False
            for pt in ("adversarial", "legitimate"):
                lat = df[df["prompt_type"] == pt]["latency_ms"].dropna()
                if lat.empty:
                    continue
                lat.plot.kde(ax=ax, color=PT_COLORS[pt], linewidth=2,
                             label=PT_LABEL_ES[pt])
                ax.axvline(lat.median(), color=PT_COLORS[pt], linewidth=1.2,
                           linestyle="--", alpha=0.7,
                           label=f"{pt[:3]}. mediana = {lat.median():.0f} ms")
                plotted   = True
                any_data  = True
            if plotted:
                ax.set_xlim(left=0, right=xmax)
                ax.set_xlabel("Latencia (ms)")
                ax.set_ylabel("Densidad")
                ax.set_title(
                    f"{_domain_label(domain)} — Escenario {SCEN_LABEL[scenario]}"
                )
                ax.legend(fontsize=8)
                ax.text(0.5, -0.22,
                        f"eje x recortado en el percentil 99; {n_outliers} valores "
                        f"atípicos excluidos",
                        transform=ax.transAxes, ha="center", va="top",
                        fontsize=7.5, style="italic", color="#555555")
            else:
                ax.set_visible(False)

    if not any_data:
        print("  [skip] latency_adv_vs_legit_kde: no data.")
        plt.close(fig)
        return

    fig.suptitle("KDE de latencia: prompts adversariales vs legítimos",
                 fontweight="bold", fontsize=12)
    fig.tight_layout()
    _save(fig, figures_dir, "latency_adv_vs_legit_kde.png")
    plt.close(fig)


def plot_fpr_by_domain_scenario(artifacts_dir: Path, domains: list, figures_dir: Path):
    """Bar chart of False Positive Rate (FPR) per domain — Scenario B only.

    FPR is defined as the proportion of legitimate prompts incorrectly blocked by
    the security layer:

        FPR = legitimate_blocked / total_legitimate

    Scenario A (unprotected) has no active classifier/blocking mechanism, so FPR
    is undefined (not zero) for it — there is nothing to compute a false-positive
    rate over. Scenario A is therefore omitted entirely; this figure shows one bar
    per domain, all from Scenario B (LLM Guard), with an explanatory annotation.

    Parameters
    ----------
    artifacts_dir : Path
        Root artifacts directory containing ``consolidated_<domain>_protected.csv``
        files.  Only rows with ``prompt_type == "legitimate"`` are used.
    domains : list
        Ordered list of domain names; one bar per domain.
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
    - artifacts/figures/fpr_by_domain_scenario.png : bar chart, dpi=150.
    """
    import matplotlib.pyplot as plt
    import numpy as np
    setup_style()

    fpr_data: dict[str, float | None] = {}
    for domain in domains:
        path = artifacts_dir / f"consolidated_{domain}_protected.csv"
        if not path.exists():
            fpr_data[domain] = None
            continue
        df    = pd.read_csv(path)
        legit = (df[df["prompt_type"] == "legitimate"].copy()
                 if "prompt_type" in df.columns else pd.DataFrame())
        if legit.empty or "was_blocked" not in legit.columns:
            fpr_data[domain] = None
            continue
        n  = len(legit)
        nb = int(pd.to_numeric(legit["was_blocked"], errors="coerce").fillna(0).sum())
        fpr_data[domain] = nb / n if n > 0 else 0.0

    x     = np.arange(len(domains))
    width = 0.5
    fig, ax = plt.subplots(figsize=(max(6, 3 * len(domains)), 5))

    vals = [fpr_data[d] or 0.0 for d in domains]
    bars = ax.bar(x, vals, width, label="B (LLM Guard)",
                   color="#DD8452", alpha=0.85, edgecolor="white")
    for bar, val, d in zip(bars, vals, domains):
        label = f"{val:.4f}" if fpr_data[d] is not None else "N/D"
        ax.text(bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.001,
                label, ha="center", va="bottom", fontsize=9, fontweight="bold")

    ax.set_ylim(0, max(vals) * 1.35 + 0.01)
    ax.set_xticks(x)
    ax.set_xticklabels([_domain_label(d) for d in domains], fontsize=10)
    ax.set_ylabel("Tasa de Falsos Positivos (FPR)")
    ax.set_title("FPR por dominio — Escenario B (LLM Guard)\n"
                 "(prompts legítimos bloqueados incorrectamente)")
    ax.axhline(0, color="black", linewidth=0.5)
    ax.legend(fontsize=9)
    fig.text(0.5, -0.02,
             "El Escenario A (sin protección) no tiene un clasificador activo, por lo "
             "que el FPR no aplica (N/D) por diseño y no se muestra.",
             ha="center", va="top", fontsize=8.5, style="italic", color="#555555")

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
    domain_labels = [_domain_label(d) for d in domains]
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
        ax.set_xlabel("Dominio")
        ax.set_title(title, fontsize=11, fontweight="bold")
        for i in range(len(all_probes)):
            for j in range(len(domains)):
                val = mat[i, j]
                if not np.isnan(val):
                    tc = "white" if (val < 0.3 or val > 0.72) else "black"
                    ax.text(j, i, f"{val:.2f}", ha="center", va="center",
                            fontsize=8, color=tc)
                else:
                    ax.text(j, i, "N/D", ha="center", va="center",
                            fontsize=7, color="#aaaaaa")
        return im

    im = _draw(axes[0], _build("A"), "Escenario A (sin protección)")
    if has_b:
        _draw(axes[1], _build("B"), "Escenario B (LLM Guard)")

    fig.colorbar(im, ax=axes[-1], label="TFA (Tasa de Filtrado de Ataques)", shrink=0.7)
    fig.suptitle("Mapa de calor de TFA: sonda × dominio — Escenario A vs B",
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
               label=_domain_label(domain),
               color=color, alpha=0.8, edgecolor="white")

    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=35, ha="right", fontsize=9)
    ax.axhline(0, color="black", linewidth=0.8)
    ax.set_xlabel("Sonda")
    ax.set_ylabel("ΔTFA (Escenario B − Escenario A)")
    ax.set_title("ΔTFA por sonda y dominio — Contribución neta de LLM Guard")
    ax.legend(fontsize=9, title="Dominio")
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
            ax.set_title(f"{_domain_label(domain)}\n[sin datos de Escenario B]")
            ax.set_visible(False)
            continue
        df = pd.read_csv(path)
        if "prompt_type" in df.columns:
            df = df[df["prompt_type"] == "adversarial"].copy()
        if df.empty or "probe" not in df.columns or "scanner_triggered" not in df.columns:
            ax.set_title(f"{_domain_label(domain)}\n[columnas faltantes]")
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
        ax.set_xlabel("Sonda")
        ax.set_ylabel("Prompts adversariales (cantidad)")
        ax.set_title(_domain_label(domain))
        ax.legend(title="Scanner activado", fontsize=7.5, loc="upper right")
        any_data = True

    if not any_data:
        print("  [skip] scanner_breakdown_by_probe: no Scenario B adversarial data.")
        plt.close(fig)
        return

    fig.suptitle(
        "Activación de scanners por sonda\nEscenario B — Prompts adversariales",
        fontweight="bold",
    )
    fig.tight_layout()
    _save(fig, figures_dir, "scanner_breakdown_by_probe.png")
    plt.close(fig)


def plot_repetition_variance(figures_dir: Path):
    """Repetition stability chart — TFA mean/std/min-max per probe, Scenario A.

    Reads ``artifacts/characterization/repetition_variance.csv`` (produced by
    ``characterizer.py``) and, for each domain, draws one row per probe with a
    gray min-max range bar and a diamond marker (colored by OWASP suite) at
    the mean TFA with a ±std error bar. Probes are sorted by mean TFA
    ascending. Scenario B is excluded.

    Args:
        figures_dir: Directory where the PNG is saved. The CSV is read from
            ``figures_dir.parent / "characterization" / "repetition_variance.csv"``.

    Outputs:
        - artifacts/figures/fig_repetition_variance_stability.png
    """
    import matplotlib.pyplot as plt
    import matplotlib.lines as mlines
    import numpy as np

    csv_path = figures_dir.parent / "characterization" / "repetition_variance.csv"
    if not csv_path.exists():
        print(f"  [skip] repetition variance: {csv_path} not found.")
        return
    setup_style()

    df   = pd.read_csv(csv_path)
    df_a = df[df["scenario"] == "A"]
    domains = sorted(df_a["domain"].unique())
    if not domains:
        print("  [skip] repetition variance: no Scenario A rows.")
        return

    fig, axes = plt.subplots(1, len(domains), figsize=(8 * len(domains), 6))
    if len(domains) == 1:
        axes = [axes]

    for ax, domain in zip(axes, domains):
        sub    = df_a[df_a["domain"] == domain].sort_values("mean")
        y      = np.arange(len(sub))
        labels = [PROBE_SHORT.get(p, p) for p in sub["probe"]]

        ax.hlines(y, sub["min"], sub["max"], color="#bbbbbb",
                  linewidth=3, alpha=0.7, zorder=1)
        for yi, (_, row) in zip(y, sub.iterrows()):
            color = SUITE_COLORS.get(row["suite"], "#888888")
            ax.errorbar(row["mean"], yi, xerr=row["std"], fmt="D",
                         color=color, ecolor=color, elinewidth=1.5,
                         capsize=3, markersize=7, zorder=3)

        ax.set_yticks(y)
        ax.set_yticklabels(labels, fontsize=9)
        ax.set_xlim(0, 1.05)
        ax.axvline(1.0, color="gray", linewidth=0.8, linestyle="--", alpha=0.5)
        ax.set_xlabel("TFA (media ± desv. est., rango mín–máx)")
        ax.set_title(_domain_label(domain), fontsize=10)

    axes[0].text(0.02, 0.98, "Toda desv. est. < 0.03\nNo se detectaron sondas de alta varianza",
                  transform=axes[0].transAxes, fontsize=8.5, va="top", ha="left",
                  bbox=dict(boxstyle="round,pad=0.4", facecolor="white",
                            edgecolor="gray", alpha=0.85))

    suite_handles = [mlines.Line2D([], [], color=c, marker="D", linestyle="None",
                                    markersize=7, label=s)
                     for s, c in SUITE_COLORS.items()]
    fig.legend(handles=suite_handles, title="Suite OWASP", loc="lower center",
               ncol=len(SUITE_COLORS), fontsize=9, bbox_to_anchor=(0.5, -0.05))

    fig.suptitle("Estabilidad de repetición de TFA — Escenario A (5 ejecuciones por sonda)",
                  fontweight="bold")
    fig.tight_layout()
    _save(fig, figures_dir, "fig_repetition_variance_stability.png")
    plt.close(fig)


def plot_las_adv_vs_legit_summary(figures_dir: Path):
    """Median latency bar chart from the precomputed summary CSV, adv vs legit.

    Reads ``artifacts/characterization/latency_comparison.csv`` (produced by
    ``characterizer.py``) and draws one bar per (domain, scenario,
    prompt_type) combination — 8 bars total. Scenario B bars get a dashed
    border to distinguish them. Annotates the "early blocking" paradox: the
    adversarial median latency drops in Scenario B (LLM Guard blocks before
    LLM inference) while the legitimate median rises (full inference + proxy
    overhead).

    Args:
        figures_dir: Directory where the PNG is saved. The CSV is read from
            ``figures_dir.parent / "characterization" / "latency_comparison.csv"``.

    Outputs:
        - artifacts/figures/fig_las_adv_vs_legit_summary.png
    """
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    import numpy as np

    csv_path = figures_dir.parent / "characterization" / "latency_comparison.csv"
    if not csv_path.exists():
        print(f"  [skip] LAS adv vs legit summary: {csv_path} not found.")
        return
    setup_style()

    df = pd.read_csv(csv_path)

    groups = [
        ("academic_institutional", "A", "adversarial", "Acad A\nadv"),
        ("academic_institutional", "A", "legitimate",  "Acad A\nleg"),
        ("academic_institutional", "B", "adversarial", "Acad B\nadv"),
        ("academic_institutional", "B", "legitimate",  "Acad B\nleg"),
        ("regulatory_technical",   "A", "adversarial", "Reg A\nadv"),
        ("regulatory_technical",   "A", "legitimate",  "Reg A\nleg"),
        ("regulatory_technical",   "B", "adversarial", "Reg B\nadv"),
        ("regulatory_technical",   "B", "legitimate",  "Reg B\nleg"),
    ]

    ADV_COLOR, ADV_DARK = "#888780", "#5C5B56"
    LEG_COLOR, LEG_DARK = "#2471A3", "#1A4F73"

    x = np.arange(len(groups))
    values, edgecolors, linewidths, linestyles, colors = [], [], [], [], []
    for domain, scenario, prompt_type, _ in groups:
        row = df[(df["domain"] == domain) & (df["scenario"] == scenario)
                 & (df["prompt_type"] == prompt_type)]
        val = float(row["median"].iloc[0]) if not row.empty else 0.0
        values.append(val)

        is_adv = prompt_type == "adversarial"
        colors.append(ADV_COLOR if is_adv else LEG_COLOR)
        if scenario == "B":
            edgecolors.append(ADV_DARK if is_adv else LEG_DARK)
            linewidths.append(1.5)
            linestyles.append("--")
        else:
            edgecolors.append("white")
            linewidths.append(1.0)
            linestyles.append("-")

    fig, ax = plt.subplots(figsize=(12, 6))
    bars = ax.bar(x, values, width=0.6, color=colors, alpha=0.85)
    for bar, ec, lw, ls in zip(bars, edgecolors, linewidths, linestyles):
        bar.set_edgecolor(ec)
        bar.set_linewidth(lw)
        bar.set_linestyle(ls)

    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + max(values) * 0.01,
                f"{val:.0f}", ha="center", va="bottom", fontsize=8.5, fontweight="bold")

    ax.set_xticks(x)
    ax.set_xticklabels([g[3] for g in groups], fontsize=9)
    ax.set_ylabel("Latencia mediana (ms)")
    ax.set_title("LAS — latencia mediana por escenario, dominio y tipo de prompt")
    ax.set_ylim(0, max(values) * 1.35)

    # Early-blocking paradox annotation: Acad A adv (x=0) vs Acad B adv (x=2)
    y_arrow = max(values[0], values[2]) * 1.25
    ax.annotate("", xy=(x[0], y_arrow), xytext=(x[2], y_arrow),
                arrowprops=dict(arrowstyle="<->", color="black", lw=1.2))
    ax.text((x[0] + x[2]) / 2, y_arrow * 1.03, "Bloqueo temprano\n↓ mediana adv",
            ha="center", va="bottom", fontsize=8.5, style="italic")

    note = ("La mediana adversarial baja en el Escenario B: LLM Guard bloquea antes "
            "de la inferencia del LLM.\n"
            "La mediana legítima sube: inferencia LLM completa + sobrecarga del proxy.")
    ax.text(0.98, 0.95, note, transform=ax.transAxes, fontsize=8,
            ha="right", va="top",
            bbox=dict(boxstyle="round,pad=0.5", facecolor="white", edgecolor="gray", alpha=0.85))

    handles = [
        mpatches.Patch(facecolor=ADV_COLOR, alpha=0.85, label="Adversarial"),
        mpatches.Patch(facecolor=LEG_COLOR, alpha=0.85, label="Legítimo"),
        mpatches.Patch(facecolor="white", edgecolor=ADV_DARK, linestyle="--",
                       linewidth=1.5, label="Escenario B (borde discontinuo)"),
    ]
    ax.legend(handles=handles, fontsize=8.5, loc="upper left")

    fig.tight_layout()
    _save(fig, figures_dir, "fig_las_adv_vs_legit_summary.png")
    plt.close(fig)


def generate_segmented_plots(
    artifacts_dir: Path, domains: list, tfa_by_domain: dict, figures_dir: Path,
    tfa_csv_by_domain: dict | None = None,
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
    tfa_csv_by_domain : dict, optional
        Mapping with the same shape as ``tfa_by_domain``, sourced from
        ``load_tfa_from_csv``. Accepted for signature symmetry with
        ``generate_all_plots`` and forwarded from ``process_results.py``, but
        currently unused here: none of this function's plots render
        suite-level bars (they use per-probe data, valid only for LLM01, or
        CSV columns directly), so there is nothing to substitute yet.

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

    # Use corrected per-probe TFA (suite-specific GT columns) for the AB heatmap and ΔTFA chart.
    corrected_tfa_by_domain = _build_corrected_tfa(artifacts_dir, tfa_by_domain)

    plot_latency_adv_vs_legit_boxplot(artifacts_dir, domains, figures_dir)
    plot_latency_adv_vs_legit_kde(artifacts_dir, domains, figures_dir)
    plot_fpr_by_domain_scenario(artifacts_dir, domains, figures_dir)
    plot_tfa_heatmap_ab_comparison(corrected_tfa_by_domain, figures_dir)
    plot_delta_tfa_by_domain(corrected_tfa_by_domain, figures_dir)
    plot_scanner_breakdown_by_probe(artifacts_dir, domains, figures_dir)
    plot_repetition_variance(figures_dir)
    plot_las_adv_vs_legit_summary(figures_dir)

    n = len(list(figures_dir.glob("*.png")))
    print(f"\n  Segmented figures complete. {n} total figures in {figures_dir}.\n")


# ─────────────────────────────────────────────
# Probe execution timing chart
# ─────────────────────────────────────────────

def plot_probe_timings(df: pd.DataFrame, output_dir: Path) -> None:
    """Plot median probe execution times as horizontal grouped bar charts, one per domain.

    For each domain present in ``df``, generates one figure with two bar groups
    per probe — Scenario A (unprotected, ``#e07b39``) and Scenario B (protected,
    ``#1e5eff``) — where the bar length is the median execution time in minutes
    across the five repetitions and error bars span the interquartile range (IQR).

    Probes are ordered from top to bottom by OWASP suite
    (LLM01 → LLM02 → LLM07 → LLM08) then alphabetically within each suite.
    Suite boundaries are marked with a dashed horizontal separator and a
    colour-coded suite label on the right margin.  Probe labels use the short
    display names from :data:`PROBE_SHORT`.

    Parameters
    ----------
    df : pd.DataFrame
        Per-repetition timing data as returned by
        :func:`eval.metrics.compute_probe_timings`.  Required columns:
        ``domain``, ``scenario``, ``suite``, ``probe``, ``repetition``,
        ``duration_seconds``.
    output_dir : Path
        Directory where output PDF files are saved (created if absent).
        One file per domain: ``probe_timings_<domain>.pdf``.

    Notes
    -----
    Duration values are converted from seconds to minutes before plotting.
    Rows with ``duration_seconds = NaN`` (the first file of each run, which has
    no preceding file to delta from) are dropped before aggregation so they do
    not bias the median or IQR estimates.

    The function is generic: it derives domains, scenarios, and probe sets from
    ``df`` rather than from any hardcoded list, so it adapts automatically to
    whatever runs are present in ``artifacts/runs/``.

    Outputs
    -------
    ``<output_dir>/probe_timings_<domain>.pdf`` for every domain in ``df``.
    """
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    import numpy as np

    _SUITE_ORDER     = ["LLM01", "LLM02", "LLM07", "LLM08"]
    _SCENARIO_COLORS = {"unprotected": "#e07b39", "protected": "#1e5eff"}
    _SCENARIO_LABELS = {
        "unprotected": "Escenario A (sin protección)",
        "protected":   "Escenario B (LLM Guard)",
    }
    _BAR_HEIGHT = 0.35

    output_dir.mkdir(parents=True, exist_ok=True)
    setup_style()

    # Drop NaN durations (first rep of each run) and convert to minutes.
    df_valid = df.dropna(subset=["duration_seconds"]).copy()
    df_valid["duration_minutes"] = df_valid["duration_seconds"] / 60.0

    domains = sorted(df_valid["domain"].unique())
    if not domains:
        print("  [skip] probe timings: no valid duration data found.")
        return

    for domain in domains:
        df_dom    = df_valid[df_valid["domain"] == domain]
        scenarios = [s for s in ("unprotected", "protected")
                     if s in df_dom["scenario"].unique()]
        if not scenarios:
            continue

        # Probe ordering: suite rank first, then alphabetical within suite.
        all_probes = df_dom["probe"].unique().tolist()

        def _sort_key(p: str) -> tuple:
            suite_vals = df_dom.loc[df_dom["probe"] == p, "suite"]
            suite      = suite_vals.iloc[0] if len(suite_vals) > 0 else "ZZZ"
            rank       = _SUITE_ORDER.index(suite) if suite in _SUITE_ORDER else len(_SUITE_ORDER)
            return (rank, p)

        ordered_probes = sorted(all_probes, key=_sort_key)
        n_probes = len(ordered_probes)
        if n_probes == 0:
            continue

        y_base  = np.arange(n_probes, dtype=float)
        n_scen  = len(scenarios)
        offsets = np.linspace(
            -_BAR_HEIGHT * (n_scen - 1) / 2,
             _BAR_HEIGHT * (n_scen - 1) / 2,
            n_scen,
        )

        fig_height = max(5.0, n_probes * 0.85 + 1.5)
        fig, ax    = plt.subplots(figsize=(11, fig_height))

        for idx, scenario in enumerate(scenarios):
            df_s  = df_dom[df_dom["scenario"] == scenario]
            color = _SCENARIO_COLORS.get(scenario, "#888888")
            label = _SCENARIO_LABELS.get(scenario, scenario)

            medians: list[float] = []
            xerr_lo: list[float] = []
            xerr_hi: list[float] = []

            for probe in ordered_probes:
                vals = df_s.loc[df_s["probe"] == probe, "duration_minutes"].dropna()
                if vals.empty:
                    medians.append(0.0)
                    xerr_lo.append(0.0)
                    xerr_hi.append(0.0)
                    continue
                med = float(vals.median())
                q1  = float(vals.quantile(0.25))
                q3  = float(vals.quantile(0.75))
                medians.append(med)
                xerr_lo.append(max(med - q1, 0.0))
                xerr_hi.append(max(q3 - med, 0.0))

            ax.barh(
                y_base + offsets[idx], medians,
                height=_BAR_HEIGHT,
                color=color, alpha=0.85, edgecolor="white",
                xerr=[xerr_lo, xerr_hi],
                error_kw={"ecolor": "#555555", "capsize": 3, "elinewidth": 1.2},
                label=label,
                zorder=3,
            )

        # Suite group separators and right-margin labels.
        blended        = ax.get_yaxis_transform()
        prev_suite     = None
        suite_first_y: dict[str, float] = {}

        for i, probe in enumerate(ordered_probes):
            suite_vals = df_dom.loc[df_dom["probe"] == probe, "suite"]
            suite      = suite_vals.iloc[0] if len(suite_vals) > 0 else ""
            if suite != prev_suite:
                if prev_suite is not None:
                    ax.axhline(
                        y=y_base[i] - 0.5, color="#bbbbbb",
                        linewidth=0.8, linestyle="--", alpha=0.7, zorder=1,
                    )
                suite_first_y[suite] = y_base[i]
            prev_suite = suite

        for suite, y_pos in suite_first_y.items():
            ax.text(
                1.01, y_pos, suite,
                transform=blended,
                fontsize=8, color=SUITE_COLORS.get(suite, "#888888"),
                va="center", ha="left", fontweight="bold",
            )

        y_labels = [PROBE_SHORT.get(p, p.split(".")[-1]) for p in ordered_probes]
        ax.set_yticks(y_base)
        ax.set_yticklabels(y_labels, fontsize=9)
        ax.invert_yaxis()
        ax.set_xlabel(
            "Duración mediana (minutos)\n"
            "Barras de error: IQR (Q1–Q3) sobre las 5 repeticiones",
            fontsize=9,
        )
        ax.set_title(
            f"Tiempo de ejecución por sonda — {_domain_label(domain)}\n"
            "Mediana ± IQR sobre 5 repeticiones",
            fontweight="bold",
        )
        ax.legend(fontsize=9, loc="lower right")
        ax.grid(axis="x", alpha=0.3)

        fig.tight_layout()

        out_path = output_dir / f"probe_timings_{domain}.pdf"
        fig.savefig(str(out_path), format="pdf", bbox_inches="tight")
        print(f"  [saved] {out_path}")
        _save(fig, output_dir, f"probe_execution_time_median_{domain}.png")
        plt.close(fig)


def plot_probe_execution_time_total(
    artifacts_dir: Path, domains: list, figures_dir: Path,
) -> None:
    """Plot total probe execution times as horizontal grouped bar charts, one per domain,

    and also generates a summary vertical bar chart per domain comparing overall execution times.
    """
    import matplotlib.pyplot as plt
    import numpy as np
    import pandas as pd

    _SUITE_ORDER     = ["LLM01", "LLM02", "LLM07", "LLM08"]
    _SCENARIO_COLORS = {"unprotected": "#e07b39", "protected": "#1e5eff"}
    _SCENARIO_LABELS = {
        "unprotected": "Escenario A (sin protección)",
        "protected":   "Escenario B (LLM Guard)",
    }
    _BAR_HEIGHT = 0.35

    figures_dir.mkdir(parents=True, exist_ok=True)
    setup_style()

    for domain in domains:
        # Build probe→suite mapping from whichever CSVs are available.
        probe_suite: dict[str, str] = {}
        for scenario_key in ("unprotected", "protected"):
            path = artifacts_dir / f"consolidated_{domain}_{scenario_key}.csv"
            if not path.exists():
                continue
            df_tmp = pd.read_csv(path, usecols=lambda c: c in ("probe", "suite", "prompt_type"))
            if "prompt_type" in df_tmp.columns:
                df_tmp = df_tmp[df_tmp["prompt_type"] == "adversarial"]
            df_tmp = df_tmp[["probe", "suite"]].dropna(subset=["probe"]).drop_duplicates()
            for _, row in df_tmp.iterrows():
                probe_suite.setdefault(str(row["probe"]), str(row["suite"]))

        if not probe_suite:
            print(f"  [skip] probe_execution_time_total: no data for {domain}")
            continue

        def _sort_key(p: str) -> tuple:
            suite = probe_suite.get(p, "ZZZ")
            rank  = _SUITE_ORDER.index(suite) if suite in _SUITE_ORDER else len(_SUITE_ORDER)
            return (rank, p)

        ordered_probes = sorted(probe_suite.keys(), key=_sort_key)
        n_probes       = len(ordered_probes)

        scenarios_present = [
            s for s in ("unprotected", "protected")
            if (artifacts_dir / f"consolidated_{domain}_{s}.csv").exists()
        ]
        if not scenarios_present:
            continue

        # ==========================================
        # 1. PROBE-LEVEL CHART (ORIGINAL LOGIC)
        # ==========================================
        y_base  = np.arange(n_probes, dtype=float)
        n_scen  = len(scenarios_present)
        offsets = np.linspace(
            -_BAR_HEIGHT * (n_scen - 1) / 2,
             _BAR_HEIGHT * (n_scen - 1) / 2,
            n_scen,
        )

        fig_height = max(5.0, n_probes * 0.85 + 1.5)
        fig, ax    = plt.subplots(figsize=(11, fig_height))

        # List to accumulate macro-level total timing data for the whole domain
        domain_macro_data = []

        for idx, scenario in enumerate(scenarios_present):
            path = artifacts_dir / f"consolidated_{domain}_{scenario}.csv"
            df   = pd.read_csv(path)
            if "latency_ms" not in df.columns or "probe" not in df.columns:
                continue

            if "prompt_type" in df.columns:
                df = df[df["prompt_type"] == "adversarial"].copy()

            df["latency_ms"] = pd.to_numeric(df["latency_ms"], errors="coerce")

            color = _SCENARIO_COLORS.get(scenario, "#888888")
            label = _SCENARIO_LABELS.get(scenario, scenario)

            medians: list[float] = []
            xerr_lo: list[float] = []
            xerr_hi: list[float] = []

            for probe in ordered_probes:
                sub = df[df["probe"] == probe].reset_index(drop=True)
                if sub.empty:
                    medians.append(0.0)
                    xerr_lo.append(0.0)
                    xerr_hi.append(0.0)
                    continue

                # Corrected safe check for repetition column
                if "repetition" in sub.columns and sub["repetition"].notna().any():
                    rep_totals = sub.groupby("repetition")["latency_ms"].sum() / 60_000
                else:
                    n = len(sub)
                    rep_idx = (sub.index * 5) // n
                    rep_totals = sub.groupby(rep_idx)["latency_ms"].sum() / 60_000

                med_val = float(rep_totals.median())
                min_val = float(rep_totals.min())
                max_val = float(rep_totals.max())
                medians.append(med_val)
                xerr_lo.append(max(med_val - min_val, 0.0))
                xerr_hi.append(max(max_val - med_val, 0.0))

            ax.barh(
                y_base + offsets[idx], medians,
                height=_BAR_HEIGHT,
                color=color, alpha=0.85, edgecolor="white",
                xerr=[xerr_lo, xerr_hi],
                error_kw={"ecolor": "#555555", "capsize": 3, "elinewidth": 1.2},
                label=label,
                zorder=3,
            )

            # --- ADDON LOGIC: Calculate Total Overall Experiment Duration (FIXED) ---
            if "repetition" in df.columns and df["repetition"].notna().any():
                macro_rep_totals = df.groupby("repetition")["latency_ms"].sum() / 60_000
            else:
                n_macro = len(df)
                macro_rep_idx = (df.index * 5) // n_macro if n_macro > 0 else []
                macro_rep_totals = df.groupby(macro_rep_idx)["latency_ms"].sum() / 60_000 if n_macro > 0 else pd.Series([0.0])

            m_med = float(macro_rep_totals.median())
            m_min = float(macro_rep_totals.min())
            m_max = float(macro_rep_totals.max())

            domain_macro_data.append({
                "scenario": scenario,
                "label": "Escenario A\n(sin protección)" if scenario == "unprotected" else "Escenario B\n(LLM Guard)",
                "color": color,
                "median": m_med,
                "err_lo": max(m_med - m_min, 0.0),
                "err_hi": max(m_max - m_med, 0.0)
            })

        # Suite separators and right-margin labels (Original).
        blended        = ax.get_yaxis_transform()
        prev_suite     = None
        suite_first_y: dict[str, float] = {}

        for i, probe in enumerate(ordered_probes):
            suite = probe_suite.get(probe, "")
            if suite != prev_suite:
                if prev_suite is not None:
                    ax.axhline(
                        y=y_base[i] - 0.5, color="#bbbbbb",
                        linewidth=0.8, linestyle="--", alpha=0.7, zorder=1,
                    )
                suite_first_y[suite] = y_base[i]
            prev_suite = suite

        for suite, y_pos in suite_first_y.items():
            ax.text(
                1.01, y_pos, suite,
                transform=blended,
                fontsize=8, color=SUITE_COLORS.get(suite, "#888888"),
                va="center", ha="left", fontweight="bold",
            )

        y_labels = [PROBE_SHORT.get(p, p.split(".")[-1]) for p in ordered_probes]
        ax.set_yticks(y_base)
        ax.set_yticklabels(y_labels, fontsize=9)
        ax.invert_yaxis()
        ax.set_xlabel(
            "Duración total (minutos) — mediana de 5 repeticiones\n"
            "Barras de error: rango mín–máx sobre las 5 repeticiones",
            fontsize=9,
        )
        ax.set_title(
            f"Tiempo total de ejecución por sonda — {_domain_label(domain)}\n"
            "Suma de latencias/rep → mediana (mín–máx sobre 5 rep.)",
            fontweight="bold",
        )
        ax.legend(fontsize=9, loc="lower right")
        ax.grid(axis="x", alpha=0.3)

        fig.tight_layout()
        _save(fig, figures_dir, f"probe_execution_time_total_{domain}.png")
        plt.close(fig)

        # ==========================================
        # 2. OVERALL DOMAIN SUMMARY CHART (FIXED)
        # ==========================================
        if domain_macro_data:
            fig_m, ax_m = plt.subplots(figsize=(6, 5))
            
            x_pos_m   = np.arange(len(domain_macro_data))
            medians_m = [d["median"] for d in domain_macro_data]
            colors_m  = [d["color"] for d in domain_macro_data]
            labels_m  = [d["label"] for d in domain_macro_data]
            xerr_m    = [[d["err_lo"] for d in domain_macro_data], [d["err_hi"] for d in domain_macro_data]]

            bars_m = ax_m.bar(
                x_pos_m, medians_m,
                width=0.45,
                color=colors_m, alpha=0.85, edgecolor="white",
                yerr=xerr_m,
                error_kw={"ecolor": "#555555", "capsize": 5, "elinewidth": 1.5},
                zorder=3
            )

            for bar in bars_m:
                h = bar.get_height()
                ax_m.annotate(
                    f"{h:.2f} min",
                    xy=(bar.get_x() + bar.get_width() / 2, h),
                    xytext=(0, 5),
                    textcoords="offset points",
                    ha="center", va="bottom", fontsize=9, fontweight="bold"
                )

            ax_m.set_xticks(x_pos_m)
            ax_m.set_xticklabels(labels_m, fontsize=10)
            ax_m.set_ylabel("Duración total del experimento (minutos)", fontsize=10)
            
            if medians_m:
                absolute_maxs = [d["median"] + d["err_hi"] for d in domain_macro_data]
                ax_m.set_ylim(0, max(absolute_maxs) * 1.15)

            domain_title = _domain_label(domain) if "_domain_label" in globals() else domain
            ax_m.set_title(
                f"Tiempo total de ejecución — {domain_title}\n"
                "Mediana y rango mín–máx (5 repeticiones completas)",
                fontweight="bold", fontsize=11, pad=15
            )
            ax_m.grid(axis="y", alpha=0.3, zorder=1)

            fig_m.tight_layout()
            _save(fig_m, figures_dir, f"experiment_execution_time_total_{domain}.png")
            plt.close(fig_m)