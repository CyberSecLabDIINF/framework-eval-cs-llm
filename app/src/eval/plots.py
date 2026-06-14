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
    SCENARIO_COLORS,
    SUITE_COLORS,
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
from eval.metrics import print_tfa


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

        if not tfa_a:
            # No Scenario A data for this domain yet: render a placeholder so
            # the figure still has one panel per domain (matching the title)
            # instead of raising on tfa_a["per_suite"] and aborting before
            # _save() — which previously left a stale single-panel PNG.
            ax.set_title(f"{domain.replace('_', ' ').title()}\n[no data]", fontsize=10)
            ax.set_xticks([])
            continue

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
    if len(domains) == 2:
        title = "TFA per OWASP Suite — Both Domains"
    elif len(domains) == 1:
        title = f"TFA per OWASP Suite — {domains[0].replace('_', ' ').title()}"
    else:
        title = "TFA per OWASP Suite — All Domains"
    fig.suptitle(title, fontweight="bold")
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
            ax.set_yscale("log")
        fig.suptitle(
            "Latency Distribution per Domain\n"
            "(y-axis in log scale; extreme outliers shown)",
            fontweight="bold")
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
        ax.set_yscale("log")
        ax.set_ylabel("Latency (ms)")
        ax.set_title(
            "Latency Distribution — Scenario A vs B\n"
            "(y-axis in log scale; extreme outliers shown)")
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
        fig.text(0.5, -0.02,
                 "Note: a lower median in Scenario B for some suites (e.g. LLM01, LLM08) "
                 "reflects early blocking by LLM Guard before model inference.",
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

def _render_confusion_matrices(
    matrices: list,
    valid_domains: list,
    title: str,
    filename: str,
    figures_dir: Path,
    recall_label: str = "Recall",
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

    row_labels = ["Actual\nATTACK", "Actual\nLEGIT"]

    for ax, domain, matrix in zip(axes, valid_domains, matrices):
        total = matrix.sum()
        # Normalize for color, show raw counts as annotation
        norm = matrix / total if total > 0 else matrix

        ax.imshow(norm, cmap="Blues", vmin=0, vmax=1)

        ax.set_xticks([0, 1])
        ax.set_xticklabels(["Predicted\nBLOCK", "Predicted\nPASS"], fontsize=9)
        ax.set_yticks([0, 1])
        ax.set_yticklabels(row_labels, fontsize=9)

        cell_labels = [["TP", "FN"], ["FP", "TN"]]

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
                 f"{recall_label}: {recall:.3f}\n"
                 f"F1: {f1:.3f}\n"
                 f"Specificity: {specificity:.3f}")
        ax.text(1.35, 0.5, stats,
                transform=ax.transAxes,
                fontsize=8.5, va="center",
                bbox=dict(boxstyle="round,pad=0.4", facecolor="white",
                          edgecolor="gray", alpha=0.85))

        ax.set_title(domain.replace("_", " ").title(), fontsize=10)

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
        title="Confusion Matrix — Scenario B, System-Level (Two-Layer)",
        filename="confusion_matrix_scenario_b.png",
        figures_dir=figures_dir,
        recall_label="Recall (TFA_B)",
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
        title="Confusion Matrix — Scenario B, LLM Guard Only (Single-Layer)",
        filename="confusion_matrix_scenario_b_llmguard_only.png",
        figures_dir=figures_dir,
        recall_label="Recall",
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
    plot_confusion_matrix_guard_only(artifacts_dir, domains, figures_dir)
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
                             label=pt.capitalize())
                ax.axvline(lat.median(), color=PT_COLORS[pt], linewidth=1.2,
                           linestyle="--", alpha=0.7,
                           label=f"{pt[:3]}. median = {lat.median():.0f} ms")
                plotted   = True
                any_data  = True
            if plotted:
                ax.set_xlim(left=0, right=xmax)
                ax.set_xlabel("Latency (ms)")
                ax.set_ylabel("Density")
                ax.set_title(
                    f"{domain.replace('_', ' ').title()} — Scenario {SCEN_LABEL[scenario]}"
                )
                ax.legend(fontsize=8)
                ax.text(0.5, -0.22,
                        f"x-axis clipped at 99th percentile; {n_outliers} outliers excluded",
                        transform=ax.transAxes, ha="center", va="top",
                        fontsize=7.5, style="italic", color="#555555")
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
        label = f"{val:.4f}" if fpr_data[d] is not None else "N/A"
        ax.text(bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.001,
                label, ha="center", va="bottom", fontsize=9, fontweight="bold")

    ax.set_ylim(0, max(vals) * 1.35 + 0.01)
    ax.set_xticks(x)
    ax.set_xticklabels([d.replace("_", " ").title() for d in domains], fontsize=10)
    ax.set_ylabel("False Positive Rate (FPR)")
    ax.set_title("FPR per Domain — Scenario B (LLM Guard)\n"
                 "(Legitimate prompts incorrectly blocked)")
    ax.axhline(0, color="black", linewidth=0.5)
    ax.legend(fontsize=9)
    fig.text(0.5, -0.02,
             "Scenario A (unprotected) has no active classifier, so FPR is N/A "
             "by design and is not shown.",
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

