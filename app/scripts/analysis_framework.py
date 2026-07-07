#!/usr/bin/env python3
"""
Generación de gráficos PCC a partir de controles_llmsec.csv

Produce DOCE figuras distribuidas según el análisis requerido:
- 4 Gráficos de barras individuales (Ecosistema Global)
- 4 Gráficos de torta individuales con leyendas (Solo Verificables de Laboratorio)
- 4 Gráficos de barras dobles comparativas (Totalidad vs Verificables)

Figuras generadas:
[Globales - Barras]
1. pcc_fuente_evidencia.png
2. pcc_subdimension.png
3. pcc_nivel.png
4. pcc_funcional.png

[Verificables - Tortas]
5. pcc_fuente_evidencia_verificables.png
6. pcc_subdimension_verificables.png
7. pcc_nivel_verificables.png
8. pcc_funcional_verificables.png

[Comparativas - Barras Dobles]
9. pcc_comparativa_evidencia.png
10. pcc_comparativa_subdimension.png
11. pcc_comparativa_nivel.png
12. pcc_comparativa_funcional.png
"""

import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

sns.set_theme(style="whitegrid")

plt.rcParams.update({
    "font.size": 11,
    "axes.labelsize": 12,
    "axes.titlesize": 14,
})

# Paleta de colores solicitada (versiones estéticas para reportes)
PALETA_COLORES = [
    "#4C72B0",  # Azul bonito
    "#F4CB42",  # Amarillo bonito
    "#E15759",  # Rojo bonito
    "#55A868"   # Verde bonito
]

# ------------------------------------------------------------
# CONFIGURACIONES Y ÓRDENES
# ------------------------------------------------------------

ORDERS = {
    "Fuente_Evidencia": ["Configuración", "Experimental", "Declarativo"],
    "Subdimension": ["D1", "D2", "D3", "D4", "D5"],
    "Nivel": ["N1", "N2", "N3", "N4", "N5"],
    "Tipo_Funcional": ["Preventivo", "Detectivo", "Correctivo", "Gobernanza"]
}

TITLES = {
    "Fuente_Evidencia": "Fuente de evidencia",
    "Subdimension": "Subdimensión",
    "Nivel": "Nivel",
    "Tipo_Funcional": "Tipo funcional"
}


# ------------------------------------------------------------
# PROCESAMIENTO DE DATOS
# ------------------------------------------------------------

def load_data(csv_path):
    df = pd.read_csv(csv_path)
    cols = ["Implementado", "Subdimension", "Nivel", "Fuente_Evidencia", "Tipo_Funcional", "Verificable_Lab"]
    for c in cols:
        if c in df.columns:
            df[c] = df[c].astype(str).str.strip()
    return df


def explode_column(df, column, sep):
    tmp = df.copy()
    tmp[column] = tmp[column].str.replace("/", sep)
    tmp[column] = tmp[column].str.split(sep)
    tmp = tmp.explode(column)
    tmp[column] = tmp[column].str.strip()
    return tmp


def calculate(df, column, sep=None):
    if sep is not None and column in df.columns:
        df = explode_column(df, column, sep)

    metrics = (
        df.groupby(column)
        .agg(
            Implementados=("Implementado", lambda x: (x == "Sí").sum()),
            Total=("Implementado", "count")
        )
        .reset_index()
    )

    metrics["PCC"] = (metrics["Implementados"] / metrics["Total"] * 100).round(2)

    if column in ORDERS and ORDERS[column]:
        metrics[column] = pd.Categorical(metrics[column], categories=ORDERS[column], ordered=True)
        metrics = metrics.sort_values(column)
    return metrics


# ------------------------------------------------------------
# SECCIÓN DE PLOTS (MÓDULOS DE GRAFICACIÓN)
# ------------------------------------------------------------

def plot_barras_global(metrics, column, outfile, title):
    """Genera un gráfico de barras elegante para la totalidad de los controles."""
    plt.figure(figsize=(7, 5))

    ax = sns.barplot(
        data=metrics,
        x=column,
        y="PCC",
        palette=PALETA_COLORES[:len(metrics)]
    )

    ax.set_ylim(0, 110)
    ax.set_ylabel("PCC (%)")
    ax.set_xlabel(TITLES.get(column, column))
    ax.set_title(title)

    for p in ax.patches:
        h = p.get_height()
        if pd.isna(h):
            continue
        ax.annotate(
            f"{h:.2f}".replace(".", ",") + " %",
            (p.get_x() + p.get_width() / 2, h),
            ha="center", va="bottom", fontsize=10, xytext=(0, 3),
            textcoords="offset points", weight="bold"
        )

    plt.tight_layout()
    plt.savefig(outfile, dpi=300)
    plt.close()
    print("Guardado (Barras Global):", outfile)


def plot_torta_verificables(metrics, column, outfile, title):
    """Genera un gráfico de torta limpio con leyendas externas para controles verificables."""
    fig, ax = plt.subplots(figsize=(8, 5))
    active = metrics[metrics["Total"] > 0].copy()
    
    if len(active) == 0:
        ax.pie([1], labels=["Sin datos"], colors=["#CCCCCC"], startangle=90)
    else:
        sizes = active["Total"].tolist()
        labels = active[column].tolist()
        pcc_values = active["PCC"].tolist()
        
        def make_autopct(values):
            def my_autopct(pct):
                total = sum(sizes)
                val = int(round(pct * total / 100.0))
                try:
                    idx = sizes.index(val)
                    return f"{values[idx]:.2f}".replace(".", ",") + " %"
                except ValueError:
                    import numpy as np
                    closest_idx = np.abs(np.array(sizes) - val).argmin()
                    return f"{values[closest_idx]:.2f}".replace(".", ",") + " %"
            return my_autopct

        wedges, texts, autotexts = ax.pie(
            sizes, 
            colors=PALETA_COLORES[:len(labels)], 
            autopct=make_autopct(pcc_values),
            startangle=140, pctdistance=0.75,
            textprops={'fontsize': 10, 'weight': 'bold', 'color': 'black'}
        )
        
        ax.legend(
            wedges, labels, title=TITLES.get(column, column),
            loc="center left", bbox_to_anchor=(1, 0, 0.5, 1)
        )
        
    ax.set_title(title, pad=20, weight="bold")
    plt.tight_layout()
    plt.savefig(outfile, dpi=300)
    plt.close()
    print("Guardado (Torta Verificables):", outfile)


def plot_comparativo_universos(df_all, df_ver, column, outfile, title, sep=None):
    """Genera una barra comparativa lado a lado: Totalidad de Controles vs Solo Verificables."""
    pcc_all = calculate(df_all, column, sep)
    pcc_all["Universo"] = "Totalidad de Controles"
    
    pcc_ver = calculate(df_ver, column, sep)
    pcc_ver["Universo"] = "Solo Verificables"
    
    combined = pd.concat([pcc_all, pcc_ver], ignore_index=True)
    
    plt.figure(figsize=(10, 6))
    ax = sns.barplot(
        data=combined, 
        x=column, 
        y="PCC", 
        hue="Universo", 
        palette=[PALETA_COLORES[0], PALETA_COLORES[3]]
    )
    
    ax.set_title(title, weight="bold", pad=15)
    ax.set_ylabel("PCC (%)")
    ax.set_xlabel(TITLES.get(column, column))
    ax.set_ylim(0, 110)
    
    for p in ax.patches:
        h = p.get_height()
        if h >= 0 and not pd.isna(h):
            ax.annotate(
                f"{h:.2f}".replace(".", ",") + " %",
                (p.get_x() + p.get_width() / 2., h),
                ha='center', va='bottom', xytext=(0, 3),
                textcoords='offset points', fontsize=9, color='black', weight='bold'
            )
            
    plt.tight_layout()
    plt.savefig(outfile, dpi=300)
    plt.close()
    print("Guardado (Comparativo):", outfile)


# ------------------------------------------------------------
# FUNCIÓN PRINCIPAL (PROCESAMIENTO SECUENCIAL EXPLÍCITO)
# ------------------------------------------------------------

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.abspath(os.path.join(script_dir, "..", ".."))
    
    csv_file = os.path.join(repo_root, "controles_llmsec.csv")
    figures = os.path.join(repo_root, "artifacts", "figures")
    os.makedirs(figures, exist_ok=True)

    df = load_data(csv_file)
    df_ver = df[df["Verificable_Lab"] == "Sí"].copy()

    print("=== Iniciando Generación de Reportes Visuales (12 Figuras Completas) ===\n")

    # --- BLOQUE 1: 4 GRÁFICOS DE BARRAS GLOBALES (TODO EL UNIVERSO) ---
    print("[1/3] Generando gráficos globales en barras...")
    plot_barras_global(calculate(df, "Fuente_Evidencia", None), "Fuente_Evidencia", os.path.join(figures, "pcc_fuente_evidencia.png"), "PCC por Fuente de evidencia")
    plot_barras_global(calculate(df, "Subdimension", ","), "Subdimension", os.path.join(figures, "pcc_subdimension.png"), "PCC por Subdimensión")
    plot_barras_global(calculate(df, "Nivel", None), "Nivel", os.path.join(figures, "pcc_nivel.png"), "PCC por Nivel")
    plot_barras_global(calculate(df, "Tipo_Funcional", ","), "Tipo_Funcional", os.path.join(figures, "pcc_funcional.png"), "PCC por Tipo funcional")

    # --- BLOQUE 2: 4 GRÁFICOS DE TORTA (SOLO VERIFICABLES) ---
    print("\n[2/3] Generando gráficos de torta para controles de laboratorio...")
    plot_torta_verificables(calculate(df_ver, "Fuente_Evidencia", None), "Fuente_Evidencia", os.path.join(figures, "pcc_fuente_evidencia_verificables.png"), "PCC por Fuente de evidencia (solo verificables)")
    plot_torta_verificables(calculate(df_ver, "Subdimension", ","), "Subdimension", os.path.join(figures, "pcc_subdimension_verificables.png"), "PCC por Subdimensión (solo verificables)")
    plot_torta_verificables(calculate(df_ver, "Nivel", None), "Nivel", os.path.join(figures, "pcc_nivel_verificables.png"), "PCC por Nivel (solo verificables)")
    plot_torta_verificables(calculate(df_ver, "Tipo_Funcional", ","), "Tipo_Funcional", os.path.join(figures, "pcc_funcional_verificables.png"), "PCC por Tipo funcional (solo verificables)")

    # --- BLOQUE 3: 4 GRÁFICOS COMPARATIVOS DIRECTOS ---
    print("\n[3/3] Generando las 4 figuras comparativas avanzadas (Barras Dobles)...")
    
    # 9. Comparativa Fuente de Evidencia
    plot_comparativo_universos(
        df_all=df, df_ver=df_ver, column="Fuente_Evidencia", sep=None,
        outfile=os.path.join(figures, "pcc_comparativa_evidencia.png"),
        title="Comparativa PCC por Fuente de Evidencia"
    )

    # 10. Comparativa Subdimensiones
    plot_comparativo_universos(
        df_all=df, df_ver=df_ver, column="Subdimension", sep=",",
        outfile=os.path.join(figures, "pcc_comparativa_subdimension.png"),
        title="Comparativa PCC por Subdimensión"
    )

    # 11. Comparativa Niveles
    plot_comparativo_universos(
        df_all=df, df_ver=df_ver, column="Nivel", sep=None,
        outfile=os.path.join(figures, "pcc_comparativa_nivel.png"),
        title="Comparativa PCC por Nivel"
    )

    # 12. Comparativa Tipo Funcional
    plot_comparativo_universos(
        df_all=df, df_ver=df_ver, column="Tipo_Funcional", sep=",",
        outfile=os.path.join(figures, "pcc_comparativa_funcional.png"),
        title="Comparativa PCC por Tipo Funcional"
    )

    print(f"\n[ÉXITO TOTAL] Las 12 figuras se guardaron perfectamente en: {figures}")


# ------------------------------------------------------------

if __name__ == "__main__":
    main()