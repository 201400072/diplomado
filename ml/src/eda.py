"""
Analisis Exploratorio de Datos (EDA) del sample CIC IDS 2017.

Genera reporte con:
  - Distribucion de clases (grafico + tabla)
  - Heatmap de correlacion entre features numericas top-20
  - Distribucion de features clave por clase
  - Valores faltantes y estadisticas basicas
  - Guardar figuras en reports/

Uso:
    python src/eda.py
"""
from __future__ import annotations

import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")  # Sin display
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns


PROCESSED_CSV = Path("data/processed/cic_ids_2017_sample.csv")
REPORTS_DIR = Path("reports")


def load_data() -> pd.DataFrame:
    print(f"[INFO] Cargando {PROCESSED_CSV}")
    df = pd.read_csv(PROCESSED_CSV)
    print(f"  Shape: {df.shape}")
    print(f"  Memoria: {df.memory_usage(deep=True).sum() / 1024 / 1024:.1f} MB")
    return df


def class_distribution(df: pd.DataFrame) -> None:
    """Grafico de distribucion de clases."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    counts = df["Label"].value_counts()
    plt.figure(figsize=(12, 6))
    ax = counts.plot(kind="bar", color="steelblue", edgecolor="black")
    plt.title("Distribucion de clases - CIC IDS 2017 (muestra 500k)", fontsize=14)
    plt.xlabel("Clase")
    plt.ylabel("Numero de muestras")
    plt.xticks(rotation=30, ha="right")

    for p in ax.patches:
        ax.annotate(
            f"{int(p.get_height()):,}",
            (p.get_x() + p.get_width() / 2, p.get_height()),
            ha="center", va="bottom", fontsize=9
        )

    plt.tight_layout()
    plt.savefig(REPORTS_DIR / "01_class_distribution.png", dpi=120)
    plt.close()
    print(f"[OK] {REPORTS_DIR}/01_class_distribution.png")


def basic_stats(df: pd.DataFrame) -> pd.DataFrame:
    """Estadisticas basicas por clase."""
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    # Agrupar por Label, mostrar media de las primeras 10 numericas
    grouped = df.groupby("Label")[numeric_cols[:10]].mean()
    print("\n[INFO] Media de features por clase (top 10 numericas):")
    print(grouped.round(2).to_string())
    grouped.to_csv(REPORTS_DIR / "02_stats_by_class.csv")
    return grouped


def correlation_heatmap(df: pd.DataFrame) -> None:
    """Heatmap de correlacion de las features mas relevantes."""
    numeric = df.select_dtypes(include=[np.number])
    # Varianzas altas primero
    variances = numeric.var().sort_values(ascending=False)
    top_features = variances.head(20).index.tolist()

    corr = numeric[top_features].corr()

    plt.figure(figsize=(14, 12))
    sns.heatmap(
        corr,
        annot=True,
        fmt=".2f",
        cmap="coolwarm",
        center=0,
        square=True,
        linewidths=0.5,
        cbar_kws={"shrink": 0.8},
    )
    plt.title("Matriz de correlacion - Top 20 features (mayor varianza)", fontsize=14)
    plt.xticks(rotation=45, ha="right", fontsize=8)
    plt.yticks(fontsize=8)
    plt.tight_layout()
    plt.savefig(REPORTS_DIR / "03_correlation_heatmap.png", dpi=120)
    plt.close()
    print(f"[OK] {REPORTS_DIR}/03_correlation_heatmap.png")


def missing_values(df: pd.DataFrame) -> None:
    """Reporte de valores faltantes."""
    missing = df.isnull().sum()
    missing = missing[missing > 0].sort_values(ascending=False)
    if len(missing) == 0:
        print("[OK] No hay valores faltantes en el dataset limpio")
    else:
        print("\n[WARN] Valores faltantes detectados:")
        print(missing)


def feature_boxplots(df: pd.DataFrame) -> None:
    """Boxplots de features clave por tipo de trafico."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    # Seleccionar 6 features representativas
    features_to_plot = [
        "Flow Duration",
        "Total Fwd Packets",
        "Total Backward Packets",
        "Flow Bytes/s",
        "Flow Packets/s",
        "Average Packet Size",
    ]
    available = [f for f in features_to_plot if f in df.columns]

    fig, axes = plt.subplots(2, 3, figsize=(16, 10))
    axes = axes.flatten()

    for ax, feat in zip(axes, available):
        # Solo top 6 clases para legibilidad
        top_classes = df["Label"].value_counts().head(6).index.tolist()
        data_to_plot = df[df["Label"].isin(top_classes)]
        sns.boxplot(data=data_to_plot, x="Label", y=feat, ax=ax)
        ax.set_title(feat, fontsize=11)
        ax.tick_params(axis="x", rotation=30)
        for label in ax.get_xticklabels():
            label.set_horizontalalignment("right")

    plt.suptitle("Distribucion de features por top-6 clases", fontsize=14)
    plt.tight_layout()
    plt.savefig(REPORTS_DIR / "04_feature_boxplots.png", dpi=120)
    plt.close()
    print(f"[OK] {REPORTS_DIR}/04_feature_boxplots.png")


def main() -> None:
    if not PROCESSED_CSV.exists():
        sys.exit(f"[ERROR] No se encuentra {PROCESSED_CSV}. Ejecuta primero prepare_dataset.py")

    df = load_data()
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    print("\n" + "=" * 70)
    print(" EDA - CIC IDS 2017 (muestra 500k)")
    print("=" * 70)

    print("\n[1/5] Distribucion de clases...")
    class_distribution(df)

    print("\n[2/5] Estadisticas basicas...")
    basic_stats(df)

    print("\n[3/5] Heatmap de correlacion...")
    correlation_heatmap(df)

    print("\n[4/5] Valores faltantes...")
    missing_values(df)

    print("\n[5/5] Boxplots por clase...")
    feature_boxplots(df)

    print("\n" + "=" * 70)
    print(f" Reportes guardados en: {REPORTS_DIR.resolve()}")
    print("=" * 70)


if __name__ == "__main__":
    main()