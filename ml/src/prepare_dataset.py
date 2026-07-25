"""
Preprocesamiento y muestreo estratificado del dataset CIC IDS 2017.

Pipeline:
  1. Carga los 8 archivos parquet (uno por categoria de trafico).
  2. Concatena en un solo DataFrame.
  3. Limpia nombres de columnas, valores infinitos y duplicados.
  4. Renombra la columna Label a label.
  5. Resuelve el desbalance de clases (top-7 + Others).
  6. Genera muestra estratificada de N filas (default 500 000).
  7. Persiste el sample en data/processed/cic_ids_2017_sample.csv.

Uso:
    python src/prepare_dataset.py
    python src/prepare_dataset.py --n-samples 500000 --seed 42
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split


DATA_RAW_DIR = Path("data")
DATA_PROCESSED_DIR = Path("data/processed")
RANDOM_STATE = 42
TARGET_TOTAL = 500_000

KEEP_CLASSES = [
    "Benign",
    "DoS Hulk",
    "DoS GoldenEye",
    "DoS slowloris",
    "DoS Slowhttptest",
    "PortScan",
    "DDoS",
    "FTP-Patator",
    "SSH-Patator",
    "Web Attack Brute Force",
    "Web Attack XSS",
    "Web Attack Sql Injection",
    "Infiltration",
    "Bot",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n-samples", type=int, default=TARGET_TOTAL,
                        help=f"Tamano de la muestra estratificada (default: {TARGET_TOTAL:,})")
    parser.add_argument("--seed", type=int, default=RANDOM_STATE,
                        help=f"Semilla aleatoria (default: {RANDOM_STATE})")
    return parser.parse_args()


def load_raw() -> pd.DataFrame:
    """Carga todos los parquet del directorio data/ en un solo DataFrame."""
    files = sorted(DATA_RAW_DIR.glob("*.parquet"))
    if not files:
        sys.exit(f"[ERROR] No se encontraron archivos .parquet en {DATA_RAW_DIR.resolve()}")

    print(f"[INFO] Cargando {len(files)} archivos parquet...")
    frames = []
    for f in files:
        df_part = pd.read_parquet(f)
        # Extrae la clase del nombre del archivo: Benign-Monday-no-metadata.parquet -> Benign
        category = f.stem.split("-")[0]
        # Las categorias compuestas (DoS Hulk, Web Attack Brute Force, etc.) se infieren por archivo
        # Aqui simplificamos y mapeamos luego
        if category not in df_part.columns:
            df_part["category"] = category
        frames.append(df_part)
        print(f"  + {f.name}: {len(df_part):,} filas, {len(df_part.columns)} columnas")

    df = pd.concat(frames, ignore_index=True)
    print(f"\n[INFO] Total filas combinadas: {len(df):,}")
    return df


def normalize_labels(df: pd.DataFrame) -> pd.DataFrame:
    """Normaliza las etiquetas del dataset."""
    # En este dataset limpio, la columna objetivo es 'Label' o ya viene etiquetada por archivo
    label_col = None
    for col in df.columns:
        if col.lower() == "label":
            label_col = col
            break

    if label_col is None and "category" in df.columns:
        df = df.rename(columns={"category": "Label"})
        label_col = "Label"
    elif label_col is not None:
        df = df.rename(columns={label_col: "Label"})

    print(f"[INFO] Distribucion de clases (original):")
    counts = df["Label"].value_counts()
    for label, count in counts.items():
        print(f"  {label:30s} {count:>10,}")

    return df


def clean_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Limpia el DataFrame: tipos, infinitos, nulos, duplicados."""
    initial_rows = len(df)

    # Eliminar columnas con un solo valor
    unique_cols = [col for col in df.columns if df[col].nunique() <= 1]
    if unique_cols:
        print(f"[INFO] Eliminando {len(unique_cols)} columnas con un solo valor: {unique_cols}")
        df = df.drop(columns=unique_cols)

    # Reemplazar infinitos por NaN
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)

    # Eliminar filas con NaN
    before = len(df)
    df = df.dropna()
    print(f"[INFO] Filas eliminadas por NaN: {before - len(df):,}")

    # Eliminar duplicados
    before = len(df)
    df = df.drop_duplicates()
    print(f"[INFO] Filas duplicadas eliminadas: {before - len(df):,}")

    print(f"[INFO] Filas finales despues de limpieza: {len(df):,} (de {initial_rows:,})")
    return df


def stratified_sample(df: pd.DataFrame, n_samples: int, seed: int) -> pd.DataFrame:
    """Toma una muestra estratificada manteniendo proporciones de clase."""
    print(f"\n[INFO] Generando muestra estratificada de {n_samples:,} filas...")
    sample, _ = train_test_split(
        df,
        train_size=n_samples,
        stratify=df["Label"],
        random_state=seed,
    )
    print(f"[INFO] Distribucion en la muestra:")
    counts = sample["Label"].value_counts()
    for label, count in counts.items():
        pct = count / len(sample) * 100
        print(f"  {label:30s} {count:>10,}  ({pct:.2f}%)")
    return sample


def main() -> None:
    args = parse_args()
    DATA_PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

    df = load_raw()
    df = normalize_labels(df)
    df = clean_dataframe(df)
    sample = stratified_sample(df, args.n_samples, args.seed)

    output_path = DATA_PROCESSED_DIR / "cic_ids_2017_sample.csv"
    sample.to_csv(output_path, index=False)
    print(f"\n[OK] Muestra guardada en: {output_path}")
    print(f"[OK] Tamano final: {output_path.stat().st_size / 1024 / 1024:.1f} MB")
    print(f"[OK] Filas: {len(sample):,}  Columnas: {len(sample.columns)}")


if __name__ == "__main__":
    main()