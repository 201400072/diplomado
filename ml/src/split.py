"""
Normalizacion, balanceo y split train/test del dataset CIC IDS 2017.

Pasos:
  1. Carga data/processed/cic_ids_2017_encoded.csv.
  2. Separa features (X) y target (y).
  3. Split train/test estratificado (80/20).
  4. Normaliza features con StandardScaler (solo en train).
  5. Persiste splits escalados y scaler.pkl.

Uso:
    python src/split.py
"""
from __future__ import annotations

import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler


PROCESSED_CSV = Path("data/processed/cic_ids_2017_encoded.csv")
OUTPUT_DIR = Path("data/processed")
TEST_SIZE = 0.2
RANDOM_STATE = 42


def main() -> None:
    if not PROCESSED_CSV.exists():
        sys.exit(f"[ERROR] No existe {PROCESSED_CSV}. Ejecuta features.py primero.")

    print(f"[INFO] Cargando {PROCESSED_CSV}...")
    df = pd.read_csv(PROCESSED_CSV)
    print(f"  Filas: {len(df):,}  Columnas: {len(df.columns)}")

    # 1. Separar features y target
    print("\n[INFO] Separando features (X) y target (y)...")
    # Quitar columnas no feature: Label (texto), Label_encoded (int = target), category (metadata)
    feature_cols = [c for c in df.columns if c not in ("Label", "Label_encoded", "category")]
    X = df[feature_cols].astype(np.float32)
    y = df["Label_encoded"].astype(int)

    print(f"  Features: {X.shape[1]}")
    print(f"  Target classes: {y.nunique()}")
    print(f"  Distribucion y:")
    label_map = {v: k for k, v in zip(df["Label"], df["Label_encoded"])}
    for idx in sorted(y.unique()):
        n = (y == idx).sum()
        pct = n / len(y) * 100
        print(f"    {idx} ({label_map[idx]:20s}): {n:>10,}  ({pct:.2f}%)")

    # 2. Split train/test estratificado
    print(f"\n[INFO] Split train/test ({1-TEST_SIZE:.0%}/{TEST_SIZE:.0%}) estratificado...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=TEST_SIZE,
        stratify=y,
        random_state=RANDOM_STATE,
    )
    print(f"  X_train: {X_train.shape}")
    print(f"  X_test:  {X_test.shape}")

    # 3. Normalizacion con StandardScaler (fit en train)
    print("\n[INFO] Normalizando features con StandardScaler (fit en train)...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    # Convertir de vuelta a DataFrame con nombres de columnas
    X_train_scaled = pd.DataFrame(X_train_scaled, columns=feature_cols)
    X_test_scaled = pd.DataFrame(X_test_scaled, columns=feature_cols)
    print(f"  Media ~0, Std ~1 en train")

    # 4. Persistir
    print("\n[INFO] Guardando splits...")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    X_train_scaled.to_parquet(OUTPUT_DIR / "X_train.parquet")
    X_test_scaled.to_parquet(OUTPUT_DIR / "X_test.parquet")
    pd.Series(y_train).to_frame("y").to_parquet(OUTPUT_DIR / "y_train.parquet")
    pd.Series(y_test).to_frame("y").to_parquet(OUTPUT_DIR / "y_test.parquet")

    joblib.dump(scaler, OUTPUT_DIR / "scaler.pkl")

    print(f"\n[OK] Splits guardados:")
    for f in ["X_train.parquet", "X_test.parquet", "y_train.parquet", "y_test.parquet", "scaler.pkl"]:
        path = OUTPUT_DIR / f
        size_mb = path.stat().st_size / 1024 / 1024
        print(f"  - {f}: {size_mb:.1f} MB")

    # Mapeo Label -> int (para uso posterior)
    label_mapping = {idx: name for name, idx in label_map.items()}
    import json
    with open(OUTPUT_DIR / "label_mapping.json", "w") as fh:
        json.dump({str(k): v for k, v in label_mapping.items()}, fh, indent=2)
    print(f"\n[OK] label_mapping.json:")
    for k, v in label_mapping.items():
        print(f"  {k}: {v}")


if __name__ == "__main__":
    main()