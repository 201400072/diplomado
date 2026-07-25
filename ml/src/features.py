"""
Feature engineering para el sample CIC IDS 2017.

Pasos:
  1. Carga la muestra procesada en data/processed/cic_ids_2017_sample.csv.
  2. Reduce las 15 clases originales a 7 clases manejables:
        Benign, DoS, DDoS, PortScan, BruteForce, WebAttack, Bot, Infiltration, Other.
  3. Codifica la variable objetivo Label como entero (Label_encoded).
  4. Persiste data/processed/cic_ids_2017_encoded.csv.

Uso:
    python src/features.py
"""
from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd


PROCESSED_CSV = Path("data/processed/cic_ids_2017_sample.csv")
OUTPUT_CSV = Path("data/processed/cic_ids_2017_encoded.csv")


# Mapeo de clase original -> clase agrupada (multiclase academico)
# Los "Web Attack" tienen encoding raro (–) que se reemplaza por " - "
LABEL_MAP = {
    "Benign": "Benign",
    "DoS Hulk": "DoS",
    "DoS GoldenEye": "DoS",
    "DoS slowloris": "DoS",
    "DoS Slowhttptest": "DoS",
    "DDoS": "DDoS",
    "PortScan": "PortScan",
    "FTP-Patator": "BruteForce",
    "SSH-Patator": "BruteForce",
    "Web Attack - Brute Force": "WebAttack",
    "Web Attack - XSS": "WebAttack",
    "Web Attack - Sql Injection": "WebAttack",
    "Bot": "Bot",
    "Infiltration": "Infiltration",
    "Heartbleed": "Other",
}


def main() -> None:
    if not PROCESSED_CSV.exists():
        sys.exit(f"[ERROR] No existe {PROCESSED_CSV}. Ejecuta prepare_dataset.py primero.")

    print(f"[INFO] Cargando {PROCESSED_CSV}...")
    df = pd.read_csv(PROCESSED_CSV)
    print(f"  Filas: {len(df):,}  Columnas: {len(df.columns)}")

    # 1. Normalizar nombres de clase (quitar caracteres raros y em dash)
    df["Label"] = df["Label"].str.strip()
    # Reemplazar cualquier caracter no-ASCII por " - " usando apply
    df["Label"] = df["Label"].apply(lambda x: " - ".join(x.split(" - ")) if " - " in x else x)
    df["Label"] = df["Label"].str.encode("ascii", "replace").str.decode("ascii")
    df["Label"] = df["Label"].str.replace(r"\?\?\?", "-", regex=True)
    df["Label"] = df["Label"].str.replace(r"\?+", "-", regex=True)
    df["Label"] = df["Label"].str.replace(r"\s+", " ", regex=True).str.strip()

    # 2. Mapear a clase agrupada
    print("\n[INFO] Mapeando a clases agrupadas...")
    df["Label_grouped"] = df["Label"].map(LABEL_MAP)
    unmapped = df[df["Label_grouped"].isna()]["Label"].unique()
    if len(unmapped) > 0:
        print(f"  [WARN] Clases sin mapear: {unmapped}")
        df["Label_grouped"] = df["Label_grouped"].fillna("Other")
    df = df.drop(columns=["Label"]).rename(columns={"Label_grouped": "Label"})

    print("\n[INFO] Distribucion de clases (post-agrupacion):")
    counts = df["Label"].value_counts()
    for label, count in counts.items():
        pct = count / len(df) * 100
        print(f"  {label:20s} {count:>10,}  ({pct:.2f}%)")

    # 3. Encoding: Label -> entero
    print("\n[INFO] Codificando Label como entero...")
    classes_sorted = sorted(df["Label"].unique())
    label_to_int = {label: idx for idx, label in enumerate(classes_sorted)}
    df["Label_encoded"] = df["Label"].map(label_to_int)

    print("  Mapeo Label -> entero:")
    for label, idx in label_to_int.items():
        print(f"    {idx}: {label}")

    # 4. Persistir
    OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUTPUT_CSV, index=False)
    print(f"\n[OK] Dataset encoded guardado en: {OUTPUT_CSV}")
    print(f"[OK] Filas: {len(df):,}  Columnas: {len(df.columns)}")
    print(f"[OK] Tamano: {OUTPUT_CSV.stat().st_size / 1024 / 1024:.1f} MB")


if __name__ == "__main__":
    main()