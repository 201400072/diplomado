"""
Entrenamiento de modelos ML para deteccion de amenazas.

Modelos:
  1. Random Forest (baseline, rapido)
  2. XGBoost (modelo principal, multiclase con multi:softprob)

Optimizacion:
  - Optuna para busqueda de hiperparametros de XGBoost.
  - Por defecto 30 trials (ajustable con --n-trials).

Metricas evaluadas:
  - Accuracy, Precision, Recall, F1 (macro y weighted)
  - Matriz de confusion
  - ROC AUC por clase (one-vs-rest)
  - Classification report

Salidas:
  - ml/models/model.joblib        (mejor modelo)
  - ml/models/scaler.pkl          (StandardScaler)
  - ml/models/label_classes.json  (mapeo int -> nombre)
  - ml/models/metrics.json        (metricas comparativas)
  - ml/reports/05_confusion_matrix.png
  - ml/reports/06_roc_curves.png
  - ml/reports/07_feature_importance.png

Uso:
    python src/train.py
    python src/train.py --n-trials 50  # Optuna con 50 trials
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import warnings
from datetime import datetime
from pathlib import Path

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import optuna
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.preprocessing import label_binarize
import xgboost as xgb

warnings.filterwarnings("ignore")
optuna.logging.set_verbosity(optuna.logging.WARNING)


DATA_DIR = Path("data/processed")
MODELS_DIR = Path("models")
REPORTS_DIR = Path("reports")
RANDOM_STATE = 42


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n-trials", type=int, default=30,
                        help="Numero de trials de Optuna para XGBoost (default: 30)")
    parser.add_argument("--cv-folds", type=int, default=3,
                        help="Folds para cross-validation durante tuning (default: 3)")
    parser.add_argument("--skip-optuna", action="store_true",
                        help="Saltar Optuna y usar XGBoost con hiperparametros por defecto")
    return parser.parse_args()


def load_data() -> tuple:
    """Carga splits pre-procesados."""
    print(f"[INFO] Cargando splits desde {DATA_DIR}...")
    X_train = pd.read_parquet(DATA_DIR / "X_train.parquet")
    X_test = pd.read_parquet(DATA_DIR / "X_test.parquet")
    y_train = pd.read_parquet(DATA_DIR / "y_train.parquet")["y"].values
    y_test = pd.read_parquet(DATA_DIR / "y_test.parquet")["y"].values
    with open(DATA_DIR / "label_mapping.json") as fh:
        raw = json.load(fh)
        # Aceptar tanto {"Benign": 0} como {"0": "Benign"}
        if all(isinstance(v, int) for v in raw.values()):
            label_map = {v: k for k, v in raw.items()}
        else:
            label_map = {int(k): v for k, v in raw.items()}

    print(f"  X_train: {X_train.shape}  y_train: {y_train.shape}")
    print(f"  X_test:  {X_test.shape}  y_test:  {y_test.shape}")
    print(f"  Clases: {len(label_map)} ({min(label_map)}-{max(label_map)})")
    return X_train, X_test, y_train, y_test, label_map


def objective_xgb(trial, X, y, cv_folds: int) -> float:
    """Funcion objetivo de Optuna para XGBoost multiclase."""
    from sklearn.model_selection import StratifiedKFold

    params = {
        "objective": "multi:softprob",
        "num_class": len(np.unique(y)),
        "n_estimators": trial.suggest_int("n_estimators", 100, 500, step=100),
        "max_depth": trial.suggest_int("max_depth", 4, 12),
        "learning_rate": trial.suggest_float("learning_rate", 0.01, 0.3, log=True),
        "subsample": trial.suggest_float("subsample", 0.6, 1.0),
        "colsample_bytree": trial.suggest_float("colsample_bytree", 0.6, 1.0),
        "min_child_weight": trial.suggest_int("min_child_weight", 1, 10),
        "gamma": trial.suggest_float("gamma", 0.0, 1.0),
        "reg_alpha": trial.suggest_float("reg_alpha", 0.0, 1.0),
        "reg_lambda": trial.suggest_float("reg_lambda", 0.0, 2.0),
        "random_state": RANDOM_STATE,
        "n_jobs": -1,
        "tree_method": "hist",
    }

    skf = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=RANDOM_STATE)
    f1_scores = []

    for fold, (tr_idx, val_idx) in enumerate(skf.split(X, y)):
        X_tr, X_val = X.iloc[tr_idx], X.iloc[val_idx]
        y_tr, y_val = y[tr_idx], y[val_idx]

        model = xgb.XGBClassifier(**params)
        model.fit(X_tr, y_tr, verbose=False)

        y_pred = model.predict(X_val)
        f1 = f1_score(y_val, y_pred, average="macro", zero_division=0)
        f1_scores.append(f1)

    return float(np.mean(f1_scores))


def train_random_forest(X_train, y_train, X_test, y_test) -> tuple:
    """Entrena Random Forest como baseline."""
    print("\n" + "=" * 70)
    print(" BASELINE: Random Forest")
    print("=" * 70)

    rf_params = {
        "n_estimators": 200,
        "max_depth": 20,
        "min_samples_split": 5,
        "min_samples_leaf": 2,
        "n_jobs": -1,
        "random_state": RANDOM_STATE,
        "class_weight": "balanced",
    }
    print(f"[INFO] Hiperparametros: {rf_params}")

    t0 = time.time()
    model = RandomForestClassifier(**rf_params)
    model.fit(X_train, y_train)
    elapsed = time.time() - t0

    print(f"[OK] Entrenamiento completado en {elapsed:.1f}s")
    return model, elapsed


def train_xgboost(X_train, y_train, X_test, y_test, n_trials: int, cv_folds: int, skip_optuna: bool) -> tuple:
    """Entrena XGBoost, opcionalmente con tuning Optuna."""
    print("\n" + "=" * 70)
    print(" MODELO PRINCIPAL: XGBoost")
    print("=" * 70)

    best_params = None
    if not skip_optuna:
        print(f"\n[INFO] Tuning con Optuna ({n_trials} trials, {cv_folds} folds CV)...")
        t0 = time.time()
        study = optuna.create_study(
            direction="maximize",
            sampler=optuna.samplers.TPESampler(seed=RANDOM_STATE),
            study_name="xgboost_intrusion_detection",
        )
        study.optimize(
            lambda trial: objective_xgb(trial, X_train, y_train, cv_folds),
            n_trials=n_trials,
            show_progress_bar=False,
        )
        optuna_time = time.time() - t0

        print(f"\n[OK] Optuna terminado en {optuna_time:.1f}s")
        print(f"  Mejor F1 macro (CV): {study.best_value:.4f}")
        print(f"  Mejores hiperparametros:")
        for k, v in study.best_params.items():
            print(f"    {k}: {v}")
        best_params = study.best_params
    else:
        print("\n[INFO] Saltando Optuna, usando hiperparametros por defecto")
        best_params = {
            "n_estimators": 300,
            "max_depth": 8,
            "learning_rate": 0.1,
            "subsample": 0.8,
            "colsample_bytree": 0.8,
        }

    # Entrenar modelo final con mejores hiperparametros
    print(f"\n[INFO] Entrenando XGBoost final con {len(X_train):,} muestras...")
    final_params = {
        "objective": "multi:softprob",
        "num_class": len(np.unique(y_train)),
        "random_state": RANDOM_STATE,
        "n_jobs": -1,
        "tree_method": "hist",
        **best_params,
    }

    t0 = time.time()
    model = xgb.XGBClassifier(**final_params)
    model.fit(X_train, y_train)
    elapsed = time.time() - t0

    print(f"[OK] Entrenamiento completado en {elapsed:.1f}s")
    return model, elapsed, best_params


def evaluate_model(model, X_test, y_test, label_map, name: str) -> dict:
    """Evalua modelo y retorna metricas + figuras."""
    print(f"\n[INFO] Evaluando {name}...")

    y_pred = model.predict(X_test)
    if hasattr(model, "predict_proba"):
        y_proba = model.predict_proba(X_test)
    else:
        y_proba = None

    # Metricas
    accuracy = accuracy_score(y_test, y_pred)
    precision_macro = precision_score(y_test, y_pred, average="macro", zero_division=0)
    recall_macro = recall_score(y_test, y_pred, average="macro", zero_division=0)
    f1_macro = f1_score(y_test, y_pred, average="macro", zero_division=0)
    f1_weighted = f1_score(y_test, y_pred, average="weighted", zero_division=0)

    print(f"  Accuracy:  {accuracy:.4f}")
    print(f"  Precision: {precision_macro:.4f} (macro)")
    print(f"  Recall:    {recall_macro:.4f} (macro)")
    print(f"  F1:        {f1_macro:.4f} (macro) / {f1_weighted:.4f} (weighted)")

    # ROC AUC por clase (one-vs-rest)
    roc_auc = None
    if y_proba is not None:
        try:
            # Limitar a clases presentes en y_test (algunas clases pueden tener 0 muestras)
            classes_present = sorted(set(y_test))
            # Asegurar que y_proba tenga el mismo numero de columnas que clases presentes
            if y_proba.shape[1] == len(classes_present):
                y_test_bin = label_binarize(y_test, classes=classes_present)
                roc_auc = roc_auc_score(y_test_bin, y_proba, average="macro", multi_class="ovr")
                print(f"  ROC AUC:   {roc_auc:.4f} (macro OvR, {len(classes_present)} clases)")
            else:
                # Fallback: usar todas las clases del modelo
                all_classes = list(range(y_proba.shape[1]))
                y_test_bin = label_binarize(y_test, classes=all_classes)
                roc_auc = roc_auc_score(y_test_bin, y_proba, average="macro", multi_class="ovr")
                print(f"  ROC AUC:   {roc_auc:.4f} (macro OvR, {y_proba.shape[1]} clases)")
        except Exception as e:
            print(f"  ROC AUC:   no se pudo calcular ({e})")

    # Matriz de confusion
    cm = confusion_matrix(y_test, y_pred)
    return {
        "name": name,
        "accuracy": float(accuracy),
        "precision_macro": float(precision_macro),
        "recall_macro": float(recall_macro),
        "f1_macro": float(f1_macro),
        "f1_weighted": float(f1_weighted),
        "roc_auc_macro": float(roc_auc) if roc_auc else None,
        "confusion_matrix": cm.tolist(),
        "y_pred": y_pred.tolist(),
        "y_proba": y_proba.tolist() if y_proba is not None else None,
    }


def plot_confusion_matrix(cm, label_map, name: str) -> None:
    """Genera heatmap de matriz de confusion normalizada."""
    import seaborn as sns

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    classes = [label_map[i] for i in sorted(label_map.keys())]
    cm_norm = cm.astype("float") / cm.sum(axis=1)[:, np.newaxis]

    plt.figure(figsize=(10, 8))
    sns.heatmap(
        cm_norm,
        annot=True,
        fmt=".2f",
        cmap="Blues",
        xticklabels=classes,
        yticklabels=classes,
        cbar_kws={"label": "Proporcion"},
        vmin=0, vmax=1,
    )
    plt.title(f"Matriz de Confusion Normalizada - {name}", fontsize=14)
    plt.xlabel("Predicho")
    plt.ylabel("Real")
    plt.xticks(rotation=30, ha="right")
    plt.yticks(rotation=0)
    plt.tight_layout()

    fname = REPORTS_DIR / f"05_confusion_matrix_{name.lower().replace(' ', '_')}.png"
    plt.savefig(fname, dpi=120)
    plt.close()
    print(f"  [OK] {fname}")


def plot_roc_curves(y_test, y_proba, label_map, name: str) -> None:
    """ROC curves one-vs-rest por clase."""
    if y_proba is None:
        return

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    classes_present = sorted(set(y_test))
    y_test_bin = label_binarize(y_test, classes=classes_present)

    plt.figure(figsize=(10, 8))
    for i, cls in enumerate(classes_present):
        if cls not in label_map:
            continue
        fpr, tpr, _ = roc_curve(y_test_bin[:, i], y_proba[:, i])
        roc_auc = roc_auc_score(y_test_bin[:, i], y_proba[:, i])
        plt.plot(fpr, tpr, lw=2, label=f"{label_map[cls]} (AUC={roc_auc:.3f})")

    plt.plot([0, 1], [0, 1], "k--", lw=1)
    plt.xlim([0, 1])
    plt.ylim([0, 1.05])
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title(f"Curvas ROC (One-vs-Rest) - {name}", fontsize=14)
    plt.legend(loc="lower right", fontsize=9)
    plt.grid(alpha=0.3)
    plt.tight_layout()

    fname = REPORTS_DIR / f"06_roc_curves_{name.lower().replace(' ', '_')}.png"
    plt.savefig(fname, dpi=120)
    plt.close()
    print(f"  [OK] {fname}")


def plot_feature_importance(model, feature_names, name: str, top_n: int = 20) -> None:
    """Top-N features mas importantes del modelo."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    if hasattr(model, "feature_importances_"):
        importances = model.feature_importances_
        idx = np.argsort(importances)[-top_n:]
        top_features = [feature_names[i] for i in idx]
        top_values = importances[idx]

        plt.figure(figsize=(10, 8))
        y_pos = np.arange(len(top_features))
        plt.barh(y_pos, top_values, color="steelblue")
        plt.yticks(y_pos, top_features)
        plt.xlabel("Importancia")
        plt.title(f"Top {top_n} Features - {name}", fontsize=14)
        plt.tight_layout()

        fname = REPORTS_DIR / f"07_feature_importance_{name.lower().replace(' ', '_')}.png"
        plt.savefig(fname, dpi=120)
        plt.close()
        print(f"  [OK] {fname}")


def main() -> None:
    args = parse_args()
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    X_train, X_test, y_train, y_test, label_map = load_data()
    feature_names = X_train.columns.tolist()
    n_classes = len(np.unique(y_train))

    # 1. Random Forest baseline
    rf_model, rf_time = train_random_forest(X_train, y_train, X_test, y_test)
    rf_metrics = evaluate_model(rf_model, X_test, y_test, label_map, "Random Forest")
    rf_metrics["train_time_s"] = rf_time

    plot_confusion_matrix(np.array(rf_metrics["confusion_matrix"]), label_map, "Random Forest")
    plot_roc_curves(y_test, np.array(rf_metrics["y_proba"]) if rf_metrics["y_proba"] else None,
                    label_map, "Random Forest")
    plot_feature_importance(rf_model, feature_names, "Random Forest")

    # 2. XGBoost
    xgb_model, xgb_time, best_params = train_xgboost(
        X_train, y_train, X_test, y_test,
        n_trials=args.n_trials,
        cv_folds=args.cv_folds,
        skip_optuna=args.skip_optuna,
    )
    xgb_metrics = evaluate_model(xgb_model, X_test, y_test, label_map, "XGBoost")
    xgb_metrics["train_time_s"] = xgb_time
    xgb_metrics["best_params"] = best_params

    plot_confusion_matrix(np.array(xgb_metrics["confusion_matrix"]), label_map, "XGBoost")
    plot_roc_curves(y_test, np.array(xgb_metrics["y_proba"]) if xgb_metrics["y_proba"] else None,
                    label_map, "XGBoost")
    plot_feature_importance(xgb_model, feature_names, "XGBoost")

    # 3. Seleccionar mejor modelo (por F1 macro)
    if xgb_metrics["f1_macro"] >= rf_metrics["f1_macro"]:
        best_name = "XGBoost"
        best_model = xgb_model
        best_metrics = xgb_metrics
    else:
        best_name = "Random Forest"
        best_model = rf_model
        best_metrics = rf_metrics

    print(f"\n[OK] Mejor modelo: {best_name} (F1 macro={best_metrics['f1_macro']:.4f})")

    # 4. Guardar mejor modelo con Joblib
    print(f"\n[INFO] Guardando modelo en {MODELS_DIR}...")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Modelo en formato Joblib
    joblib.dump(best_model, MODELS_DIR / "model.joblib")
    print(f"  [OK] model.joblib ({best_name})")

    # Scaler (copia del usado en split.py)
    if (DATA_DIR / "scaler.pkl").exists():
        import shutil
        shutil.copy(DATA_DIR / "scaler.pkl", MODELS_DIR / "scaler.pkl")
        print(f"  [OK] scaler.pkl")

    # Mapeo de clases
    with open(MODELS_DIR / "label_classes.json", "w") as fh:
        json.dump({str(k): v for k, v in label_map.items()}, fh, indent=2)
    print(f"  [OK] label_classes.json")

    # Metricas comparativas
    comparison = {
        "timestamp": timestamp,
        "n_classes": n_classes,
        "n_features": len(feature_names),
        "n_train": int(len(y_train)),
        "n_test": int(len(y_test)),
        "label_mapping": label_map,
        "models": {
            "random_forest": {
                k: v for k, v in rf_metrics.items()
                if k not in ("y_pred", "y_proba", "confusion_matrix")
            },
            "xgboost": {
                k: v for k, v in xgb_metrics.items()
                if k not in ("y_pred", "y_proba", "confusion_matrix")
            },
        },
        "best_model": best_name,
    }
    with open(MODELS_DIR / "metrics.json", "w") as fh:
        json.dump(comparison, fh, indent=2, default=str)
    print(f"  [OK] metrics.json")

    print("\n" + "=" * 70)
    print(" RESUMEN COMPARATIVO")
    print("=" * 70)
    print(f"  {'Metrica':<20} {'Random Forest':>15} {'XGBoost':>15}")
    print(f"  {'-'*20} {'-'*15} {'-'*15}")
    for metric in ["accuracy", "precision_macro", "recall_macro", "f1_macro", "f1_weighted", "roc_auc_macro"]:
        rf_v = rf_metrics.get(metric)
        xg_v = xgb_metrics.get(metric)
        rf_s = f"{rf_v:.4f}" if rf_v is not None else "N/A"
        xg_s = f"{xg_v:.4f}" if xg_v is not None else "N/A"
        print(f"  {metric:<20} {rf_s:>15} {xg_s:>15}")
    print(f"  {'train_time_s':<20} {rf_metrics['train_time_s']:>15.1f} {xgb_metrics['train_time_s']:>15.1f}")

    print(f"\n[OK] Mejor modelo: {best_name}")
    print(f"[OK] Artefactos guardados en: {MODELS_DIR.resolve()}")


if __name__ == "__main__":
    main()