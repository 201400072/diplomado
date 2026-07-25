"""
Validacion de compatibilidad de algoritmos ML en el entorno actual.

Este script valida que todos los algoritmos candidatos al proyecto
funcionan correctamente en la maquina antes de invertir tiempo en
entrenamiento con datos reales.

Uso:
    python src/compatibility_check.py
    python src/compatibility_check.py --verbose
"""
from __future__ import annotations

import argparse
import platform
import sys
import time
from dataclasses import dataclass
from typing import Callable

import numpy as np
from sklearn.datasets import make_classification
from sklearn.ensemble import (
    ExtraTreesClassifier,
    HistGradientBoostingClassifier,
    RandomForestClassifier,
)
from sklearn.metrics import f1_score
from sklearn.model_selection import train_test_split


@dataclass(frozen=True)
class AlgorithmResult:
    """Resultado de validar un algoritmo en el entorno actual."""

    name: str
    available: bool
    f1_macro: float | None
    train_time_s: float | None
    error: str | None


def _build_dataset(n_samples: int = 2000, n_features: int = 20, n_classes: int = 4) -> tuple:
    """Genera dataset sintetico multiclase para la validacion."""
    X, y = make_classification(
        n_samples=n_samples,
        n_features=n_features,
        n_classes=n_classes,
        n_informative=10,
        random_state=42,
    )
    return train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)


def _try_algorithm(
    name: str,
    factory: Callable,
    X_train: np.ndarray,
    X_test: np.ndarray,
    y_train: np.ndarray,
    y_test: np.ndarray,
) -> AlgorithmResult:
    """Entrena un algoritmo y mide F1 macro y tiempo de entrenamiento."""
    try:
        t0 = time.perf_counter()
        model = factory()
        model.fit(X_train, y_train)
        elapsed = time.perf_counter() - t0

        predictions = model.predict(X_test)
        f1 = f1_score(y_test, predictions, average="macro")
        return AlgorithmResult(
            name=name, available=True, f1_macro=f1, train_time_s=elapsed, error=None
        )
    except Exception as exc:
        return AlgorithmResult(
            name=name, available=False, f1_macro=None, train_time_s=None, error=str(exc)[:120]
        )


def run_all_checks(verbose: bool = False) -> list[AlgorithmResult]:
    """Ejecuta la bateria completa de pruebas de compatibilidad."""
    X_train, X_test, y_train, y_test = _build_dataset()
    results: list[AlgorithmResult] = []

    # Algoritmo primario del proyecto
    import xgboost

    results.append(
        _try_algorithm(
            "1. XGBoost (primario)",
            lambda: xgboost.XGBClassifier(
                n_estimators=50, max_depth=4, verbosity=0, random_state=42
            ),
            X_train, X_test, y_train, y_test,
        )
    )

    # Baseline del proyecto
    results.append(
        _try_algorithm(
            "2. RandomForest (baseline)",
            lambda: RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1),
            X_train, X_test, y_train, y_test,
        )
    )

    # Alternativas scikit-learn puras (Plan B sin dependencias externas)
    results.append(
        _try_algorithm(
            "3. HistGradientBoosting (sklearn)",
            lambda: HistGradientBoostingClassifier(max_iter=50, random_state=42),
            X_train, X_test, y_train, y_test,
        )
    )

    results.append(
        _try_algorithm(
            "4. ExtraTrees (sklearn)",
            lambda: ExtraTreesClassifier(n_estimators=100, random_state=42, n_jobs=-1),
            X_train, X_test, y_train, y_test,
        )
    )

    # Alternativas externas opcionales
    try:
        import lightgbm as lgb

        results.append(
            _try_algorithm(
                "5. LightGBM",
                lambda: lgb.LGBMClassifier(
                    n_estimators=50, verbose=-1, random_state=42
                ),
                X_train, X_test, y_train, y_test,
            )
        )
    except ImportError:
        results.append(AlgorithmResult("5. LightGBM", False, None, None, "no instalado"))

    try:
        import catboost as cb

        results.append(
            _try_algorithm(
                "6. CatBoost",
                lambda: cb.CatBoostClassifier(iterations=50, verbose=0, random_state=42),
                X_train, X_test, y_train, y_test,
            )
        )
    except ImportError:
        results.append(AlgorithmResult("6. CatBoost", False, None, None, "no instalado"))

    return results


def print_report(results: list[AlgorithmResult]) -> None:
    """Imprime el reporte en formato tabla."""
    print("=" * 78)
    print(f" ENTORNO: {platform.system()} {platform.machine()} - Python {platform.python_version()}")
    print("=" * 78)
    print(f"{'Algoritmo':<40} {'Estado':<10} {'F1 macro':<12} {'Train (s)':<12}")
    print("-" * 78)

    for r in results:
        if r.available:
            f1_str = f"{r.f1_macro:.4f}"
            t_str = f"{r.train_time_s:.2f}"
            print(f"{r.name:<40} {'OK':<10} {f1_str:<12} {t_str:<12}")
        else:
            print(f"{r.name:<40} {'NO':<10} {'-':<12} {'-':<12}")
            if r.error:
                print(f"  └─ error: {r.error}")

    print("-" * 78)
    disponibles = sum(1 for r in results if r.available)
    print(f" {disponibles}/{len(results)} algoritmos disponibles")


def main() -> int:
    """Punto de entrada CLI."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Muestra informacion detallada del sistema",
    )
    args = parser.parse_args()

    if args.verbose:
        print("Informacion del entorno:")
        print(f"  Sistema:      {platform.system()} {platform.release()}")
        print(f"  Arquitectura: {platform.machine()}")
        print(f"  Python:       {platform.python_version()}")
        print(f"  NumPy:        {np.__version__}")
        print()

    results = run_all_checks(verbose=args.verbose)
    print_report(results)

    # Codigo de salida: 0 si XGBoost funciona, 1 en caso contrario
    xgb_result = results[0]
    if not xgb_result.available:
        print("\n[ALERTA] XGBoost no funciona. Revisar dependencias.")
        print("  En macOS: brew install libomp")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())