"""
Tests unitarios del predictor ML.

Uso:
    cd api && source ../api/.venv-api/bin/activate && pytest tests/unit -v
"""
from __future__ import annotations

import numpy as np
import pytest

from app.infrastructure.ml.loader import ModelLoader
from app.services.predictor import PredictorService


@pytest.fixture(scope="module")
def model_loader() -> ModelLoader:
    """Carga el modelo una vez por modulo."""
    from pathlib import Path
    project_root = Path(__file__).resolve().parent.parent.parent.parent
    ml_models = project_root / "ml" / "models"
    loader = ModelLoader(
        model_path=ml_models / "model.joblib",
        scaler_path=ml_models / "scaler.pkl",
        label_classes_path=ml_models / "label_classes.json",
    )
    loader.load()
    return loader


@pytest.fixture(scope="module")
def predictor(model_loader) -> PredictorService:
    return PredictorService(model_loader)


def test_model_loader_has_features(model_loader: ModelLoader) -> None:
    """El loader debe tener nombres de features."""
    assert len(model_loader.feature_names) > 0
    assert len(model_loader.feature_names) == 69


def test_model_loader_has_classes(model_loader: ModelLoader) -> None:
    """El loader debe tener 9 clases."""
    assert model_loader.n_classes == 9


def test_label_classes(model_loader: ModelLoader) -> None:
    """Verifica que las clases esperadas estan presentes."""
    expected = {"Benign", "DoS", "DDoS", "BruteForce", "WebAttack", "PortScan", "Bot", "Infiltration", "Other"}
    actual = set(model_loader.label_classes.values())
    assert expected == actual


def test_predictor_handles_empty(predictor: PredictorService) -> None:
    """Prediccion con lista vacia retorna lista vacia."""
    assert predictor.predict([]) == []


def test_predictor_single_event(predictor: PredictorService) -> None:
    """Prediccion de un solo evento retorna una prediccion."""
    event = {
        "Flow Duration": 117189197,
        "Total Fwd Packets": 4,
        "Total Backward Packets": 2,
        "Fwd Packets Length Total": 334,
        "Bwd Packets Length Total": 1250,
        "Protocol": 6,
    }
    # Completar con ceros para las features faltantes
    result = predictor.predict([event])
    assert len(result) == 1
    pred = result[0]
    assert "prediction" in pred
    assert "prediction_id" in pred
    assert "confidence" in pred
    assert 0.0 <= pred["confidence"] <= 1.0
    assert pred["prediction"] in {
        "Benign", "DoS", "DDoS", "BruteForce", "WebAttack",
        "PortScan", "Bot", "Infiltration", "Other"
    }


def test_predictor_batch(predictor: PredictorService) -> None:
    """Prediccion de un batch de 10 eventos retorna 10 predicciones."""
    events = [
        {"Flow Duration": 100 + i * 1000, "Protocol": 6}
        for i in range(10)
    ]
    results = predictor.predict(events)
    assert len(results) == 10
    for r in results:
        assert 0.0 <= r["confidence"] <= 1.0


def test_predictor_probabilities_sum_one(predictor: PredictorService) -> None:
    """Las probabilidades deben sumar 1.0."""
    event = {"Flow Duration": 100000, "Protocol": 6}
    result = predictor.predict([event])[0]
    total = sum(result["probabilities"].values())
    assert abs(total - 1.0) < 0.001


def test_vectorize_handles_missing_features(model_loader: ModelLoader) -> None:
    """vectorize completa features faltantes con 0."""
    event = {"Flow Duration": 100}
    X = model_loader.vectorize([event])
    assert X.shape == (1, 69)
    assert not np.any(np.isnan(X))


def test_vectorize_handles_invalid_values(model_loader: ModelLoader) -> None:
    """vectorize maneja valores invalidos."""
    event = {"Flow Duration": "invalid", "Protocol": 6}
    X = model_loader.vectorize([event])
    assert X.shape == (1, 69)
    assert not np.any(np.isnan(X))