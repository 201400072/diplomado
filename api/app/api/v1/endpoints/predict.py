"""
Endpoint: POST /predict

Recibe un batch de eventos (features), los clasifica con el
modelo XGBoost, y opcionalmente indexa el resultado en OpenSearch.
"""
from __future__ import annotations

import logging
import time
from typing import Annotated

from fastapi import APIRouter, Depends, status

from app.api.deps import require_api_key
from app.config.settings import get_settings
from app.infrastructure.ml.loader import get_model_loader
from app.infrastructure.opensearch.client import get_opensearch_client
from app.schemas.predict import (
    PredictionItem,
    PredictionRequest,
    PredictionResponse,
)
from app.services.predictor import PredictorService

logger = logging.getLogger(__name__)
router = APIRouter()


def get_predictor_service() -> PredictorService:
    """Dependencia: retorna instancia del predictor."""
    return PredictorService(get_model_loader())


@router.post(
    "/predict",
    response_model=PredictionResponse,
    status_code=status.HTTP_200_OK,
    summary="Predecir amenazas en batch",
    description=(
        "Recibe una lista de eventos (features como dict) y devuelve "
        "la clase predicha, confianza y probabilidades por clase. "
        "Requiere API Key en header X-API-Key."
    ),
    tags=["predict"],
    dependencies=[Depends(require_api_key)],
)
def predict(
    request: PredictionRequest,
    predictor: Annotated[PredictorService, Depends(get_predictor_service)],
) -> PredictionResponse:
    """Endpoint principal de prediccion."""
    settings = get_settings()
    t0 = time.perf_counter()

    predictions = predictor.predict(request.events)

    inference_time_ms = (time.perf_counter() - t0) * 1000.0

    # Indexar cada prediccion en OpenSearch (best-effort)
    os_client = get_opensearch_client()
    for i, pred in enumerate(predictions):
        document = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "prediction": pred["prediction"],
            "prediction_id": pred["prediction_id"],
            "confidence": pred["confidence"],
            "model_version": settings.app_version,
            "inference_time_ms": inference_time_ms / len(predictions),
            "source": "api",
            "probabilities": [
                {"class": k, "probability": v}
                for k, v in pred["probabilities"].items()
            ],
        }
        if not os_client.index_prediction(document):
            logger.warning("No se pudo indexar prediccion %d en OpenSearch", i)

    return PredictionResponse(
        count=len(predictions),
        model_version=settings.app_version,
        inference_time_ms=inference_time_ms,
        predictions=[PredictionItem(**p) for p in predictions],
    )