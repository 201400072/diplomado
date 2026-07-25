"""
Endpoint: GET /health

Verifica el estado del servicio y la disponibilidad de
dependencias externas (modelo ML, scaler, OpenSearch).
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, status

from app.config.settings import get_settings
from app.infrastructure.ml.loader import get_model_loader
from app.infrastructure.opensearch.client import get_opensearch_client
from app.schemas.predict import HealthResponse

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get(
    "/health",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Health check",
    description="Verifica el estado del servicio, modelo ML y OpenSearch.",
    tags=["health"],
)
def health_check() -> HealthResponse:
    """Health check endpoint (sin autenticacion)."""
    settings = get_settings()
    loader = get_model_loader()
    os_client = get_opensearch_client()

    model_loaded = loader.is_loaded
    scaler_loaded = loader._scaler is not None if hasattr(loader, "_scaler") else False
    os_reachable = os_client.is_reachable()

    if model_loaded and scaler_loaded and os_reachable:
        status_str = "healthy"
    elif model_loaded and scaler_loaded:
        status_str = "degraded"
    else:
        status_str = "unhealthy"

    return HealthResponse(
        status=status_str,
        version=settings.app_version,
        model_loaded=model_loaded,
        scaler_loaded=scaler_loaded,
        opensearch_reachable=os_reachable,
        timestamp=datetime.now(timezone.utc),
    )