"""
Schemas Pydantic para request/response de la API.

Define los DTOs (Data Transfer Objects) con validacion automatica
y documentacion Swagger/OpenAPI.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class HealthResponse(BaseModel):
    """Respuesta del endpoint /health."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "status": "healthy",
                "version": "1.0.0",
                "model_loaded": True,
                "scaler_loaded": True,
                "opensearch_reachable": True,
                "timestamp": "2026-07-11T20:00:00Z",
            }
        }
    )

    status: str = Field(..., description="Estado del servicio: healthy | degraded | unhealthy")
    version: str = Field(..., description="Version de la API")
    model_loaded: bool = Field(..., description="Si el modelo ML esta cargado")
    scaler_loaded: bool = Field(..., description="Si el scaler esta cargado")
    opensearch_reachable: bool = Field(..., description="Si OpenSearch responde")
    timestamp: datetime = Field(..., description="Momento de la verificacion")


class PredictionRequest(BaseModel):
    """Request para /predict con un batch de eventos.

    Cada evento es un dict feature_name -> valor numerico.
    Se acepta cualquier cantidad de features; las que falten
    seran completadas con 0 (con warning en logs).
    """

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "events": [
                    {
                        "Flow Duration": 117189197,
                        "Total Fwd Packets": 4,
                        "Total Backward Packets": 2,
                        "Fwd Packets Length Total": 334,
                        "Bwd Packets Length Total": 1250,
                        "Protocol": 6
                    }
                ]
            }
        }
    )

    events: list[dict[str, float]] = Field(
        ...,
        min_length=1,
        max_length=10000,
        description="Lista de eventos a clasificar (cada uno es un dict de features)",
    )


class PredictionItem(BaseModel):
    """Una prediccion individual."""

    prediction: str = Field(..., description="Clase predicha (string)")
    prediction_id: int = Field(..., description="Clase predicha (entero)")
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Probabilidad de la clase predicha",
    )
    probabilities: dict[str, float] = Field(
        ...,
        description="Probabilidad por clase (todas las clases)",
    )


class PredictionResponse(BaseModel):
    """Respuesta de /predict con todas las predicciones del batch."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "count": 1,
                "model_version": "1.0.0",
                "inference_time_ms": 12.5,
                "predictions": [
                    {
                        "prediction": "DoS",
                        "prediction_id": 4,
                        "confidence": 0.97,
                        "probabilities": {
                            "Benign": 0.001,
                            "DoS": 0.97,
                            "DDoS": 0.02,
                            "Bot": 0.005,
                            "BruteForce": 0.001,
                            "WebAttack": 0.001,
                            "PortScan": 0.001,
                            "Infiltration": 0.0,
                            "Other": 0.0
                        }
                    }
                ]
            }
        }
    )

    count: int = Field(..., description="Numero de predicciones devueltas")
    model_version: str = Field(..., description="Version del modelo usado")
    inference_time_ms: float = Field(..., description="Tiempo de inferencia total (ms)")
    predictions: list[PredictionItem] = Field(..., description="Lista de predicciones")


class ErrorResponse(BaseModel):
    """Respuesta de error estandar."""

    detail: str = Field(..., description="Mensaje de error")
    error_code: str | None = Field(default=None, description="Codigo de error opcional")
    timestamp: datetime = Field(..., description="Momento del error")


class SuricataEventRequest(BaseModel):
    """Schema para eventos Suricata en formato EVE JSON."""

    model_config = ConfigDict(extra="allow")

    timestamp: str | None = Field(default=None, description="Timestamp ISO 8601")
    flow_id: int | None = None
    in_iface: str | None = None
    event_type: str | None = Field(default="alert", description="alert, http, flow, etc.")
    src_ip: str | None = None
    src_port: int | None = None
    dest_ip: str | None = None
    dest_port: int | None = None
    proto: str | None = None
    app_proto: str | None = None
    alert: dict[str, Any] | None = Field(default=None, description="Bloque alert de Suricata")
    http: dict[str, Any] | None = None
    flow: dict[str, Any] | None = None
    metadata: dict[str, Any] | None = None