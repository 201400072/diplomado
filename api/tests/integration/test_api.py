"""
Tests de integracion: requieren la API corriendo (uvicorn).

Uso:
    cd api && source ../api/.venv-api/bin/activate
    uvicorn app.main:app --port 8000 &
    pytest tests/integration -v
"""
from __future__ import annotations

import os
from typing import Generator

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client() -> Generator:
    """Crea un TestClient con la app cargada."""
    from app.main import create_app
    app = create_app()
    with TestClient(app) as c:
        yield c


def test_health_no_auth(client: TestClient) -> None:
    """/health no requiere API key."""
    r = client.get("/api/v1/health")
    assert r.status_code == 200
    data = r.json()
    assert "status" in data
    assert "version" in data
    assert "model_loaded" in data


def test_root(client: TestClient) -> None:
    """/ retorna info basica."""
    r = client.get("/")
    assert r.status_code == 200
    data = r.json()
    assert "docs" in data
    assert "health" in data
    assert "predict" in data


def test_predict_without_api_key(client: TestClient) -> None:
    """/predict sin API key retorna 401."""
    r = client.post("/api/v1/predict", json={"events": [{"a": 1}]})
    assert r.status_code == 401


def test_predict_with_invalid_api_key(client: TestClient) -> None:
    """/predict con API key invalida retorna 403."""
    r = client.post(
        "/api/v1/predict",
        json={"events": [{"a": 1}]},
        headers={"X-API-Key": "invalid-key"},
    )
    assert r.status_code == 403


def test_predict_with_valid_api_key(client: TestClient) -> None:
    """/predict con API key valida retorna prediccion."""
    api_key = os.getenv("API_KEY", "ml-diplomado-2026-secure-key-change-in-prod")
    r = client.post(
        "/api/v1/predict",
        json={"events": [{"Flow Duration": 100, "Protocol": 6}]},
        headers={"X-API-Key": api_key},
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["count"] == 1
    assert "predictions" in data
    assert len(data["predictions"]) == 1
    pred = data["predictions"][0]
    assert pred["prediction"] in {
        "Benign", "DoS", "DDoS", "BruteForce", "WebAttack",
        "PortScan", "Bot", "Infiltration", "Other"
    }


def test_predict_empty_events(client: TestClient) -> None:
    """/predict con lista vacia retorna 422."""
    api_key = os.getenv("API_KEY", "ml-diplomado-2026-secure-key-change-in-prod")
    r = client.post(
        "/api/v1/predict",
        json={"events": []},
        headers={"X-API-Key": api_key},
    )
    assert r.status_code == 422  # Validacion Pydantic


def test_docs_available(client: TestClient) -> None:
    """Swagger docs disponibles."""
    r = client.get("/docs")
    assert r.status_code == 200
    assert "swagger" in r.text.lower() or "swagger" in r.headers.get("content-type", "").lower() or "<!DOCTYPE" in r.text


def test_openapi_spec(client: TestClient) -> None:
    """OpenAPI spec disponible."""
    r = client.get("/openapi.json")
    assert r.status_code == 200
    spec = r.json()
    assert "openapi" in spec
    assert "paths" in spec
    assert "/api/v1/health" in spec["paths"]
    assert "/api/v1/predict" in spec["paths"]