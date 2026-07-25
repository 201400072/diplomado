"""
Tests del orquestador Wazuh -> API ML con httpx mockeado.

Uso:
    cd api && source .venv-api/bin/activate && pytest tests/integration/test_orchestrator.py -v
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
import pytest

from app.infrastructure.wazuh.orchestrator import WazuhMLOrchestrator


@pytest.fixture
def orchestrator() -> WazuhMLOrchestrator:
    """Crea el orquestador con clientes HTTP mockeados."""
    orch = WazuhMLOrchestrator.__new__(WazuhMLOrchestrator)
    orch.wazuh_url = "https://localhost:9200"
    orch.wazuh_user = "admin"
    orch.wazuh_password = "SecretPassword"
    orch.ml_api_url = "http://localhost:8000"
    orch.ml_api_key = "test-key"
    orch.ml_index_prefix = "wazuh-ml"
    # Cargar feature template
    from app.infrastructure.wazuh.orchestrator import _get_feature_template
    orch.feature_names, orch.feature_template = _get_feature_template()
    # Clientes mockeados
    orch.wazuh_client = MagicMock()
    orch.ml_client = MagicMock()
    orch.processed_alerts = set()
    return orch


@pytest.fixture
def sample_alerts() -> list[dict]:
    """Alertas Suricata realistas como las devuelve Wazuh Indexer."""
    return [
        {
            "_index": "wazuh-alerts-4.x-2026.07.11",
            "_id": "alert-001",
            "_source": {
                "timestamp": "2026-07-11T19:00:00.000Z",
                "id": "alert-001",
                "rule": {
                    "id": "86601",
                    "level": 3,
                    "description": "Suricata: Alert - Nmap scan",
                    "groups": ["ids", "suricata"],
                },
                "data": {
                    "srcip": "10.10.10.30",
                    "dstip": "10.10.10.40",
                    "alert_severity": 2,
                    "suricata_alert_signature": "ET SCAN Nmap",
                },
            },
        },
        {
            "_index": "wazuh-alerts-4.x-2026.07.11",
            "_id": "alert-002",
            "_source": {
                "timestamp": "2026-07-11T19:01:00.000Z",
                "id": "alert-002",
                "rule": {
                    "id": "86601",
                    "level": 3,
                    "description": "Suricata: Alert - SQL Injection",
                    "groups": ["ids", "suricata"],
                },
                "data": {
                    "srcip": "10.10.10.30",
                    "dstip": "10.10.10.40",
                    "alert_severity": 1,
                    "suricata_alert_signature": "ET WEB_SERVER SQL Injection",
                },
            },
        },
        {
            "_index": "wazuh-alerts-4.x-2026.07.11",
            "_id": "alert-003",
            "_source": {
                "timestamp": "2026-07-11T19:02:00.000Z",
                "id": "alert-003",
                "rule": {
                    "id": "86601",
                    "level": 3,
                    "description": "Suricata: Alert - Brute Force",
                    "groups": ["ids", "suricata"],
                },
                "data": {
                    "srcip": "10.10.10.30",
                    "dstip": "10.10.10.40",
                    "alert_severity": 1,
                    "suricata_alert_signature": "ET BRUTE FORCE Hydra",
                },
            },
        },
    ]


def _mock_response(status: int, json_data: dict | None = None) -> httpx.Response:
    request = httpx.Request("GET", "http://localhost")
    return httpx.Response(status_code=status, json=json_data or {}, request=request)


# =====================================================
# Tests de feature transformation
# =====================================================

def test_alert_to_features_nmap(orchestrator):
    """Alerta severidad 2 (Nmap) genera 69 features correctas."""
    alert = {
        "id": "test-001",
        "data": {
            "srcip": "10.10.10.30",
            "dstip": "10.10.10.40",
            "alert_severity": 2,
            "suricata_alert_signature": "ET SCAN Nmap",
        },
        "rule": {"description": "Nmap"},
    }
    out = orchestrator.alert_to_features(alert)
    assert out["src_ip"] == "10.10.10.30"
    assert out["dst_ip"] == "10.10.10.40"
    assert out["alert_signature"] == "ET SCAN Nmap"
    assert out["alert_severity"] == 2

    features = out["features"]
    # Exactamente 69 features (las del scaler)
    assert len(features) == 69
    assert len(orchestrator.feature_names) == 69
    assert set(features.keys()) == set(orchestrator.feature_names)

    # Protocol es TCP
    assert features["Protocol"] == 6
    # severity=2 -> mult=2.5, Flow Duration base=1_000_000 * 2.5 = 2_500_000
    assert features["Flow Duration"] == 2_500_000.0


def test_alert_to_features_severity_3(orchestrator):
    """Severidad 3 (alta) escala mas fuerte."""
    alert = {
        "id": "test-002",
        "data": {
            "srcip": "10.10.10.30",
            "dstip": "10.10.10.40",
            "alert_severity": 3,
            "suricata_alert_signature": "ET CRITICAL",
        },
    }
    out = orchestrator.alert_to_features(alert)
    assert out["alert_severity"] == 3
    # severity=3 -> mult=5.0, Flow Duration base=1_000_000 * 5 = 5_000_000
    assert out["features"]["Flow Duration"] == 5_000_000.0


def test_alert_to_features_handles_missing_data(orchestrator):
    """Si faltan campos, usa defaults razonables."""
    alert = {
        "id": "test-003",
        "rule": {"description": "Generic"},
    }
    out = orchestrator.alert_to_features(alert)
    assert out["src_ip"] == ""
    assert out["alert_severity"] == 1
    # 69 features aunque no haya data
    assert len(out["features"]) == 69


def test_alert_to_features_sqli_severity_1(orchestrator):
    """SQLi severidad 1 -> mult=1.0, Flow Duration base."""
    alert = {
        "id": "test-004",
        "data": {
            "srcip": "10.10.10.30",
            "dstip": "10.10.10.40",
            "alert_severity": 1,
            "suricata_alert_signature": "ET SQLi",
        },
    }
    out = orchestrator.alert_to_features(alert)
    assert out["features"]["Flow Duration"] == 1_000_000.0


def test_alert_to_features_uses_correct_names(orchestrator):
    """Las features usan los nombres EXACTOS del scaler (no abreviaturas)."""
    alert = {"id": "x", "data": {"alert_severity": 2}}
    out = orchestrator.alert_to_features(alert)
    feats = out["features"]
    # Nombres del scaler (no las versiones con guiones bajos o iniciales)
    assert "Init Fwd Win Bytes" in feats
    assert "Init Bwd Win Bytes" in feats
    assert "Fwd Act Data Packets" in feats
    assert "Fwd Seg Size Min" in feats
    # No deben existir las versiones antiguas
    assert "Init_Win_bytes_forward" not in feats
    assert "act_data_pkt_fwd" not in feats
    assert "min_seg_size_forward" not in feats


# =====================================================
# Tests de HTTP calls (mocked)
# =====================================================

def test_call_ml_api_success(orchestrator):
    """call_ml_api retorna JSON de respuesta exitosa."""
    mock_response = _mock_response(200, {
        "count": 1,
        "model_version": "1.0.0",
        "inference_time_ms": 5.0,
        "predictions": [{
            "prediction": "DoS",
            "prediction_id": 4,
            "confidence": 0.97,
            "probabilities": {"DoS": 0.97, "Benign": 0.03},
        }],
    })
    orchestrator.ml_client.post.return_value = mock_response

    result = orchestrator.call_ml_api({"Flow Duration": 1000})
    assert result["count"] == 1
    assert result["predictions"][0]["prediction"] == "DoS"
    orchestrator.ml_client.post.assert_called_once_with(
        "/api/v1/predict",
        json={"events": [{"Flow Duration": 1000}]},
    )


def test_call_ml_api_http_error(orchestrator):
    """call_ml_api retorna dict vacio en error HTTP."""
    mock_response = _mock_response(500, {"detail": "Internal server error"})
    orchestrator.ml_client.post.return_value = mock_response

    result = orchestrator.call_ml_api({"Flow Duration": 1000})
    assert result == {}


def test_call_ml_api_connection_error(orchestrator):
    """call_ml_api maneja excepcion de conexion."""
    orchestrator.ml_client.post.side_effect = httpx.ConnectError("Connection refused")
    result = orchestrator.call_ml_api({"Flow Duration": 1000})
    assert result == {}


def test_ensure_index_creates_if_missing(orchestrator):
    """_ensure_index crea el indice si no existe."""
    head_404 = _mock_response(404)
    put_201 = _mock_response(201, {"acknowledged": True})

    orchestrator.wazuh_client.head.return_value = head_404
    orchestrator.wazuh_client.put.return_value = put_201

    result = orchestrator._ensure_index()
    assert result is True
    orchestrator.wazuh_client.put.assert_called_once()
    call_args = orchestrator.wazuh_client.put.call_args
    assert "mappings" in str(call_args)


def test_ensure_index_existing(orchestrator):
    """_ensure_index retorna True si el indice ya existe."""
    head_200 = _mock_response(200)
    orchestrator.wazuh_client.head.return_value = head_200

    result = orchestrator._ensure_index()
    assert result is True
    orchestrator.wazuh_client.put.assert_not_called()


def test_index_prediction_success(orchestrator):
    """index_prediction indexa correctamente."""
    ensure_true = _mock_response(200)
    index_201 = _mock_response(201, {"result": "created"})
    orchestrator.wazuh_client.head.return_value = ensure_true
    orchestrator.wazuh_client.post.return_value = index_201

    doc = {
        "alert_id": "test-123",
        "prediction": "DoS",
        "confidence": 0.95,
    }
    result = orchestrator.index_prediction(doc)
    assert result is True
    orchestrator.wazuh_client.post.assert_called_once()


def test_fetch_new_suricata_alerts(orchestrator, sample_alerts):
    """fetch_new_suricata_alerts parsea correctamente."""
    search_response = _mock_response(200, {
        "hits": {
            "total": {"value": len(sample_alerts)},
            "hits": [{"_source": a["_source"]} for a in sample_alerts],
        }
    })
    orchestrator.wazuh_client.post.return_value = search_response

    alerts = orchestrator.fetch_new_suricata_alerts()
    assert len(alerts) == 3
    assert alerts[0]["id"] == "alert-001"


# =====================================================
# Tests de process_alert end-to-end
# =====================================================

def test_process_alert_end_to_end(orchestrator, sample_alerts):
    """Pipeline completo: alerta -> features -> ML -> indexar."""
    alert = sample_alerts[0]["_source"]

    ml_response = _mock_response(200, {
        "count": 1, "model_version": "1.0.0", "inference_time_ms": 8.0,
        "predictions": [{
            "prediction": "DoS", "prediction_id": 4,
            "confidence": 0.95, "probabilities": {"DoS": 0.95, "Benign": 0.05},
        }],
    })
    index_response = _mock_response(201, {})

    orchestrator.ml_client.post.return_value = ml_response
    orchestrator.wazuh_client.head.return_value = _mock_response(200)
    orchestrator.wazuh_client.post.return_value = index_response

    result = orchestrator.process_alert(alert)
    assert result is True
    assert "alert-001" in orchestrator.processed_alerts


def test_process_alert_idempotent(orchestrator, sample_alerts):
    """Una alerta procesada dos veces no se duplica."""
    alert = sample_alerts[0]["_source"]

    ml_response = _mock_response(200, {
        "count": 1, "model_version": "1.0.0", "inference_time_ms": 8.0,
        "predictions": [{
            "prediction": "DoS", "prediction_id": 4,
            "confidence": 0.95, "probabilities": {},
        }],
    })
    index_response = _mock_response(201, {})
    orchestrator.ml_client.post.return_value = ml_response
    orchestrator.wazuh_client.head.return_value = _mock_response(200)
    orchestrator.wazuh_client.post.return_value = index_response

    # Primera vez: procesa
    assert orchestrator.process_alert(alert) is True
    # Segunda vez: ya procesada
    assert orchestrator.process_alert(alert) is False


def test_process_alert_without_id(orchestrator):
    """Sin id de alerta, retorna False."""
    alert = {"data": {"alert_severity": 1}}
    result = orchestrator.process_alert(alert)
    assert result is False


def test_process_alert_ml_fails(orchestrator, sample_alerts):
    """Si la API ML falla, retorna False y no marca como procesada."""
    alert = sample_alerts[0]["_source"]

    ml_response = _mock_response(500, {"detail": "Error"})
    orchestrator.ml_client.post.return_value = ml_response

    result = orchestrator.process_alert(alert)
    assert result is False
    assert "alert-001" not in orchestrator.processed_alerts


def test_run_once_processes_all(orchestrator, sample_alerts):
    """run_once procesa todas las alertas nuevas."""
    search_response = _mock_response(200, {
        "hits": {
            "total": {"value": 3},
            "hits": [{"_source": a["_source"]} for a in sample_alerts],
        }
    })
    ml_response = _mock_response(200, {
        "count": 1, "model_version": "1.0.0", "inference_time_ms": 5.0,
        "predictions": [{
            "prediction": "Benign", "prediction_id": 0,
            "confidence": 0.9, "probabilities": {},
        }],
    })
    index_response = _mock_response(201, {})

    # search returns first; then 3 index_response calls
    orchestrator.wazuh_client.post.side_effect = [search_response, index_response, index_response, index_response]
    orchestrator.wazuh_client.head.return_value = _mock_response(200)
    orchestrator.ml_client.post.return_value = ml_response

    n = orchestrator.run_once()
    assert n == 3