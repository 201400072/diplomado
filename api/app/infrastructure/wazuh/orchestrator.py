"""
Orquestador Wazuh -> API ML.

Lee alertas Suricata desde Wazuh Indexer via HTTPS API,
las transforma en features para el modelo XGBoost, llama a
la API /predict y guarda el resultado enriquecido en el
indice wazuh-ml-YYYY.MM.DD del mismo Wazuh Indexer.

Uso:
    python src/orchestrator.py                  # modo daemon continuo
    python src/orchestrator.py --once          # procesa una vez y sale
    python src/orchestrator.py --interval 30  # cada 30s

Requiere:
    - Wazuh Indexer accesible (HTTPS)
    - FastAPI ML API corriendo (http://localhost:8000)
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import joblib


# Configuracion desde env con defaults seguros
WAZUH_INDEXER_URL = os.getenv("WAZUH_INDEXER_URL", "https://localhost:9200")
WAZUH_USER = os.getenv("WAZUH_USER", "admin")
WAZUH_PASSWORD = os.getenv("WAZUH_PASSWORD", "SecretPassword")
WAZUH_VERIFY_SSL = os.getenv("WAZUH_VERIFY_SSL", "false").lower() == "true"

ML_API_URL = os.getenv("ML_API_URL", "http://localhost:8000")
ML_API_KEY = os.getenv("ML_API_KEY", "ml-diplomado-2026-secure-key-change-in-prod")

ML_INDEX_PREFIX = "wazuh-ml"
ALERT_INDEX_PATTERN = "wazuh-alerts-*"
SCAN_LOOKBACK_MINUTES = 60

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
)
logger = logging.getLogger("wazuh-ml-orchestrator")


# Feature template con los NOMBRES EXACTOS del scaler (69 features CICFlowMeter).
# Carga dinamicamente del scaler para asegurar consistencia con FASE 7-8.
def _load_feature_template() -> tuple[list[str], list]:
    """Carga nombres de features y template de defaults del scaler entrenado."""
    from pathlib import Path
    project_root = Path(__file__).resolve().parent.parent.parent.parent.parent
    scaler_path = project_root / "ml" / "models" / "scaler.pkl"
    scaler = joblib.load(scaler_path)
    names = list(scaler.feature_names_in_)
    # Template: para cada feature, calculamos un valor por defecto en escala 1.0
    # (severity_scale = 1.0 = benign normal; 2.0 = alerta media; 3.0 = alta)
    template = {name: 0.0 for name in names}
    # Defaults por feature (basados en la mediana del dataset de entrenamiento)
    template.update({
        "Protocol": 6,                          # TCP
        "Flow Duration": 1_000_000.0,            # 1s tipico
        "Total Fwd Packets": 15.0,
        "Total Backward Packets": 13.0,
        "Fwd Packets Length Total": 1000.0,
        "Bwd Packets Length Total": 5000.0,
        "Fwd Packet Length Max": 300.0,
        "Fwd Packet Length Min": 40.0,
        "Fwd Packet Length Mean": 150.0,
        "Fwd Packet Length Std": 80.0,
        "Bwd Packet Length Max": 1600.0,
        "Bwd Packet Length Min": 60.0,
        "Bwd Packet Length Mean": 500.0,
        "Bwd Packet Length Std": 240.0,
        "Flow Bytes/s": 1000.0,
        "Flow Packets/s": 50.0,
        "Flow IAT Mean": 50000.0,
        "Flow IAT Std": 20000.0,
        "Flow IAT Max": 200000.0,
        "Flow IAT Min": 1000.0,
        "Fwd IAT Total": 200000.0,
        "Fwd IAT Mean": 40000.0,
        "Fwd IAT Std": 15000.0,
        "Fwd IAT Max": 150000.0,
        "Fwd IAT Min": 500.0,
        "Bwd IAT Total": 180000.0,
        "Bwd IAT Mean": 36000.0,
        "Bwd IAT Std": 12000.0,
        "Bwd IAT Max": 120000.0,
        "Bwd IAT Min": 400.0,
        "Fwd PSH Flags": 0.0,
        "Fwd URG Flags": 0.0,
        "Fwd Header Length": 80.0,
        "Bwd Header Length": 80.0,
        "Fwd Packets/s": 25.0,
        "Bwd Packets/s": 20.0,
        "Packet Length Min": 20.0,
        "Packet Length Max": 800.0,
        "Packet Length Mean": 150.0,
        "Packet Length Std": 80.0,
        "Packet Length Variance": 6400.0,
        "FIN Flag Count": 1.0,
        "SYN Flag Count": 1.0,
        "RST Flag Count": 1.0,
        "PSH Flag Count": 1.0,
        "ACK Flag Count": 1.0,
        "URG Flag Count": 0.0,
        "CWE Flag Count": 0.0,
        "ECE Flag Count": 0.0,
        "Down/Up Ratio": 1.0,
        "Avg Packet Size": 150.0,
        "Avg Fwd Segment Size": 75.0,
        "Avg Bwd Segment Size": 250.0,
        "Subflow Fwd Packets": 5.0,
        "Subflow Fwd Bytes": 500.0,
        "Subflow Bwd Packets": 4.0,
        "Subflow Bwd Bytes": 800.0,
        "Init Fwd Win Bytes": 1024.0,
        "Init Bwd Win Bytes": 512.0,
        "Fwd Act Data Packets": 5.0,
        "Fwd Seg Size Min": 20.0,
        "Active Mean": 50000.0,
        "Active Std": 20000.0,
        "Active Max": 200000.0,
        "Active Min": 1000.0,
        "Idle Mean": 50000.0,
        "Idle Std": 20000.0,
        "Idle Max": 200000.0,
        "Idle Min": 1000.0,
    })
    return names, template


# Carga lazy del template
_FEATURE_NAMES: list[str] | None = None
_FEATURE_TEMPLATE: dict[str, float] | None = None


def _get_feature_template() -> tuple[list[str], dict]:
    global _FEATURE_NAMES, _FEATURE_TEMPLATE
    if _FEATURE_NAMES is None:
        _FEATURE_NAMES, _FEATURE_TEMPLATE = _load_feature_template()
    return _FEATURE_NAMES, _FEATURE_TEMPLATE


class WazuhMLOrchestrator:
    """Lee alertas Suricata de Wazuh Indexer y las enriquece con ML."""

    def __init__(
        self,
        wazuh_url: str = WAZUH_INDEXER_URL,
        wazuh_user: str = WAZUH_USER,
        wazuh_password: str = WAZUH_PASSWORD,
        wazuh_verify_ssl: bool = WAZUH_VERIFY_SSL,
        ml_api_url: str = ML_API_URL,
        ml_api_key: str = ML_API_KEY,
        ml_index_prefix: str = ML_INDEX_PREFIX,
    ) -> None:
        self.wazuh_url = wazuh_url.rstrip("/")
        self.wazuh_user = wazuh_user
        self.wazuh_password = wazuh_password
        self.ml_api_url = ml_api_url.rstrip("/")
        self.ml_api_key = ml_api_key
        self.ml_index_prefix = ml_index_prefix

        # Cargar feature template desde scaler
        self.feature_names, self.feature_template = _get_feature_template()
        logger.info("Cargadas %d features del scaler", len(self.feature_names))

        self.wazuh_client = httpx.Client(
            auth=(wazuh_user, wazuh_password),
            verify=wazuh_verify_ssl,
            timeout=10,
        )
        self.ml_client = httpx.Client(
            base_url=ml_api_url,
            headers={"X-API-Key": ml_api_key, "Content-Type": "application/json"},
            timeout=30,
        )

        self.processed_alerts: set[str] = set()

    def _check_connections(self) -> None:
        try:
            r = self.ml_client.get("/api/v1/health")
            if r.status_code == 200:
                logger.info("API ML OK: %s", r.json().get("status"))
            else:
                logger.warning("API ML responde HTTP %d", r.status_code)
        except Exception as exc:
            logger.error("No se puede conectar a la API ML: %s", exc)

        try:
            r = self.wazuh_client.get(f"{self.wazuh_url}/_cluster/health")
            if r.status_code == 200:
                logger.info("Wazuh Indexer OK: %s", r.json().get("status"))
            else:
                logger.warning("Wazuh Indexer responde HTTP %d", r.status_code)
        except Exception as exc:
            logger.error("No se puede conectar a Wazuh Indexer: %s", exc)

    def _today_index(self) -> str:
        today = datetime.now(timezone.utc).strftime("%Y.%m.%d")
        return f"{self.ml_index_prefix}-{today}"

    def _ensure_index(self) -> bool:
        name = self._today_index()
        try:
            r = self.wazuh_client.head(f"{self.wazuh_url}/{name}")
            if r.status_code == 200:
                return True
            mapping = {
                "mappings": {
                    "properties": {
                        "@timestamp": {"type": "date"},
                        "alert_id": {"type": "keyword"},
                        "timestamp": {"type": "date"},
                        "prediction": {"type": "keyword"},
                        "prediction_id": {"type": "integer"},
                        "confidence": {"type": "float"},
                        "model_version": {"type": "keyword"},
                        "src_ip": {"type": "ip"},
                        "dest_ip": {"type": "ip"},
                        "alert_signature": {"type": "text"},
                        "alert_severity": {"type": "integer"},
                        "rule_id": {"type": "keyword"},
                        "rule_description": {"type": "text"},
                        "probabilities": {"type": "object", "enabled": False},
                        "raw_event": {"type": "object", "enabled": False},
                    }
                }
            }
            r = self.wazuh_client.put(f"{self.wazuh_url}/{name}", json=mapping)
            if r.status_code in (200, 201):
                logger.info("Indice ML creado: %s", name)
                return True
            logger.error("Error creando indice: HTTP %d - %s", r.status_code, r.text[:200])
            return False
        except Exception as exc:
            logger.error("Excepcion creando indice: %s", exc)
            return False

    def fetch_new_suricata_alerts(self, since_timestamp: str | None = None) -> list[dict]:
        if since_timestamp is None:
            lookback = datetime.now(timezone.utc) - timedelta(minutes=SCAN_LOOKBACK_MINUTES)
            since_timestamp = lookback.isoformat().replace("+00:00", "Z")

        query = {
            "size": 100,
            "sort": [{"timestamp": {"order": "asc"}}],
            "query": {
                "bool": {
                    "must": [
                        {"term": {"rule.groups": "suricata"}},
                        {"range": {"timestamp": {"gte": since_timestamp}}},
                    ]
                }
            },
        }
        try:
            r = self.wazuh_client.post(
                f"{self.wazuh_url}/{ALERT_INDEX_PATTERN}/_search",
                json=query,
            )
            if r.status_code != 200:
                logger.error("Error buscando alertas: HTTP %d - %s", r.status_code, r.text[:200])
                return []
            hits = r.json().get("hits", {}).get("hits", [])
            return [h["_source"] for h in hits]
        except Exception as exc:
            logger.error("Excepcion buscando alertas: %s", exc)
            return []

    def alert_to_features(self, alert: dict[str, Any]) -> dict[str, Any]:
        """Convierte una alerta Wazuh en features para el modelo.

        LIMITACION CONOCIDA: Suricata NO provee todas las 69 features de
        CICFlowMeter. Usamos defaults del template escalados por severidad.
        Esto es 'domain shift' y se documenta en conclusiones.
        """
        data = alert.get("data", {}) or {}

        src_ip = data.get("srcip", "")
        dst_ip = data.get("dstip", "")

        alert_signature = (
            data.get("suricata_alert_signature", "")
            or data.get("alert_signature", "")
            or (alert.get("rule", {}) or {}).get("description", "")
        )
        try:
            alert_severity = int(data.get("alert_severity", 1))
        except (ValueError, TypeError):
            alert_severity = 1

        # Escalar features segun severidad: 1.0=benign, 2.0=media, 3.0=alta
        severity_scale = float(alert_severity)
        # Features que escalan con severidad (mas trafico = mas bytes/packets)
        scalable_keys = {
            "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
            "Fwd Packets Length Total", "Bwd Packets Length Total",
            "Fwd Packet Length Max", "Fwd Packet Length Mean",
            "Bwd Packet Length Max", "Bwd Packet Length Mean",
            "Flow Bytes/s", "Flow Packets/s", "Fwd Packets/s", "Bwd Packets/s",
            "Packet Length Max", "Avg Packet Size",
        }
        # Multiplicadores por severidad (1=normal, 2=escaneos, 3=ataques graves)
        multipliers = {1: 1.0, 2: 2.5, 3: 5.0}
        mult = multipliers.get(alert_severity, 1.0)

        features = {}
        for name in self.feature_names:
            base = self.feature_template.get(name, 0.0)
            if name in scalable_keys:
                features[name] = float(base) * mult
            else:
                features[name] = float(base)

        return {
            "features": features,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "alert_signature": alert_signature,
            "alert_severity": alert_severity,
        }

    def call_ml_api(self, features: dict[str, Any]) -> dict[str, Any]:
        try:
            r = self.ml_client.post(
                "/api/v1/predict",
                json={"events": [features]},
            )
            r.raise_for_status()
            return r.json()
        except httpx.HTTPError as exc:
            logger.error("Error llamando API ML: %s", exc)
            return {}

    def index_prediction(self, doc: dict[str, Any]) -> bool:
        if not self._ensure_index():
            return False
        try:
            r = self.wazuh_client.post(
                f"{self.wazuh_url}/{self._today_index()}/_doc",
                json=doc,
            )
            if r.status_code in (200, 201):
                logger.info(
                    "Indexed: alert_id=%s prediction=%s conf=%.2f",
                    doc.get("alert_id"),
                    doc.get("prediction"),
                    doc.get("confidence", 0),
                )
                return True
            logger.error("Error indexando: HTTP %d - %s", r.status_code, r.text[:200])
            return False
        except Exception as exc:
            logger.error("Excepcion indexando: %s", exc)
            return False

    def process_alert(self, alert: dict[str, Any]) -> bool:
        alert_id = alert.get("id", "")
        if not alert_id:
            return False

        if alert_id in self.processed_alerts:
            return False

        transformed = self.alert_to_features(alert)
        features = transformed["features"]

        response = self.call_ml_api(features)
        if not response or "predictions" not in response:
            return False

        pred = response["predictions"][0]

        doc = {
            "@timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "alert_id": alert_id,
            "timestamp": alert.get("timestamp"),
            "prediction": pred["prediction"],
            "prediction_id": pred["prediction_id"],
            "confidence": pred["confidence"],
            "model_version": response.get("model_version", "1.0.0"),
            "src_ip": transformed["src_ip"],
            "dest_ip": transformed["dst_ip"],
            "alert_signature": transformed["alert_signature"],
            "alert_severity": transformed["alert_severity"],
            "rule_id": (alert.get("rule", {}) or {}).get("id", ""),
            "rule_description": (alert.get("rule", {}) or {}).get("description", ""),
            "probabilities": pred["probabilities"],
            "raw_event": {
                k: v for k, v in alert.items()
                if k in ("rule", "data", "agent", "manager", "full_log")
            },
        }

        if self.index_prediction(doc):
            self.processed_alerts.add(alert_id)
            return True
        return False

    def run_once(self) -> int:
        alerts = self.fetch_new_suricata_alerts()
        logger.info("Encontradas %d alertas Suricata nuevas", len(alerts))
        processed = 0
        for alert in alerts:
            if self.process_alert(alert):
                processed += 1
        return processed

    def run_daemon(self, interval: int = 30) -> None:
        logger.info("Iniciando daemon, intervalo=%ds", interval)
        try:
            while True:
                try:
                    n = self.run_once()
                    if n > 0:
                        logger.info("Ciclo completado: %d alertas enriquecidas", n)
                except KeyboardInterrupt:
                    break
                except Exception as exc:
                    logger.exception("Error en ciclo: %s", exc)
                time.sleep(interval)
        except KeyboardInterrupt:
            logger.info("Daemon detenido por usuario")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true",
                        help="Procesa una vez y sale (modo test)")
    parser.add_argument("--interval", type=int, default=30,
                        help="Intervalo en segundos para el daemon")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    orch = WazuhMLOrchestrator()
    orch._check_connections()
    if args.once:
        n = orch.run_once()
        print(f"\nResultado: {n} alertas procesadas")
        return 0 if n >= 0 else 1
    orch.run_daemon(args.interval)
    return 0


if __name__ == "__main__":
    sys.exit(main())