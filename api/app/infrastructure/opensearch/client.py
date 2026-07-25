"""
Cliente de OpenSearch para indexar predicciones ML.

Encapsula la conexion y operaciones basicas con OpenSearch,
incluyendo la creacion automatica del indice con mapping apropiado.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any

from opensearchpy import OpenSearch

logger = logging.getLogger(__name__)


class OpenSearchClient:
    """Cliente OpenSearch singleton con operaciones basicas."""

    def __init__(
        self,
        host: str,
        port: int,
        scheme: str,
        user: str,
        password: str,
        verify_ssl: bool,
        index_prefix: str,
    ) -> None:
        self.index_prefix = index_prefix
        self._client = OpenSearch(
            hosts=[{"host": host, "port": port}],
            http_auth=(user, password),
            use_ssl=(scheme == "https"),
            verify_certs=verify_ssl,
            ssl_show_warn=False,
            timeout=3,  # timeout corto para no bloquear la API
            max_retries=0,
        )

    @property
    def client(self) -> OpenSearch:
        return self._client

    @property
    def index_name(self) -> str:
        """Nombre del indice con fecha actual (rotacion diaria)."""
        today = datetime.now(timezone.utc).strftime("%Y.%m.%d")
        return f"{self.index_prefix}-{today}"

    def is_reachable(self) -> bool:
        """Comprueba si el cluster responde."""
        try:
            return self._client.ping()
        except Exception as exc:
            logger.warning("OpenSearch no responde: %s", exc)
            return False

    def cluster_health(self) -> dict[str, Any] | None:
        """Retorna el estado del cluster o None si falla."""
        try:
            return dict(self._client.cluster.health())
        except Exception as exc:
            logger.warning("No se pudo obtener health: %s", exc)
            return None

    def ensure_index(self) -> bool:
        """Crea el indice diario si no existe."""
        name = self.index_name
        try:
            if not self._client.indices.exists(index=name):
                body = {
                    "settings": {
                        "number_of_shards": 1,
                        "number_of_replicas": 0,
                    },
                    "mappings": {
                        "properties": {
                            "timestamp": {"type": "date"},
                            "prediction": {"type": "keyword"},
                            "prediction_id": {"type": "integer"},
                            "confidence": {"type": "float"},
                            "model_version": {"type": "keyword"},
                            "inference_time_ms": {"type": "float"},
                            "source": {"type": "keyword"},
                            "src_ip": {"type": "ip"},
                            "dest_ip": {"type": "ip"},
                            "dest_port": {"type": "integer"},
                            "alert_signature": {"type": "text"},
                            "alert_severity": {"type": "integer"},
                            "probabilities": {
                                "type": "nested",
                                "properties": {
                                    "class": {"type": "keyword"},
                                    "probability": {"type": "float"},
                                }
                            },
                            "raw_event": {"type": "object", "enabled": False},
                        }
                    }
                }
                self._client.indices.create(index=name, body=body)
                logger.info("Indice creado: %s", name)
            return True
        except Exception as exc:
            logger.error("Error creando indice %s: %s", name, exc)
            return False

    def index_prediction(self, document: dict[str, Any]) -> bool:
        """Indexa un documento de prediccion."""
        if not self.ensure_index():
            return False
        try:
            self._client.index(
                index=self.index_name,
                body=document,
                refresh=False,
            )
            return True
        except Exception as exc:
            logger.error("Error indexando prediccion: %s", exc)
            return False


@lru_cache(maxsize=1)
def get_opensearch_client() -> OpenSearchClient:
    """Retorna el cliente singleton."""
    from app.config.settings import get_settings
    settings = get_settings()
    return OpenSearchClient(
        host=settings.opensearch_host,
        port=settings.opensearch_port,
        scheme=settings.opensearch_scheme,
        user=settings.opensearch_user,
        password=settings.opensearch_password,
        verify_ssl=settings.opensearch_verify_ssl,
        index_prefix=settings.opensearch_index_prefix,
    )