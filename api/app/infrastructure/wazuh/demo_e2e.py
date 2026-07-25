"""
Demo end-to-end del orquestador con un mock de Wazuh Indexer.

Genera alertas Suricata sinteticas, las inyecta al Indexer (si esta
disponible), y ejecuta el orquestador para enriquecerlas con ML.

Uso:
    python -m app.infrastructure.wazuh.demo_e2e
"""
from __future__ import annotations

import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("demo-e2e")


WAZUH_URL = "https://localhost:9200"
WAZUH_AUTH = ("admin", "SecretPassword")
WAZUH_VERIFY = False

ML_API_URL = "http://localhost:8000"
ML_API_KEY = "ml-diplomado-2026-secure-key-change-in-prod"

ML_INDEX = "wazuh-ml-demo"

# Alertas Suricata sinteticas (formato real Wazuh)
SYNTHETIC_ALERTS = [
    {
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "id": f"demo-{int(time.time())}-1",
        "rule": {
            "id": "86601",
            "level": 3,
            "description": "Suricata: Alert - POSIBLE Nmap scan",
            "groups": ["ids", "suricata"],
        },
        "data": {
            "srcip": "10.10.10.30",
            "dstip": "10.10.10.40",
            "alert_severity": 2,
            "suricata_alert_signature": "ET SCAN Nmap Scripting Engine User-Agent Detected",
        },
        "manager": {"name": "wazuh.manager"},
    },
    {
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "id": f"demo-{int(time.time())}-2",
        "rule": {
            "id": "86601",
            "level": 3,
            "description": "Suricata: Alert - DVWA SQL Injection",
            "groups": ["ids", "suricata"],
        },
        "data": {
            "srcip": "10.10.10.30",
            "dstip": "10.10.10.40",
            "alert_severity": 1,
            "suricata_alert_signature": "ET WEB_SERVER SQL Injection",
        },
        "manager": {"name": "wazuh.manager"},
    },
    {
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "id": f"demo-{int(time.time())}-3",
        "rule": {
            "id": "86601",
            "level": 3,
            "description": "Suricata: Alert - Brute Force Hydra",
            "groups": ["ids", "suricata"],
        },
        "data": {
            "srcip": "10.10.10.30",
            "dstip": "10.10.10.40",
            "alert_severity": 1,
            "suricata_alert_signature": "ET BRUTE FORCE Hydra",
        },
        "manager": {"name": "wazuh.manager"},
    },
    {
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "id": f"demo-{int(time.time())}-4",
        "rule": {
            "id": "86601",
            "level": 3,
            "description": "Suricata: Alert - ApacheBench flood",
            "groups": ["ids", "suricata"],
        },
        "data": {
            "srcip": "10.10.10.30",
            "dstip": "10.10.10.40",
            "alert_severity": 2,
            "suricata_alert_signature": "ET DOS ApacheBench user agent",
        },
        "manager": {"name": "wazuh.manager"},
    },
    {
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "id": f"demo-{int(time.time())}-5",
        "rule": {
            "id": "86601",
            "level": 3,
            "description": "Suricata: Alert - XSS attack",
            "groups": ["ids", "suricata"],
        },
        "data": {
            "srcip": "10.10.10.30",
            "dstip": "10.10.10.40",
            "alert_severity": 1,
            "suricata_alert_signature": "ET WEB_SERVER XSS",
        },
        "manager": {"name": "wazuh.manager"},
    },
]


def inject_alerts_to_wazuh_indexer(client: httpx.Client, alerts: list[dict]) -> int:
    """Inyecta alertas Suricata al indice wazuh-alerts de Wazuh Indexer."""
    if not client.put(f"{WAZUH_URL}/wazuh-alerts-demo", json={
        "mappings": {"properties": {
            "timestamp": {"type": "date"},
            "id": {"type": "keyword"},
            "rule": {"type": "object"},
            "data": {"type": "object"},
            "manager": {"type": "object"},
        }}
    }).status_code in (200, 201, 400):
        logger.info("Indice wazuh-alerts-demo listo")

    injected = 0
    for alert in alerts:
        r = client.post(f"{WAZUH_URL}/wazuh-alerts-demo/_doc", json=alert)
        if r.status_code in (200, 201):
            injected += 1
    return injected


def main() -> int:
    wazuh_client = httpx.Client(auth=WAZUH_AUTH, verify=WAZUH_VERIFY, timeout=10)

    # Verificar OpenSearch
    try:
        r = wazuh_client.get(f"{WAZUH_URL}/_cluster/health")
        if r.status_code != 200:
            logger.error("OpenSearch no responde")
            return 1
        logger.info("OpenSearch: %s", r.json().get("status"))
    except Exception as exc:
        logger.error("Error conectando a OpenSearch: %s", exc)
        return 1

    # Inyectar alertas
    logger.info("Inyectando %d alertas sinteticas...", len(SYNTHETIC_ALERTS))
    n = inject_alerts_to_wazuh_indexer(wazuh_client, SYNTHETIC_ALERTS)
    logger.info("Inyectadas %d alertas en wazuh-alerts-demo", n)

    # Esperar a que OpenSearch indexe
    wazuh_client.post(f"{WAZUH_URL}/wazuh-alerts-demo/_refresh")
    time.sleep(2)

    # Ejecutar orquestador apuntando al indice demo
    logger.info("Ejecutando orquestador contra wazuh-alerts-demo...")

    import os
    os.environ["WAZUH_INDEXER_URL"] = WAZUH_URL
    os.environ["WAZUH_USER"] = WAZUH_AUTH[0]
    os.environ["WAZUH_PASSWORD"] = WAZUH_AUTH[1]
    os.environ["WAZUH_VERIFY_SSL"] = "false"

    # Monkey-patch el orchestrator para usar el indice demo
    from app.infrastructure.wazuh import orchestrator as orch_mod
    from app.infrastructure.wazuh.orchestrator import WazuhMLOrchestrator

    # Crear orchestrator y apuntar al indice demo
    orch = WazuhMLOrchestrator()
    ALERT_INDEX_PATTERN_ORIG = orch_mod.ALERT_INDEX_PATTERN
    ML_INDEX_PREFIX_ORIG = orch.ml_index_prefix
    orch_mod.ALERT_INDEX_PATTERN = "wazuh-alerts-demo"
    orch.ml_index_prefix = "wazuh-ml-demo"

    # Reemplazar SCAN_LOOKBACK para incluir alertas recientes
    lookback = datetime.now(timezone.utc).replace(microsecond=0)
    since_ts = (lookback.replace(minute=max(0, lookback.minute - 5))).isoformat().replace("+00:00", "Z")
    alerts = orch.fetch_new_suricata_alerts(since_timestamp=since_ts)
    logger.info("Encontradas %d alertas nuevas", len(alerts))

    processed = 0
    for alert in alerts:
        if orch.process_alert(alert):
            processed += 1

    logger.info("Procesadas: %d/%d", processed, len(alerts))

    # Restaurar
    orch_mod.ALERT_INDEX_PATTERN = ALERT_INDEX_PATTERN_ORIG
    orch.ml_index_prefix = ML_INDEX_PREFIX_ORIG

    # Verificar documentos en wazuh-ml-demo
    wazuh_client.post(f"{WAZUH_URL}/wazuh-ml-demo/_refresh")
    r = wazuh_client.get(f"{WAZUH_URL}/wazuh-ml-demo/_count")
    if r.status_code == 200:
        count = r.json().get("count", 0)
        logger.info("Total documentos en wazuh-ml-demo: %d", count)

    # Mostrar 2 predicciones
    r = wazuh_client.post(f"{WAZUH_URL}/wazuh-ml-demo/_search",
                          json={"size": 2, "sort": [{"@timestamp": {"order": "desc"}}]})
    if r.status_code == 200:
        hits = r.json().get("hits", {}).get("hits", [])
        logger.info("\n=== ULTIMAS 2 PREDICCIONES INDEXADAS ===")
        for hit in hits:
            src = hit["_source"]
            logger.info("  alert_id=%s | prediction=%s (id=%d) | conf=%.3f | %s -> %s",
                       src.get("alert_id"),
                       src.get("prediction"),
                       src.get("prediction_id"),
                       src.get("confidence", 0),
                       src.get("src_ip"),
                       src.get("dest_ip"))

    return 0 if processed == len(alerts) else 1


if __name__ == "__main__":
    sys.exit(main())