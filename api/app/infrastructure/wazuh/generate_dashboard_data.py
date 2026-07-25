"""
Genera un dataset realista de alertas Suricata para el dashboard.

Crea 50 alertas de diferentes tipos (Nmap, SQLi, Brute Force, XSS, DoS, Bot)
con diferentes IPs y niveles de severidad, las inyecta al Wazuh Indexer,
y luego las procesa con el orquestador para generar predicciones ML.

Uso:
    python -m app.infrastructure.wazuh.generate_dashboard_data
"""
from __future__ import annotations

import logging
import random
import sys
import time
from datetime import datetime, timedelta, timezone

import httpx


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("gen-data")

WAZUH_URL = "https://localhost:9200"
WAZUH_AUTH = ("admin", "SecretPassword")
WAZUH_VERIFY = False

ALERT_INDEX = "wazuh-alerts-demo"
ML_INDEX_PREFIX = "wazuh-ml-demo"

# Firmas Suricata realistas con su severidad tipica
ATTACK_TEMPLATES = [
    ("ET SCAN Nmap Scripting Engine", 2, "Reconocimiento"),
    ("ET SCAN Suspicious inbound to mySQL port 3306", 2, "Reconocimiento"),
    ("ET WEB_SERVER SQL Injection", 1, "SQL Injection"),
    ("ET WEB_SERVER Possible SQL Injection", 1, "SQL Injection"),
    ("ET WEB_SERVER XSS Attempt", 1, "XSS"),
    ("ET WEB_SERVER Cross Site Scripting", 1, "XSS"),
    ("ET BRUTE FORCE Hydra", 1, "Brute Force"),
    ("ET POLICY SSH brute force attempt", 1, "Brute Force"),
    ("ET DOS ApacheBench user agent", 2, "DoS"),
    ("ET DOS Slowloris attack", 2, "DoS"),
    ("ET MALWARE Bot C&C Channel", 3, "Bot"),
    ("ET TROJAN Possible Win32/Sality", 3, "Malware"),
    ("ET POLICY Outgoing Basic Auth Base64 HTTP Password", 1, "Policy"),
]

# IPs atacante simuladas (internas al lab)
ATTACKER_IPS = ["10.10.10.30", "10.10.10.31", "10.10.10.32", "192.168.1.100"]
VICTIM_IPS = ["10.10.10.40", "10.10.10.41"]

VICTIM_PORTS = [80, 443, 22, 3306, 8080]


def generate_alerts(n: int = 50) -> list[dict]:
    """Genera N alertas Suricata sinteticas realistas."""
    random.seed(42)  # Reproducibilidad
    alerts = []
    now = datetime.now(timezone.utc)
    base_id = int(time.time())

    for i in range(n):
        template = random.choice(ATTACK_TEMPLATES)
        signature, severity, attack_type = template
        alert = {
            "timestamp": (now - timedelta(minutes=random.randint(0, 1440))).isoformat().replace("+00:00", "Z"),
            "id": f"gen-{base_id}-{i}",
            "rule": {
                "id": "86601",
                "level": severity + 2,
                "description": f"Suricata: Alert - {signature}",
                "groups": ["ids", "suricata"],
            },
            "data": {
                "srcip": random.choice(ATTACKER_IPS),
                "dstip": random.choice(VICTIM_IPS),
                "dstport": random.choice(VICTIM_PORTS),
                "alert_severity": severity,
                "suricata_alert_signature": signature,
            },
            "manager": {"name": "wazuh.manager"},
        }
        alerts.append(alert)
    return alerts


def inject_to_wazuh(client: httpx.Client, alerts: list[dict]) -> int:
    """Inyecta alertas al indice wazuh-alerts-demo."""
    # Asegurar que el indice existe
    if client.head(f"{WAZUH_URL}/{ALERT_INDEX}").status_code == 404:
        client.put(f"{WAZUH_URL}/{ALERT_INDEX}", json={
            "mappings": {"properties": {
                "timestamp": {"type": "date"},
                "id": {"type": "keyword"},
                "rule": {"type": "object"},
                "data": {"type": "object"},
                "manager": {"type": "object"},
            }}
        })
        logger.info("Indice %s creado", ALERT_INDEX)

    injected = 0
    for alert in alerts:
        r = client.post(f"{WAZUH_URL}/{ALERT_INDEX}/_doc", json=alert)
        if r.status_code in (200, 201):
            injected += 1
    client.post(f"{WAZUH_URL}/{ALERT_INDEX}/_refresh")
    return injected


def main() -> int:
    client = httpx.Client(auth=WAZUH_AUTH, verify=WAZUH_VERIFY, timeout=10)

    # Verificar conexion
    try:
        r = client.get(f"{WAZUH_URL}/_cluster/health")
        if r.status_code != 200:
            logger.error("OpenSearch no responde")
            return 1
    except Exception as exc:
        logger.error("Error OpenSearch: %s", exc)
        return 1

    # Generar alertas
    alerts = generate_alerts(50)
    logger.info("Generadas %d alertas sinteticas", len(alerts))

    # Inyectar
    n = inject_to_wazuh(client, alerts)
    logger.info("Inyectadas %d alertas en %s", n, ALERT_INDEX)

    # Ejecutar orquestador
    logger.info("Ejecutando orquestador...")
    import os
    os.environ["WAZUH_INDEXER_URL"] = WAZUH_URL
    os.environ["WAZUH_USER"] = WAZUH_AUTH[0]
    os.environ["WAZUH_PASSWORD"] = WAZUH_AUTH[1]
    os.environ["WAZUH_VERIFY_SSL"] = "false"

    from app.infrastructure.wazuh import orchestrator as orch_mod
    from app.infrastructure.wazuh.orchestrator import WazuhMLOrchestrator

    orch = WazuhMLOrchestrator()
    ALERT_PATTERN_ORIG = orch_mod.ALERT_INDEX_PATTERN
    ML_PREFIX_ORIG = orch.ml_index_prefix
    orch_mod.ALERT_INDEX_PATTERN = ALERT_INDEX
    orch.ml_index_prefix = ML_INDEX_PREFIX

    lookback = (datetime.now(timezone.utc) - timedelta(days=2))
    since_ts = lookback.isoformat().replace("+00:00", "Z")
    found = orch.fetch_new_suricata_alerts(since_timestamp=since_ts)
    logger.info("Encontradas %d alertas por procesar", len(found))

    processed = 0
    for alert in found:
        if orch.process_alert(alert):
            processed += 1

    orch_mod.ALERT_INDEX_PATTERN = ALERT_PATTERN_ORIG
    orch.ml_index_prefix = ML_PREFIX_ORIG

    logger.info("Procesadas: %d/%d", processed, len(found))

    # Refresh y verificar
    ml_index_name = f"{ML_INDEX_PREFIX}-{datetime.now(timezone.utc).strftime('%Y.%m.%d')}"
    client.post(f"{WAZUH_URL}/{ml_index_name}/_refresh")
    r = client.get(f"{WAZUH_URL}/{ml_index_name}/_count")
    if r.status_code == 200:
        count = r.json().get("count", 0)
        logger.info("Total en %s: %d documentos", ml_index_name, count)

    # Distribucion por clase
    r = client.post(f"{WAZUH_URL}/{ml_index_name}/_search", json={
        "size": 0,
        "aggs": {
            "by_prediction": {"terms": {"field": "prediction", "size": 10}}
        }
    })
    if r.status_code == 200:
        buckets = r.json().get("aggregations", {}).get("by_prediction", {}).get("buckets", [])
        logger.info("\n=== Distribucion de predicciones ===")
        for b in buckets:
            logger.info("  %s: %d", b["key"], b["doc_count"])

    return 0 if processed == len(found) else 1


if __name__ == "__main__":
    sys.exit(main())