"""
Crea las visualizaciones y el dashboard en Wazuh Dashboard via API.

Wazuh Dashboard es OpenSearch Dashboards + plugin de Wazuh.
Podemos usar la API REST para crear index patterns, visualizaciones
y dashboards programaticamente.

Uso:
    python -m app.infrastructure.wazuh.setup_dashboards
"""
from __future__ import annotations

import json
import logging
import sys
from typing import Any

import httpx


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("setup-dashboards")

# OpenSearch Dashboards API (puerto 443 mapea a 5601 interno)
DASHBOARDS_URL = "https://localhost:443"
DASHBOARDS_USER = "admin"
DASHBOARDS_PASSWORD = "SecretPassword"

# OpenSearch Indices
INDEX_ML = "wazuh-ml-demo-*"
INDEX_ALERTS = "wazuh-alerts-*"  # Para alertas Wazuh


def dashboards_request(client: httpx.Client, method: str, path: str, **kwargs) -> httpx.Response:
    """Wrapper para requests a OpenSearch Dashboards API."""
    # CSRF protection: necesitamos el header osd-xsrf
    headers = kwargs.pop("headers", {}) or {}
    headers.setdefault("osd-xsrf", "true")
    headers.setdefault("Content-Type", "application/json")
    return client.request(method, f"{DASHBOARDS_URL}{path}", headers=headers, **kwargs)


def create_index_pattern(client: httpx.Client, name: str, time_field: str = "@timestamp") -> str:
    """Crea un index pattern. Retorna el ID."""
    pattern_id = name.replace("*", "").replace("-", "_")
    payload = {
        "attributes": {
            "title": name,
            "timeFieldName": time_field,
        }
    }
    # Verificar si ya existe
    r = dashboards_request(client, "POST", f"/api/saved_objects/index-pattern/{pattern_id}",
                           json=payload)
    if r.status_code == 200:
        logger.info("Index pattern creado: %s (id=%s)", name, pattern_id)
    elif r.status_code == 409:
        logger.info("Index pattern ya existe: %s", name)
    else:
        logger.warning("Index pattern %s: HTTP %d - %s", name, r.status_code, r.text[:200])
    return pattern_id


def create_visualization(
    client: httpx.Client,
    vis_id: str,
    title: str,
    vis_type: str,
    index_pattern_id: str,
    params: dict[str, Any],
) -> bool:
    """Crea una visualizacion (lens/pie/bar/etc)."""
    payload = {
        "attributes": {
            "title": title,
            "visState": json.dumps({
                "type": vis_type,
                "params": params,
            }),
            "uiStateJSON": "{}",
            "description": f"SOC Diplomado - {title}",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
                    "index": index_pattern_id,
                })
            }
        }
    }
    r = dashboards_request(client, "POST", f"/api/saved_objects/visualization/{vis_id}",
                           json=payload)
    if r.status_code == 200:
        logger.info("Visualizacion creada: %s (%s)", vis_id, title)
        return True
    logger.warning("Visualizacion %s: HTTP %d - %s", vis_id, r.status_code, r.text[:200])
    return False


def create_dashboard(
    client: httpx.Client,
    dash_id: str,
    title: str,
    description: str,
    panels: list[dict[str, Any]],
) -> bool:
    """Crea un dashboard con paneles."""
    payload = {
        "attributes": {
            "title": title,
            "description": description,
            "panelsJSON": json.dumps(panels),
            "optionsJSON": json.dumps({
                "useMargins": True,
                "hidePanelTitles": False,
            }),
            "timeRestore": True,
            "timeTo": "now",
            "timeFrom": "now-24h",
            "refreshInterval": {
                "pause": False,
                "value": 60000,
            },
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "query": {"language": "kuery", "query": ""},
                    "filter": []
                })
            }
        }
    }
    r = dashboards_request(client, "POST", f"/api/saved_objects/dashboard/{dash_id}",
                           json=payload)
    if r.status_code == 200:
        logger.info("Dashboard creado: %s (%s)", dash_id, title)
        return True
    logger.warning("Dashboard %s: HTTP %d - %s", dash_id, r.status_code, r.text[:200])
    return False


def setup_all(client: httpx.Client) -> int:
    """Crea index patterns, visualizaciones y dashboard."""
    logger.info("=" * 70)
    logger.info(" SETUP DE DASHBOARDS - SOC DIPLOMADO")
    logger.info("=" * 70)

    # 1. Index patterns
    logger.info("\n[1/3] Creando index patterns...")
    ml_id = create_index_pattern(client, INDEX_ML, time_field="@timestamp")
    alert_id = create_index_pattern(client, INDEX_ALERTS, time_field="timestamp")

    # 2. Visualizaciones
    logger.info("\n[2/3] Creando visualizaciones...")

    # Viz 1: Cantidad de predicciones ML por clase
    create_visualization(
        client, "ml-predictions-by-class",
        "Cantidad de Predicciones ML por Clase",
        "histogram",
        ml_id,
        {
            "type": "histogram",
            "grid": {"categoryLines": False},
            "categoryAxes": [{
                "id": "CategoryAxis-1",
                "type": "category",
                "position": "bottom",
                "show": True,
                "scale": {"type": "linear"},
            }],
            "valueAxes": [{
                "id": "ValueAxis-1",
                "name": "LeftAxis-1",
                "type": "value",
                "position": "left",
                "show": True,
                "scale": {"type": "linear", "mode": "normal"},
            }],
            "seriesParams": [{
                "show": True,
                "type": "histogram",
                "data": {"label": "Count", "id": "1"},
                "valueAxis": "ValueAxis-1",
                "scale": "linear",
            }],
            "addTooltip": True,
            "addLegend": True,
            "categoryAxis": {"id": "CategoryAxis-1"},
            "valueAxis": "ValueAxis-1",
            "indexPatternRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
            "interval": "auto",
            "aggConfigs": [
                {"id": "1", "type": "count", "schema": "metric"},
                {"id": "2", "type": "date_histogram", "schema": "segment", "params": {"field": "@timestamp", "interval": "auto"}},
            ],
            "filters": [],
        }
    )

    # Viz 2: Top IPs atacantes (basado en src_ip)
    create_visualization(
        client, "top-attackers",
        "Top IPs Atacantes",
        "table",
        ml_id,
        {
            "type": "table",
            "grid": {"categoryLines": False},
            "perPage": 20,
            "showPartialRows": False,
            "showMetricsAtAllLevels": False,
            "showTotal": False,
            "totalFunc": "sum",
            "percentageCol": "",
            "row": True,
            "seriesParams": [{
                "data": {"label": "Count", "id": "1"},
                "function": "sum",
                "show": True,
                "type": "number",
            }],
            "aggConfigs": [
                {"id": "1", "type": "count", "schema": "metric"},
                {"id": "2", "type": "terms", "schema": "bucket", "params": {"field": "src_ip", "size": 20, "order": "desc", "orderBy": "1"}},
                {"id": "3", "type": "terms", "schema": "bucket", "params": {"field": "alert_signature", "size": 1, "order": "desc"}},
            ],
        }
    )

    # Viz 3: Distribucion de confidence
    create_visualization(
        client, "confidence-distribution",
        "Distribucion de Confianza del Modelo ML",
        "histogram",
        ml_id,
        {
            "type": "histogram",
            "aggConfigs": [
                {"id": "1", "type": "count", "schema": "metric"},
                {"id": "2", "type": "histogram", "schema": "segment", "params": {"field": "confidence", "interval": 0.1, "min": 0, "max": 1}},
            ],
            "addLegend": True,
            "addTooltip": True,
            "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom"}],
            "valueAxes": [{"id": "ValueAxis-1", "type": "value", "position": "left"}],
            "seriesParams": [{"data": {"label": "Count", "id": "1"}, "valueAxis": "ValueAxis-1", "type": "histogram"}],
        }
    )

    # Viz 4: Tabla de predicciones recientes
    create_visualization(
        client, "ml-predictions-recent",
        "Predicciones ML Recientes",
        "table",
        ml_id,
        {
            "type": "table",
            "perPage": 10,
            "showPartialRows": False,
            "showMetricsAtAllLevels": False,
            "showTotal": False,
            "totalFunc": "sum",
            "percentageCol": "",
            "row": True,
            "seriesParams": [
                {"data": {"label": "Timestamp", "id": "1"}, "function": "max", "show": True, "type": "number"},
                {"data": {"label": "Source IP", "id": "2"}, "function": "max", "show": True, "type": "number"},
                {"data": {"label": "Prediction", "id": "3"}, "function": "max", "show": True, "type": "number"},
                {"data": {"label": "Confidence", "id": "4"}, "function": "max", "show": True, "type": "number"},
                {"data": {"label": "Signature", "id": "5"}, "function": "max", "show": True, "type": "number"},
            ],
            "aggConfigs": [
                {"id": "1", "type": "max", "schema": "metric", "params": {"field": "@timestamp"}},
                {"id": "2", "type": "max", "schema": "metric", "params": {"field": "src_ip"}},
                {"id": "3", "type": "max", "schema": "metric", "params": {"field": "prediction"}},
                {"id": "4", "type": "max", "schema": "metric", "params": {"field": "confidence"}},
                {"id": "5", "type": "max", "schema": "metric", "params": {"field": "alert_signature"}},
            ],
        }
    )

    # 3. Dashboard principal
    logger.info("\n[3/3] Creando dashboard principal...")
    panels = [
        {
            "version": "8.8.0",
            "gridData": {"x": 0, "y": 0, "w": 24, "h": 12, "i": "panel-1"},
            "panelIndex": "panel-1",
            "embeddableConfig": {},
            "panelRefName": "panel_ml_overview",
        },
        {
            "version": "8.8.0",
            "gridData": {"x": 24, "y": 0, "w": 24, "h": 12, "i": "panel-2"},
            "panelIndex": "panel-2",
            "embeddableConfig": {},
            "panelRefName": "panel_top_attackers",
        },
        {
            "version": "8.8.0",
            "gridData": {"x": 0, "y": 12, "w": 24, "h": 12, "i": "panel-3"},
            "panelIndex": "panel-3",
            "embeddableConfig": {},
            "panelRefName": "panel_confidence",
        },
        {
            "version": "8.8.0",
            "gridData": {"x": 24, "y": 12, "w": 24, "h": 15, "i": "panel-4"},
            "panelIndex": "panel-4",
            "embeddableConfig": {},
            "panelRefName": "panel_recent",
        },
    ]

    # Referencias a paneles (mapeo panelRefName -> saved object id)
    references = [
        {"name": "panel_ml_overview", "type": "visualization", "id": "ml-predictions-by-class"},
        {"name": "panel_top_attackers", "type": "visualization", "id": "top-attackers"},
        {"name": "panel_confidence", "type": "visualization", "id": "confidence-distribution"},
        {"name": "panel_recent", "type": "visualization", "id": "ml-predictions-recent"},
    ]

    # Crear dashboard (sin referencesJSON - usamos formato simplificado)
    payload = {
        "attributes": {
            "title": "SOC Diplomado - Deteccion de Amenazas con ML",
            "description": "Dashboard principal del SOC: visualiza alertas Suricata enriquecidas con predicciones XGBoost",
            "panelsJSON": json.dumps(panels),
            "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}),
            "timeRestore": True,
            "timeTo": "now",
            "timeFrom": "now-7d",
            "refreshInterval": {"pause": False, "value": 30000},
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "query": {"language": "kuery", "query": ""},
                    "filter": []
                })
            }
        }
    }
    r = dashboards_request(client, "POST", "/api/saved_objects/dashboard/soc-diplomado",
                           json=payload)
    if r.status_code == 200:
        logger.info("Dashboard 'soc-diplomado' creado")
    elif r.status_code == 409:
        # Actualizar
        r = dashboards_request(client, "PUT", "/api/saved_objects/dashboard/soc-diplomado",
                               json=payload)
        if r.status_code == 200:
            logger.info("Dashboard 'soc-diplomado' actualizado")
    else:
        logger.warning("Dashboard: HTTP %d - %s", r.status_code, r.text[:200])

    return 0


def main() -> int:
    client = httpx.Client(
        auth=(DASHBOARDS_USER, DASHBOARDS_PASSWORD),
        verify=False,
        timeout=30,
    )

    # Verificar dashboards disponibles
    try:
        r = dashboards_request(client, "GET", "/api/status")
        if r.status_code != 200:
            logger.error("OpenSearch Dashboards no responde: HTTP %d", r.status_code)
            return 1
        logger.info("OpenSearch Dashboards OK")
    except Exception as exc:
        logger.error("Error conectando a Dashboards: %s", exc)
        return 1

    return setup_all(client)


if __name__ == "__main__":
    sys.exit(main())