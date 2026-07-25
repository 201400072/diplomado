"""
Crea visualizaciones adicionales para el dashboard SOC Diplomado:
- Distribución de tipos de ataques (alert_signature)
- Timeline de eventos
"""
from __future__ import annotations

import json
import logging
import sys

import httpx


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("add-viz")

DASHBOARDS_URL = "https://localhost:443"
DASHBOARDS_USER = "admin"
DASHBOARDS_PASSWORD = "SecretPassword"

ML_INDEX = "wazuh-ml-demo-*"


def req(client: httpx.Client, method: str, path: str, **kwargs) -> httpx.Response:
    headers = kwargs.pop("headers", {}) or {}
    headers.setdefault("osd-xsrf", "true")
    headers.setdefault("Content-Type", "application/json")
    return client.request(method, f"{DASHBOARDS_URL}{path}", headers=headers, **kwargs)


def create_or_update_viz(client: httpx.Client, vis_id: str, payload: dict) -> bool:
    """Crea o actualiza una visualizacion."""
    r = req(client, "POST", f"/api/saved_objects/visualization/{vis_id}", json=payload)
    if r.status_code == 200:
        logger.info("Visualizacion creada: %s", vis_id)
        return True
    if r.status_code == 409:
        # Update
        r = req(client, "PUT", f"/api/saved_objects/visualization/{vis_id}", json=payload)
        if r.status_code == 200:
            logger.info("Visualizacion actualizada: %s", vis_id)
            return True
    logger.warning("Visualizacion %s: HTTP %d - %s", vis_id, r.status_code, r.text[:200])
    return False


def main() -> int:
    client = httpx.Client(auth=(DASHBOARDS_USER, DASHBOARDS_PASSWORD), verify=False, timeout=30)

    # Viz: Tipos de ataques (alert_signature)
    attack_types_payload = {
        "attributes": {
            "title": "Tipos de Ataques Detectados (Suricata)",
            "description": "Distribucion de firmas de ataques Suricata",
            "visState": json.dumps({
                "type": "pie",
                "params": {
                    "type": "pie",
                    "addTooltip": True,
                    "addLegend": True,
                    "legendPosition": "right",
                    "isDonut": True,
                    "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom"}],
                    "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "left"}],
                    "seriesParams": [{"data": {"label": "Count", "id": "1"}, "type": "pie"}],
                },
                "aggs": [
                    {"id": "1", "type": "count", "schema": "metric"},
                    {"id": "2", "type": "terms", "schema": "segment", "params": {"field": "alert_signature.keyword", "size": 10, "order": "desc", "orderBy": "1"}},
                ],
            }),
            "uiStateJSON": "{}",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
                    "index": "wazuh_ml_demo_",
                })
            }
        }
    }
    create_or_update_viz(client, "attack-types-pie", attack_types_payload)

    # Viz: Timeline de eventos por hora
    timeline_payload = {
        "attributes": {
            "title": "Timeline de Eventos por Hora",
            "description": "Cantidad de predicciones ML por hora",
            "visState": json.dumps({
                "type": "histogram",
                "params": {
                    "type": "histogram",
                    "grid": {"categoryLines": False},
                    "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom", "show": True, "scale": {"type": "linear"}}],
                    "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "left", "show": True, "scale": {"type": "linear", "mode": "normal"}}],
                    "seriesParams": [{"show": True, "type": "histogram", "data": {"label": "Count", "id": "1"}, "valueAxis": "ValueAxis-1"}],
                    "addTooltip": True,
                    "addLegend": True,
                    "categoryAxis": {"id": "CategoryAxis-1"},
                    "valueAxis": "ValueAxis-1",
                },
                "aggs": [
                    {"id": "1", "type": "count", "schema": "metric"},
                    {"id": "2", "type": "date_histogram", "schema": "segment", "params": {"field": "@timestamp", "interval": "1h"}},
                ],
            }),
            "uiStateJSON": "{}",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
                    "index": "wazuh_ml_demo_",
                })
            }
        }
    }
    create_or_update_viz(client, "timeline-events", timeline_payload)

    # Viz: Distribucion por nivel de severidad
    severity_payload = {
        "attributes": {
            "title": "Amenazas Detectadas por Severidad",
            "description": "Distribucion de alertas Suricata por nivel de severidad",
            "visState": json.dumps({
                "type": "histogram",
                "params": {
                    "type": "histogram",
                    "grid": {"categoryLines": False},
                    "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom"}],
                    "valueAxes": [{"id": "ValueAxis-1", "type": "value", "position": "left"}],
                    "seriesParams": [{"type": "histogram", "data": {"label": "Count", "id": "1"}, "valueAxis": "ValueAxis-1"}],
                    "addLegend": True,
                    "addTooltip": True,
                },
                "aggs": [
                    {"id": "1", "type": "count", "schema": "metric"},
                    {"id": "2", "type": "histogram", "schema": "segment", "params": {"field": "alert_severity", "interval": 1}},
                ],
            }),
            "uiStateJSON": "{}",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
                    "index": "wazuh_ml_demo_",
                })
            }
        }
    }
    create_or_update_viz(client, "threats-by-severity", severity_payload)

    # Viz: Mapa de calor src_ip vs prediction
    heatmap_payload = {
        "attributes": {
            "title": "Mapa de Calor: IP Atacante vs Prediccion",
            "description": "Cruce entre IPs atacantes y clases predichas",
            "visState": json.dumps({
                "type": "heatmap",
                "params": {
                    "type": "heatmap",
                    "addTooltip": True,
                    "addLegend": True,
                    "enableHover": True,
                    "legendPosition": "right",
                    "colorsNumber": 4,
                    "colorSchema": "Reds",
                    "invertColors": False,
                },
                "aggs": [
                    {"id": "1", "type": "count", "schema": "metric"},
                    {"id": "2", "type": "terms", "schema": "segment", "params": {"field": "src_ip", "size": 20}},
                    {"id": "3", "type": "terms", "schema": "group", "params": {"field": "prediction", "size": 10}},
                ],
            }),
            "uiStateJSON": "{}",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
                    "index": "wazuh_ml_demo_",
                })
            }
        }
    }
    create_or_update_viz(client, "heatmap-ip-prediction", heatmap_payload)

    # Actualizar el dashboard para incluir las nuevas visualizaciones
    dashboard_payload = {
        "attributes": {
            "title": "SOC Diplomado - Deteccion de Amenazas con ML",
            "description": "Dashboard principal del SOC: visualiza alertas Suricata enriquecidas con predicciones XGBoost",
            "panelsJSON": json.dumps([
                {"version": "8.8.0", "gridData": {"x": 0, "y": 0, "w": 24, "h": 12, "i": "p1"}, "panelIndex": "p1", "embeddableConfig": {}, "panelRefName": "panel_ml_class"},
                {"version": "8.8.0", "gridData": {"x": 24, "y": 0, "w": 24, "h": 12, "i": "p2"}, "panelIndex": "p2", "embeddableConfig": {}, "panelRefName": "panel_top_ip"},
                {"version": "8.8.0", "gridData": {"x": 0, "y": 12, "w": 16, "h": 12, "i": "p3"}, "panelIndex": "p3", "embeddableConfig": {}, "panelRefName": "panel_attacks_pie"},
                {"version": "8.8.0", "gridData": {"x": 16, "y": 12, "w": 16, "h": 12, "i": "p4"}, "panelIndex": "p4", "embeddableConfig": {}, "panelRefName": "panel_severity"},
                {"version": "8.8.0", "gridData": {"x": 32, "y": 12, "w": 16, "h": 12, "i": "p5"}, "panelIndex": "p5", "embeddableConfig": {}, "panelRefName": "panel_confidence"},
                {"version": "8.8.0", "gridData": {"x": 0, "y": 24, "w": 32, "h": 15, "i": "p6"}, "panelIndex": "p6", "embeddableConfig": {}, "panelRefName": "panel_timeline"},
                {"version": "8.8.0", "gridData": {"x": 32, "y": 24, "w": 16, "h": 15, "i": "p7"}, "panelIndex": "p7", "embeddableConfig": {}, "panelRefName": "panel_recent"},
                {"version": "8.8.0", "gridData": {"x": 0, "y": 39, "w": 48, "h": 14, "i": "p8"}, "panelIndex": "p8", "embeddableConfig": {}, "panelRefName": "panel_heatmap"},
            ]),
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
    # Agregar references via panel references (no funciona, asi que las referencias son por nombre)
    # En OpenSearch Dashboards las references se manejan diferente
    r = req(client, "POST", "/api/saved_objects/dashboard/soc-diplomado", json=dashboard_payload)
    if r.status_code == 409:
        r = req(client, "PUT", "/api/saved_objects/dashboard/soc-diplomado", json=dashboard_payload)
    if r.status_code == 200:
        logger.info("Dashboard 'soc-diplomado' actualizado con 8 paneles")
    else:
        logger.warning("Dashboard update: HTTP %d - %s", r.status_code, r.text[:200])

    # Listar todas las visualizaciones
    r = req(client, "GET", "/api/saved_objects/_find?type=visualization&per_page=50")
    if r.status_code == 200:
        vos = r.json()["saved_objects"]
        logger.info("\n=== Visualizaciones creadas ===")
        for vo in vos:
            logger.info("  - %s: %s", vo["id"], vo["attributes"]["title"])

    return 0


if __name__ == "__main__":
    sys.exit(main())