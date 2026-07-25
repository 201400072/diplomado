#!/usr/bin/env bash
# ============================================================
# Configura los dashboards del SOC Diplomado en Wazuh Dashboard.
#
# Crea:
#   - 2 index patterns
#   - 8 visualizaciones
#   - 1 dashboard con 8 paneles
#   - Exporta todo como NDJSON en dashboards/export_dashboard.ndjson
#
# Pre-requisitos:
#   - Wazuh Dashboard corriendo en https://localhost:443
#   - API ML corriendo en http://localhost:8000
#   - Wazuh Indexer con indice wazuh-ml-demo-* con datos
#
# Uso:
#   bash scripts/07_setup_dashboards.sh
# ============================================================
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

echo "============================================================"
echo " SETUP DE DASHBOARDS - SOC DIPLOMADO"
echo "============================================================"

# Verificar servicios
echo ""
echo "[CHECK] Verificando servicios..."
curl -s -k -o /dev/null -m 5 -w "API ML:        HTTP %{http_code}\n" \
    http://localhost:8000/api/v1/health || echo "API ML no responde"

curl -sSLk -u admin:SecretPassword -m 5 -o /dev/null \
    -w "Wazuh Indexer: HTTP %{http_code}\n" \
    https://localhost:9200/_cluster/health || echo "Wazuh Indexer no responde"

curl -sSLk -u admin:SecretPassword -m 5 -o /dev/null \
    -w "Wazuh Dashboard: HTTP %{http_code}\n" \
    https://localhost:443/api/status || echo "Wazuh Dashboard no responde"

# Verificar venv-api
if [ ! -d "api/.venv-api" ]; then
    echo "ERROR: api/.venv-api no existe. Ejecuta FASE 2 primero."
    exit 1
fi

echo ""
echo "[1/3] Configurando dashboards..."
cd api
source .venv-api/bin/activate
python -m app.infrastructure.wazuh.setup_dashboards 2>&1 | grep -E "creado|ya existe|OK|ERROR" | head -n 10
cd ..

echo ""
echo "[2/3] Agregando visualizaciones adicionales..."
cd api
source .venv-api/bin/activate
python -m app.infrastructure.wazuh.add_visualizations 2>&1 | grep -E "creado|actualizado|ERROR" | head -n 15
cd ..

echo ""
echo "[3/3] Generando datos de prueba (opcional)..."
read -p "    Deseas generar 50 alertas sinteticas? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    cd api
    source .venv-api/bin/activate
    python -m app.infrastructure.wazuh.generate_dashboard_data 2>&1 | grep -E "Inyectadas|Procesadas|Total" | head -n 5
    cd ..
fi

echo ""
echo "============================================================"
echo " DASHBOARDS CONFIGURADOS"
echo "============================================================"
echo ""
echo "Acceso al dashboard:"
echo "  https://localhost:443/app/dashboards#/view/soc-diplomado"
echo ""
echo "Visualizaciones individuales:"
echo "  https://localhost:443/app/visualize"
echo ""
echo "Indice ML con datos:"
echo "  https://localhost:443/app/dev_tools#/console"
echo "  GET wazuh-ml-demo-*/_count"
echo ""
echo "Export NDJSON: dashboards/export_dashboard.ndjson"
echo ""
echo "Para importar en otro Wazuh Dashboard:"
echo "  1. Settings -> Saved Objects -> Import"
echo "  2. Seleccionar dashboards/export_dashboard.ndjson"
echo "  3. Confirmar importacion (auto-resuelve dependencies)"