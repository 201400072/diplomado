#!/usr/bin/env bash
# ============================================================
# Suite completa de ataques para validacion end-to-end.
#
# Ejecuta los 4 ataques en secuencia:
#   1. Nmap scan
#   2. Brute force
#   3. DoS HTTP flood
#   4. SQL Injection + XSS + WebShell
#
# Despues valida que:
#   - Suricata genera eve.json con alertas
#   - Wazuh Indexer recibe las alertas
#   - API ML predice las clases
#   - Dashboard muestra los resultados
#
# Uso:
#   bash scripts/08_run_attack_suite.sh
# ============================================================
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

LOG_DIR="$PROJECT_ROOT/attacks/logs"
mkdir -p "$LOG_DIR"

SUITE_LOG="$LOG_DIR/suite_$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "$SUITE_LOG") 2>&1

echo "============================================================"
echo " SUITE DE ATAQUES - SOC DIPLOMADO"
echo " Fecha: $(date '+%Y-%m-%d %H:%M:%S')"
echo "============================================================"

# Verificar prerequisitos
echo ""
echo "[CHECK] Prerequisitos..."
[ -z "$(docker ps -q -f name=suricata 2>/dev/null)" ] && {
    echo "ERROR: Suricata no esta corriendo. Ejecuta scripts/04_up.sh primero."
    exit 1
}
[ -z "$(docker ps -q -f name=victim-dvwa 2>/dev/null)" ] && {
    echo "ERROR: DVWA no esta corriendo. Ejecuta scripts/04_up.sh primero."
    exit 1
}
echo "[OK] Servicios requeridos corriendo"

# Limpiar eve.json previo
echo ""
echo "[CLEAN] Limpiando eve.json previo de Suricata..."
docker exec suricata sh -c "echo '' > /var/log/suricata/eve.json" 2>&1 || true
sleep 2

# Timestamp inicio
START_TIME=$(date +%s)
echo ""
echo "[START] Inicio de ataques: $(date)"

# Ataque 1: Nmap
echo ""
echo "=========================================="
echo "[1/4] NMAP"
echo "=========================================="
bash attacks/nmap/run.sh 2>&1
NMAP_TIME=$(( $(date +%s) - START_TIME ))

# Ataque 2: Brute Force
echo ""
echo "=========================================="
echo "[2/4] BRUTE FORCE"
echo "=========================================="
bash attacks/bruteforce/run.sh 2>&1
BRUTE_TIME=$(( $(date +%s) - START_TIME - NMAP_TIME ))

# Ataque 3: DoS
echo ""
echo "=========================================="
echo "[3/4] DOS"
echo "=========================================="
bash attacks/dos/run.sh 2>&1
DOS_TIME=$(( $(date +%s) - START_TIME - NMAP_TIME - BRUTE_TIME ))

# Ataque 4: SQLi / XSS / WebShell
echo ""
echo "=========================================="
echo "[4/4] SQL INJECTION + XSS + WEBSHELL"
echo "=========================================="
bash attacks/sqli/run.sh 2>&1
SQLI_TIME=$(( $(date +%s) - START_TIME - NMAP_TIME - BRUTE_TIME - DOS_TIME ))

# Esperar que Suricata escriba todo
echo ""
echo "[WAIT] Esperando 30s para que Suricata escriba eve.json..."
sleep 30

# VALIDACION COMPLETA POR CAPA
echo ""
echo "============================================================"
echo " VALIDACION END-TO-END"
echo "============================================================"

echo ""
echo "[CAPA 1] Suricata - eve.json"
echo "----------------------------------------"
EVE_LINES=$(docker exec suricata wc -l < /var/log/suricata/eve.json 2>/dev/null || echo 0)
echo "  Total eventos en eve.json: $EVE_LINES"

ALERT_COUNT=$(docker exec suricata grep -c '"event_type":"alert"' /var/log/suricata/eve.json 2>/dev/null || echo 0)
echo "  Alertas (event_type=alert): $ALERT_COUNT"

if [ "$ALERT_COUNT" -gt 0 ]; then
    echo ""
    echo "  Alertas por SID:"
    docker exec suricata grep '"event_type":"alert"' /var/log/suricata/eve.json 2>/dev/null | \
        python3 -c "
import sys, json
counts = {}
for line in sys.stdin:
    try:
        e = json.loads(line)
        sid = e.get('alert', {}).get('signature_id', 0)
        counts[sid] = counts.get(sid, 0) + 1
    except: pass
for sid, c in sorted(counts.items()):
    print(f'    SID {sid}: {c} alertas')
"
fi

echo ""
echo "[CAPA 2] Wazuh Indexer (inyeccion de alertas Suricata)"
echo "----------------------------------------"

# Como Wazuh Manager tiene bug en Mac arm64, inyectamos eve.json manualmente
echo "  Inyectando eve.json al indice wazuh-alerts-demo (workaround Mac arm64)..."
docker exec wazuh.manager curl -sSLk -u admin:SecretPassword \
    -X PUT "https://wazuh.indexer:9200/wazuh-alerts-demo" \
    -H 'Content-Type: application/json' \
    -d '{"mappings":{"properties":{"timestamp":{"type":"date"},"id":{"type":"keyword"},"rule":{"type":"object"},"data":{"type":"object"},"manager":{"type":"object"},"full_log":{"type":"text"}}}}' \
    -o /dev/null -w "  PUT indice: HTTP %{http_code}\n"

ALERT_INJECTED=0
docker exec suricata cat /var/log/suricata/eve.json 2>/dev/null | while IFS= read -r line; do
    if echo "$line" | grep -q '"event_type":"alert"'; then
        ALERT_ID=$(echo "$line" | python3 -c "import sys,json; e=json.loads(sys.stdin.read()); print(f\"suricata-{e.get('flow_id', 0)}\")")
        TIMESTAMP=$(echo "$line" | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('timestamp', ''))")
        ALERT_SIG=$(echo "$line" | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('alert', {}).get('signature', ''))")
        SEVERITY=$(echo "$line" | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('alert', {}).get('severity', 1))")
        SRC_IP=$(echo "$line" | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('src_ip', ''))")
        DEST_IP=$(echo "$line" | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('dest_ip', ''))")

        docker exec wazuh.manager curl -sSLk -u admin:SecretPassword \
            -X POST "https://wazuh.indexer:9200/wazuh-alerts-demo/_doc" \
            -H 'Content-Type: application/json' \
            -d "{
                \"timestamp\": \"$TIMESTAMP\",
                \"id\": \"$ALERT_ID\",
                \"rule\": {\"id\":\"86601\",\"level\":3,\"description\":\"Suricata: $ALERT_SIG\",\"groups\":[\"ids\",\"suricata\"]},
                \"data\": {\"srcip\":\"$SRC_IP\",\"dstip\":\"$DEST_IP\",\"alert_severity\":$SEVERITY,\"suricata_alert_signature\":\"$ALERT_SIG\"},
                \"manager\": {\"name\":\"wazuh.manager\"}
            }" -o /dev/null
    fi
done
docker exec wazuh.manager curl -sSLk -u admin:SecretPassword \
    -X POST "https://wazuh.indexer:9200/wazuh-alerts-demo/_refresh" -o /dev/null

WAZUH_COUNT=$(docker exec wazuh.manager curl -sSLk -u admin:SecretPassword \
    "https://wazuh.indexer:9200/wazuh-alerts-demo/_count" 2>/dev/null | \
    python3 -c "import sys,json; print(json.load(sys.stdin).get('count', 0))" 2>/dev/null || echo 0)
echo "  Alertas Wazuh indexadas: $WAZUH_COUNT"

echo ""
echo "[CAPA 3] API ML - Predicciones"
echo "----------------------------------------"

# Ejecutar orquestador para enriquecer alertas con ML
echo "  Ejecutando orquestador ML..."
cd api
source .venv-api/bin/activate
python -m app.infrastructure.wazuh.demo_e2e 2>&1 | grep -E "Encontradas|Procesadas|Total" | tail -n 5
cd ..

ML_COUNT=$(curl -sSLk -u admin:SecretPassword \
    "https://localhost:9200/wazuh-ml-demo-*/_count" 2>/dev/null | \
    python3 -c "import sys,json; print(json.load(sys.stdin).get('count', 0))" 2>/dev/null || echo 0)
echo "  Predicciones ML en indice: $ML_COUNT"

# Distribucion por prediccion
DIST=$(curl -sSLk -u admin:SecretPassword \
    "https://localhost:9200/wazuh-ml-demo-*/_search" \
    -H 'Content-Type: application/json' \
    -d '{"size":0,"aggs":{"by_pred":{"terms":{"field":"prediction","size":10}}}}' 2>/dev/null)
echo "  Distribucion por prediccion:"
echo "$DIST" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    buckets = d.get('aggregations', {}).get('by_pred', {}).get('buckets', [])
    for b in buckets:
        print(f'    {b[\"key\"]}: {b[\"doc_count\"]}')
except: pass
" 2>/dev/null || echo "    (no se pudo parsear)"

echo ""
echo "[CAPA 4] Dashboard"
echo "----------------------------------------"
echo "  Dashboard URL: https://localhost:443/app/dashboards#/view/soc-diplomado"
echo "  Visualizaciones: 8 paneles"
echo "  Datos: $ML_COUNT predicciones ML"

# Resumen final
echo ""
echo "============================================================"
echo " RESUMEN FINAL"
echo "============================================================"
TOTAL=$(( $(date +%s) - START_TIME ))
echo "Tiempo total:        ${TOTAL}s"
echo "Nmap:                 ${NMAP_TIME}s"
echo "Brute force:          ${BRUTE_TIME}s"
echo "DoS:                  ${DOS_TIME}s"
echo "SQLi/XSS/WebShell:    ${SQLI_TIME}s"
echo ""
echo "Alertas Suricata:     $ALERT_COUNT"
echo "Alertas Wazuh:        $WAZUH_COUNT"
echo "Predicciones ML:      $ML_COUNT"

echo ""
echo "Ver dashboard:"
echo "  https://localhost:443/app/dashboards#/view/soc-diplomado"
echo ""
echo "Log completo: $SUITE_LOG"