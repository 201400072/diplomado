#!/usr/bin/env bash
# ============================================================
# Suite completa de ataques para validacion end-to-end.
#
# Ejecuta:
#   1. Nmap
#   2. Brute Force
#   3. DoS
#   4. SQLi / XSS / WebShell
# ============================================================

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

LOG_DIR="$PROJECT_ROOT/attacks/logs"
mkdir -p "$LOG_DIR"

SUITE_LOG="$LOG_DIR/suite_$(date +%Y%m%d_%H%M%S).log"

# Compatible con cualquier bash
exec >>"$SUITE_LOG" 2>&1

echo "============================================================"
echo " SUITE DE ATAQUES - SOC DIPLOMADO"
echo " Fecha: $(date '+%Y-%m-%d %H:%M:%S')"
echo "============================================================"

echo
echo "[CHECK] Verificando servicios..."

if ! docker ps --format '{{.Names}}' | grep -q '^suricata$'; then
    echo "ERROR: Suricata no está corriendo."
    exit 1
fi

if ! docker ps --format '{{.Names}}' | grep -q '^victim-dvwa$'; then
    echo "ERROR: DVWA no está corriendo."
    exit 1
fi

echo "[OK] Servicios disponibles"

echo
echo "[CLEAN] Limpiando eve.json..."

docker exec suricata sh -c 'echo "" > /var/log/suricata/eve.json' || true

sleep 2

START_TIME=$(date +%s)

############################################################
# NMAP
############################################################

echo
echo "=========================================="
echo "[1/4] NMAP"
echo "=========================================="

STEP=$(date +%s)

bash attacks/nmap/run.sh

NMAP_TIME=$(( $(date +%s) - STEP ))

############################################################
# BRUTE FORCE
############################################################

echo
echo "=========================================="
echo "[2/4] BRUTE FORCE"
echo "=========================================="

STEP=$(date +%s)

bash attacks/bruteforce/run.sh

BRUTE_TIME=$(( $(date +%s) - STEP ))

############################################################
# DOS
############################################################

echo
echo "=========================================="
echo "[3/4] DOS"
echo "=========================================="

STEP=$(date +%s)

bash attacks/dos/run.sh

DOS_TIME=$(( $(date +%s) - STEP ))

############################################################
# SQLI
############################################################

echo
echo "=========================================="
echo "[4/4] SQLi / XSS / WebShell"
echo "=========================================="

STEP=$(date +%s)

bash attacks/sqli/run.sh

SQLI_TIME=$(( $(date +%s) - STEP ))

############################################################

echo
echo "[WAIT] Esperando 30 segundos..."

sleep 30

############################################################
# SURICATA
############################################################

echo
echo "============================================================"
echo " VALIDACION"
echo "============================================================"

echo
echo "[CAPA 1] SURICATA"

EVE_LINES=$(docker exec suricata wc -l /var/log/suricata/eve.json | awk '{print $1}')

ALERT_COUNT=$(docker exec suricata \
grep -c '"event_type":"alert"' \
/var/log/suricata/eve.json || true)

echo "Eventos:  $EVE_LINES"
echo "Alertas:  $ALERT_COUNT"

############################################################
# WAZUH
############################################################

echo
echo "[CAPA 2] WAZUH"

docker exec wazuh.manager \
curl -k -u admin:SecretPassword \
-X POST \
"https://wazuh.indexer:9200/wazuh-alerts-demo/_refresh" \
>/dev/null 2>&1 || true

WAZUH_COUNT=$(docker exec wazuh.manager \
curl -s -k -u admin:SecretPassword \
"https://wazuh.indexer:9200/wazuh-alerts-demo/_count" \
| python3 -c 'import json,sys;print(json.load(sys.stdin)["count"])' \
2>/dev/null || echo 0)

echo "Alertas indexadas: $WAZUH_COUNT"

############################################################
# ML
############################################################

echo
echo "[CAPA 3] ML"

if [ -d api ]; then
    (
        cd api
        source .venv-api/bin/activate
        python -m app.infrastructure.wazuh.demo_e2e
    ) || true
fi

ML_COUNT=$(curl -s -k \
-u admin:SecretPassword \
https://localhost:9200/wazuh-ml-demo-*/_count \
| python3 -c 'import json,sys;print(json.load(sys.stdin)["count"])' \
2>/dev/null || echo 0)

echo "Predicciones ML: $ML_COUNT"

############################################################
# DASHBOARD
############################################################

echo
echo "[CAPA 4] DASHBOARD"

echo "https://localhost:443/app/dashboards#/view/soc-diplomado"

############################################################

TOTAL=$(( $(date +%s) - START_TIME ))

echo
echo "============================================================"
echo "RESUMEN"
echo "============================================================"

printf "%-25s %s\n" "Tiempo total:" "${TOTAL}s"
printf "%-25s %s\n" "Nmap:" "${NMAP_TIME}s"
printf "%-25s %s\n" "Brute Force:" "${BRUTE_TIME}s"
printf "%-25s %s\n" "DoS:" "${DOS_TIME}s"
printf "%-25s %s\n" "SQLi/XSS:" "${SQLI_TIME}s"

echo

printf "%-25s %s\n" "Alertas Suricata:" "$ALERT_COUNT"
printf "%-25s %s\n" "Alertas Wazuh:" "$WAZUH_COUNT"
printf "%-25s %s\n" "Predicciones ML:" "$ML_COUNT"

echo
echo "Dashboard:"
echo "https://localhost:443/app/dashboards#/view/soc-diplomado"

echo
echo "Log:"
echo "$SUITE_LOG"