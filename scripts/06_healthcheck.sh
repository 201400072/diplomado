#!/usr/bin/env bash
# ============================================================
# Verifica el estado del laboratorio y los endpoints clave.
# ============================================================
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DOCKER_DIR="$PROJECT_ROOT/docker"

cd "$DOCKER_DIR"

echo "============================================================"
echo " HEALTH CHECK - Laboratorio SOC"
echo "============================================================"
echo ""

echo "--- Contenedores corriendo ---"
docker compose ps --format "table {{.Service}}\t{{.Status}}\t{{.Ports}}" 2>&1 || echo "no compose activo"
echo ""

echo "--- Wazuh Indexer (OpenSearch) ---"
HEALTH=$(curl -sSLk -u admin:SecretPassword 'https://localhost:9200/_cluster/health' 2>&1)
if echo "$HEALTH" | grep -q "cluster_name"; then
  STATUS=$(echo "$HEALTH" | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'  cluster: {d[\"cluster_name\"]} status={d[\"status\"]} nodes={d[\"number_of_nodes\"]}')" 2>/dev/null || echo "$HEALTH" | head -n 2)
  echo "  OK - $STATUS"
else
  echo "  FAIL - indexer no responde"
fi
echo ""

echo "--- Wazuh Manager API ---"
TOKEN=$(curl -s -k -u 'wazuh-wui:MyS3cr37P450r.*-' -X POST 'https://localhost:55000/security/user/authenticate?raw=true' 2>&1)
if [ ${#TOKEN} -gt 100 ]; then
  echo "  OK - token JWT valido (${#TOKEN} chars)"
  PROC=$(curl -s -k -H "Authorization: Bearer $TOKEN" 'https://localhost:55000/manager/status' 2>&1 | python3 -c "
import sys, json
d = json.load(sys.stdin)
procs = d['data']['affected_items'][0]
running = sum(1 for v in procs.values() if v == 'running')
stopped = sum(1 for v in procs.values() if v == 'stopped')
print(f'  Manager processes: {running} running, {stopped} stopped')
" 2>/dev/null || echo "  (no se pudo parsear)")
  echo "$PROC"
else
  echo "  FAIL - manager API no responde"
fi
echo ""

echo "--- Wazuh Dashboard ---"
HTTP=$(curl -s -k -o /dev/null -w "%{http_code}" 'https://localhost:443/' 2>&1)
if [ "$HTTP" = "200" ] || [ "$HTTP" = "302" ]; then
  echo "  OK - HTTP $HTTP"
else
  echo "  WARN - HTTP $HTTP"
fi
echo ""

echo "--- DVWA (victima) ---"
HTTP=$(curl -s -o /dev/null -w "%{http_code}" 'http://localhost:80/login.php' 2>&1 || echo "000")
if [ "$HTTP" = "200" ]; then
  echo "  OK - HTTP $HTTP (DVWA accesible)"
else
  echo "  INFO - HTTP $HTTP (aun arrancando)"
fi
echo ""

echo "--- Suricata logs ---"
if docker exec suricata test -f /var/log/suricata/eve.json 2>/dev/null; then
  LINES=$(docker exec suricata wc -l /var/log/suricata/eve.json 2>/dev/null | awk '{print $1}')
  echo "  OK - eve.json existe ($LINES lineas)"
else
  echo "  INFO - eve.json no existe aun (Suricata arrancando)"
fi
echo ""

echo "============================================================"
echo " URLs del laboratorio"
echo "============================================================"
echo "  - Wazuh Dashboard:    https://localhost:443"
echo "  - Wazuh API:          https://localhost:55000"
echo "  - Wazuh Indexer:      https://localhost:9200"
echo "  - DVWA:               http://localhost:80"