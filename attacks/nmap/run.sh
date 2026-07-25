#!/usr/bin/env bash
# ============================================================
# Ataque 1: Escaneo Nmap contra DVWA
#
# Detecta: Suricata rule 1000030 (User-Agent Nmap)
# Resultado esperado: Alerta "POSIBLE Nmap scan"
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

VICTIM_IP="10.10.10.40"
SOURCE_CONTAINER="attacker"

echo "============================================================"
echo " ATAQUE 1: Nmap SYN Scan"
echo "============================================================"
echo "Objetivo: $VICTIM_IP (DVWA)"
echo "Origen:   contenedor $SOURCE_CONTAINER"
echo ""

# Escaneo SYN contra puertos comunes (no requiere root en Nmap moderno)
docker exec "$SOURCE_CONTAINER" nmap -sS -p 22,80,443,3306,8080 \
    --max-retries 1 --max-rtt-timeout 500ms \
    -T4 "$VICTIM_IP" 2>&1 | tail -n 20 || true

# Escaneo con User-Agent Nmap (dispara regla 1000030)
echo ""
echo "[+] Escaneo con User-Agent Nmap..."
docker exec "$SOURCE_CONTAINER" nmap -sV --script=http-enum \
    -p 80 --script-args http.useragent="Nmap Scripting Engine" \
    "$VICTIM_IP" 2>&1 | tail -n 15 || true

echo ""
echo "[OK] Ataque Nmap completado"
echo "Verificando alertas en eve.json..."
sleep 5

# Verificar localmente
if docker exec suricata grep -q '"signature_id":1000030' /var/log/suricata/eve.json 2>/dev/null; then
    echo "[OK] Alerta Suricata 1000030 (Nmap) DETECTADA"
else
    echo "[--] Aun no se detecta la alerta (esperar unos segundos)"
fi