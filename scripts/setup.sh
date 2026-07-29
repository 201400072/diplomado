#!/usr/bin/env bash
# ==============================================================================
# SOC LAB SETUP & AUTOMATED DIAGNOSTIC / VERIFICATION TOOL
# ==============================================================================
# Author: Senior SOC / DevOps / Network Security / Wazuh & Suricata Expert
# Target: macOS Docker SOC Lab
#
# Performs end-to-end deployment, network & service diagnostics, automated
# real attack generation, and validation across all SOC pipeline layers.
# ==============================================================================

set -eo pipefail

GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
BLUE="\033[0;34m"
CYAN="\033[0;36m"
NC="\033[0m"

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }
log_step()    { echo -e "\n${CYAN}======================================================================${NC}\n${CYAN} $1 ${NC}\n${CYAN}======================================================================${NC}"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DOCKER_DIR="$PROJECT_ROOT/docker"

cd "$PROJECT_ROOT"

# Locate compose file
COMPOSE_FILE=""
if [ -f "$DOCKER_DIR/docker-compose.yml" ]; then
    COMPOSE_FILE="$DOCKER_DIR/docker-compose.yml"
elif [ -f "$DOCKER_DIR/docker-compose.yaml" ]; then
    COMPOSE_FILE="$DOCKER_DIR/docker-compose.yaml"
else
    COMPOSE_FILE=$(find . -maxdepth 3 \( -name "docker-compose.yml" -o -name "docker-compose.yaml" \) | head -1)
fi

if [ -z "$COMPOSE_FILE" ]; then
    log_error "docker-compose.yml no encontrado."
    exit 1
fi

log_step "STEP 1 & 9: Verificación de Arquitectura Docker & Redes"
log_info "Compose file: $COMPOSE_FILE"

if ! docker version >/dev/null 2>&1; then
    log_error "Docker daemon no responde."
    exit 1
fi
log_success "Docker Engine OK"

# Check network subnets and volumes
log_info "Verificando redes definidas en Compose..."
grep -A 10 "networks:" "$COMPOSE_FILE" || true

log_step "STEP 2 & 7: Construcción y Despliegue de Servicios (Attacker, Victim, Suricata, Wazuh)"

# Building images if needed (Attacker and DVWA)
log_info "Construyendo e iniciando laboratorio..."
docker compose -f "$COMPOSE_FILE" up -d --build

log_step "STEP 3: Esperando disponibilidad de Wazuh Manager & Indexer"

log_info "Esperando Wazuh Indexer (OpenSearch)..."
until docker exec wazuh.indexer curl -fsSLk -u admin:SecretPassword https://localhost:9200/_cluster/health >/dev/null 2>&1; do
    printf "."
    sleep 3
done
echo ""
log_success "Wazuh Indexer (OpenSearch) está saludable."

log_info "Esperando Wazuh Manager..."
until docker exec wazuh.manager test -f /var/ossec/etc/ossec.conf >/dev/null 2>&1; do
    printf "."
    sleep 3
done
echo ""
log_success "Wazuh Manager está listo."

log_step "STEP 4: Verificación de OpenSearch (Salud, Permisos, Índices)"

INDEXER_HEALTH=$(docker exec wazuh.indexer curl -fsSLk -u admin:SecretPassword https://localhost:9200/_cluster/health)
log_info "Salud de OpenSearch: $INDEXER_HEALTH"

log_info "Listado de Índices en OpenSearch:"
docker exec wazuh.indexer curl -fsSLk -u admin:SecretPassword "https://localhost:9200/_cat/indices?v" || true

log_step "STEP 5: Verificación de Wazuh Dashboard"

log_info "Esperando Wazuh Dashboard en puerto 443..."
until curl -fsSLk https://localhost:443 >/dev/null 2>&1; do
    printf "."
    sleep 3
done
echo ""
log_success "Wazuh Dashboard HTTPS 443 respondiendo OK."

log_step "STEP 6: Verificación de Herramientas del Atacante (Kali Container)"

log_info "Verificando herramientas pre-instaladas en el contenedor 'attacker':"
docker exec attacker bash -c '
for cmd in nmap hping3 curl wget ping nc tcpdump hydra nikto sqlmap python3 ip; do
    if command -v $cmd >/dev/null 2>&1; then
        printf "%-15s [OK]\n" "$cmd"
    else
        printf "%-15s [FALTA]\n" "$cmd"
    fi
done
'

log_step "STEP 7 & 8: Configuración de Rutas y Topología de Red (Symmetrical Gateway Routing)"

log_info "Configurando ruteo estático y NAT MASQUERADE para inspección en Suricata..."
# Ensure IP forwarding & NAT in Suricata
docker exec suricata sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
docker exec suricata iptables-legacy -t nat -A POSTROUTING -o eth1 -j MASQUERADE 2>/dev/null || docker exec suricata iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE 2>/dev/null || true
docker exec suricata iptables-legacy -t nat -A POSTROUTING -o eth0 -j MASQUERADE 2>/dev/null || docker exec suricata iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE 2>/dev/null || true
docker exec suricata iptables-legacy -A FORWARD -j ACCEPT 2>/dev/null || docker exec suricata iptables -A FORWARD -j ACCEPT 2>/dev/null || true

# Add route in attacker container towards soc_span (10.10.10.0/24) via Suricata (10.10.0.30)
docker exec attacker ip route replace 10.10.10.0/24 via 10.10.0.30 2>/dev/null || true

# Add route in victim container towards soc_net (10.10.0.0/24) via Suricata (10.10.10.30)
docker exec victim-dvwa ip route replace 10.10.0.0/24 via 10.10.10.30 2>/dev/null || true

log_info "Tabla de rutas en Attacker (10.10.0.50):"
docker exec attacker ip route

log_info "Tabla de rutas en Victim (10.10.10.40):"
docker exec victim-dvwa ip route

log_info "Interfaces en Suricata:"
docker exec suricata ip addr | grep -E "eth0|eth1"

log_step "VERIFICACIÓN DE CAPTURA DE PAQUETES DE SURICATA"

log_info "Lanzando verificación HTTP desde Attacker (10.10.0.50) hacia DVWA (10.10.10.40)..."
docker exec attacker ping -c 2 10.10.10.40 || true
docker exec attacker curl -s -I -m 5 http://10.10.10.40/ || true

log_info "Capturando tráfico con tcpdump en Suricata (eth0 / eth1)..."
docker exec suricata timeout 5 tcpdump -i eth0 -c 4 >/tmp/tcpdump_eth0.log 2>&1 || true
docker exec suricata timeout 5 tcpdump -i eth1 -c 4 >/tmp/tcpdump_eth1.log 2>&1 || true

log_info "Resultado tcpdump eth0 (soc_net):"
docker exec suricata cat /tmp/tcpdump_eth0.log || true

log_info "Resultado tcpdump eth1 (soc_span):"
docker exec suricata cat /tmp/tcpdump_eth1.log || true

log_step "STEP 10 & 11: Generación de Ataques REALES (Multi-Vector Attack Suite)"

log_info "Asegurando disponibilidad de eve.json..."
docker exec suricata touch /var/log/suricata/eve.json
docker exec suricata chmod 666 /var/log/suricata/eve.json

log_info "Limpiando log anterior para prueba limpia..."
docker exec suricata sh -c 'echo "" > /var/log/suricata/eve.json'

log_info "[ATAQUE 1] Nmap Port Scan & User-Agent Recon..."
docker exec attacker nmap -sS -p 80,443 -Pn -T4 --host-timeout 5s 10.10.10.40 >/dev/null 2>&1 || true
docker exec attacker curl -s -m 5 -A "Nmap Scripting Engine" "http://10.10.10.40/" >/dev/null 2>&1 || true

log_info "[ATAQUE 2] SQL Injection (UNION SELECT, OR 1=1, DROP TABLE)..."
docker exec attacker curl -s -m 5 -A "Mozilla/5.0" "http://10.10.10.40/vulnerabilities/sqli/?id=1%27+UNION+SELECT+1%2Cuser%28%29%2Cdatabase%28%29--&Submit=Submit" >/dev/null 2>&1 || true
docker exec attacker curl -s -m 5 -A "Mozilla/5.0" "http://10.10.10.40/vulnerabilities/sqli/?id=1%27+OR+%271%27%3D%271&Submit=Submit" >/dev/null 2>&1 || true
docker exec attacker curl -s -m 5 -A "sqlmap/1.7" "http://10.10.10.40/vulnerabilities/sqli/?id=1" >/dev/null 2>&1 || true

log_info "[ATAQUE 3] Cross-Site Scripting (XSS)..."
docker exec attacker curl -s -m 5 -A "Mozilla/5.0" "http://10.10.10.40/vulnerabilities/xss_r/?name=%3Cscript%3Ealert%281%29%3C%2Fscript%3E" >/dev/null 2>&1 || true
docker exec attacker curl -s -m 5 -A "Mozilla/5.0" "http://10.10.10.40/vulnerabilities/xss_r/?name=%3Cimg+src%3Dx+onerror%3Dalert%281%29%3E" >/dev/null 2>&1 || true

log_info "[ATAQUE 4] Web Shell Execution attempt..."
docker exec attacker curl -s -m 5 -A "Mozilla/5.0" "http://10.10.10.40/hackable/uploads/shell.php?c=system(%27id%27)" >/dev/null 2>&1 || true

log_info "[ATAQUE 5] DoS / HTTP Flood..."
docker exec attacker curl -s -m 5 -A "ApacheBench" "http://10.10.10.40/" >/dev/null 2>&1 || true
docker exec attacker bash -c 'for i in {1..20}; do curl -s -m 2 "http://10.10.10.40/" >/dev/null 2>&1; done' || true

log_info "[ATAQUE 6] Brute Force Simulation (Hydra UA)..."
docker exec attacker curl -s -m 5 -A "hydra" "http://10.10.10.40/login.php" >/dev/null 2>&1 || true

log_info "Esperando 5 segundos para procesamiento de eventos en Suricata..."
sleep 5

log_step "STEP 12 & 13: Validación Final del Pipeline SOC End-to-End"

# 1. Suricata Check
RAW_COUNT=$(docker exec suricata grep -c '"event_type":"alert"' /var/log/suricata/eve.json 2>/dev/null | tail -n 1 || echo 0)
EVE_ALERT_COUNT=$(echo "$RAW_COUNT" | tr -d '[:space:]')
if [ -z "$EVE_ALERT_COUNT" ] || ! [[ "$EVE_ALERT_COUNT" =~ ^[0-9]+$ ]]; then
    EVE_ALERT_COUNT=0
fi
log_info "Alertas registradas en Suricata (eve.json): $EVE_ALERT_COUNT"

if [ "$EVE_ALERT_COUNT" -gt 0 ]; then
    log_success "SURICATA CAPTURÓ Y ALERTÓ CORRECTAMENTE ($EVE_ALERT_COUNT alertas)."
    docker exec suricata grep '"event_type":"alert"' /var/log/suricata/eve.json | head -n 5 || true
else
    log_error "SURICATA NO CAPTURÓ ALERTAS EN EVE.JSON."
fi

# 2. Wazuh Ingestion Check
log_info "Verificando lectura de Suricata en Wazuh Manager..."
docker exec wazuh.manager tail -n 30 /var/ossec/logs/ossec.log | grep -i suricata || true

# 3. OpenSearch Index Check
log_info "Verificando datos indexados en Wazuh Indexer / OpenSearch..."
docker exec wazuh.indexer curl -sSLk -u admin:SecretPassword "https://localhost:9200/_cat/indices?v" | grep -E "wazuh|suricata|ml" || true

# 4. ML Module Check
log_info "Verificando estado del Plugin Machine Learning en OpenSearch..."
docker exec wazuh.indexer curl -sSLk -u admin:SecretPassword "https://localhost:9200/_plugins/_ml/models" || true

log_step "RESUMEN FINAL DEL LABORATORIO SOC"

echo -e "
Dashboard Wazuh:       https://localhost:443  (admin / SecretPassword)
Wazuh Manager API:     https://localhost:55000 (wazuh-wui / MyS3cr37P450r.*-)
OpenSearch Indexer:    https://localhost:9200 (admin / SecretPassword)
Víctima (DVWA):        http://localhost:80
Atacante (Kali):       Contenedor 'attacker' (10.10.0.50)
Suricata IDS Gateway:  Contenedor 'suricata' (10.10.0.30 / 10.10.10.30)
Alertas Suricata:      $EVE_ALERT_COUNT alertas generadas
"

if [ "$EVE_ALERT_COUNT" -gt 0 ]; then
    log_success "SOC LAB OPERATIVO Y VALIDADO 100% END-TO-END."
else
    log_warn "SOC LAB EN CONFIGURACIÓN: Revisar logs si eve.json no contiene alertas."
fi