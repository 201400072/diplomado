#!/usr/bin/env bash
# ============================================================
# Levanta el laboratorio SOC completo.
# Paso 1: regenera certificados Wazuh (solo si no existen).
# Paso 2: levanta los servicios Wazuh (indexer, manager, dashboard).
# Paso 3: levanta Suricata y DVWA.
# ============================================================
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DOCKER_DIR="$PROJECT_ROOT/docker"
CERT_DIR="$DOCKER_DIR/wazuh_indexer_ssl_certs"

cd "$DOCKER_DIR"

echo "============================================================"
echo " 1/4 Verificando certificados Wazuh"
echo "============================================================"
if [ ! -f "$CERT_DIR/root-ca.pem" ]; then
  echo "Certificados no encontrados. Regenerando..."
  mkdir -p "$CERT_DIR"
  docker run --rm \
    -v "$CERT_DIR:/certificates" \
    -v "$DOCKER_DIR/certs.yml:/config/certs.yml" \
    wazuh/wazuh-certs-generator:0.0.2 2>&1 | tail -n 10
else
  echo "Certificados existentes en $CERT_DIR"
fi

echo ""
echo "============================================================"
echo " 2/4 Levantando Wazuh (indexer, manager, dashboard)"
echo "============================================================"
docker compose up -d wazuh.indexer wazuh.manager wazuh.dashboard

echo ""
echo "============================================================"
echo " 3/4 Esperando indexer healthy..."
echo "============================================================"
for i in $(seq 1 30); do
  STATUS=$(docker inspect --format='{{.State.Health.Status}}' wazuh.indexer 2>/dev/null || echo "starting")
  echo "  [$i/30] indexer=$STATUS"
  [ "$STATUS" = "healthy" ] && break
  sleep 5
done

echo ""
echo "============================================================"
echo " 4/4 Levantando Suricata y DVWA"
echo "============================================================"
docker compose up -d suricata victim.dvwa

echo ""
echo "============================================================"
echo " ESTADO FINAL"
echo "============================================================"
docker compose ps

echo ""
echo "Accesos:"
echo "  - Wazuh Dashboard:    https://localhost:443  (admin / SecretPassword)"
echo "  - Wazuh API:          https://localhost:55000 (wazuh-wui / MyS3cr37P450r.*-)"
echo "  - Wazuh Indexer:      https://localhost:9200 (admin / SecretPassword)"
echo "  - DVWA (victima):     http://localhost:80    (admin / password)"
echo ""
echo "Espera 2 minutos adicionales para que manager termine de arrancar."