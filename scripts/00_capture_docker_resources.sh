#!/usr/bin/env bash
# ============================================================
# Captura el estado actual de recursos de Docker Desktop.
# Sirve como snapshot para revertir si es necesario.
# ============================================================
set -euo pipefail

SNAPSHOT_FILE="docker/.docker-resources-snapshot.txt"
TIMESTAMP="$(date '+%Y-%m-%d %H:%M:%S')"

mkdir -p docker

{
  echo "============================================================"
  echo " DOCKER DESKTOP RESOURCE SNAPSHOT"
  echo " Fecha: $TIMESTAMP"
  echo "============================================================"
  echo ""
  echo "--- Recursos asignados al engine ---"
  docker system info 2>&1 | grep -iE "cpus|total memory|architecture|kernel|operating system|server version" | head -n 20
  echo ""
  echo "--- Uso de disco por Docker ---"
  docker system df
  echo ""
  echo "--- Contenedores activos (si los hay) ---"
  docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}" 2>&1 || echo "ninguno"
  echo ""
  echo "--- Limites por contenedor (placeholder para revertir) ---"
  echo "Si modificaste docker-compose.yml, los limites por servicio son:"
  echo "  wazuh.indexer:    mem_limit=1.5g  cpus=2.0"
  echo "  wazuh.manager:    mem_limit=1g    cpus=1.5"
  echo "  wazuh.dashboard:  mem_limit=1g    cpus=1.0"
  echo "  wazuh.dvwa_agent: mem_limit=512m  cpus=0.5"
  echo "  suricata:         mem_limit=512m  cpus=0.5"
  echo "  victim.dvwa:      mem_limit=512m  cpus=0.5"
  echo ""
  echo "Para revertir los limites en docker-compose.yml:"
  echo "  1. Abrir docker/docker-compose.yml"
  echo "  2. Eliminar o comentar las lineas mem_limit y cpus de cada servicio"
  echo "  3. Ejecutar: docker compose -f docker/docker-compose.yml up -d"
  echo ""
  echo "Para revertir el total de RAM de Docker Desktop a su valor original:"
  echo "  1. Abrir Docker Desktop"
  echo "  2. Settings (engranaje) -> Resources"
  echo "  3. Mover el slider Memory al valor previo (anotar antes de cambiar)"
  echo "  4. Apply & Restart"
} > "$SNAPSHOT_FILE"

echo "Snapshot guardado en $SNAPSHOT_FILE"
echo ""
echo "=== Contenido del snapshot ==="
cat "$SNAPSHOT_FILE"