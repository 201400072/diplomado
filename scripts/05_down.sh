#!/usr/bin/env bash
# ============================================================
# Detiene el laboratorio y opcionalmente limpia volumenes.
# ============================================================
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DOCKER_DIR="$PROJECT_ROOT/docker"

cd "$DOCKER_DIR"

echo "============================================================"
echo " Deteniendo servicios"
echo "============================================================"
docker compose down 2>&1 | tail -n 5

if [ "${1:-}" = "--clean" ] || [ "${1:-}" = "-c" ]; then
  echo ""
  echo "============================================================"
  echo " Limpiando volumenes persistentes"
  echo "============================================================"
  docker volume ls -q | grep "soc-diplomado" | xargs -r docker volume rm 2>&1 | tail -n 5
  echo "Volumenes eliminados."
fi

echo ""
echo "============================================================"
echo " Estado final"
echo "============================================================"
docker compose ps