#!/usr/bin/env bash
# ============================================================
# Revierte los limites de memoria en docker-compose.yml
# para que cada contenedor use los recursos por defecto
# del engine Docker.
#
# NO revierte la configuracion de Docker Desktop (eso requiere GUI).
# Solo revierte los mem_limit / cpus que pusimos en docker-compose.yml.
# ============================================================
set -euo pipefail

cd "$(dirname "$0")/.."

COMPOSE_FILE="docker/docker-compose.yml"

echo "Revirtiendo limites en $COMPOSE_FILE ..."
echo ""

# Eliminar lineas mem_limit: y cpus: dentro de cada servicio
# Crea un backup antes
BACKUP="${COMPOSE_FILE}.backup-$(date +%Y%m%d-%H%M%S)"
cp "$COMPOSE_FILE" "$BACKUP"
echo "Backup creado: $BACKUP"
echo ""

# Usa sed para eliminar las lineas mem_limit: y cpus: con su indentacion
sed -i.tmp -E '/^[[:space:]]+(mem_limit|cpus):[[:space:]]/d' "$COMPOSE_FILE"
rm -f "${COMPOSE_FILE}.tmp"

echo "Lineas eliminadas:"
echo "  - mem_limit: ..."
echo "  - cpus: ..."
echo ""
echo "Para revertir TAMBIEN la RAM global de Docker Desktop (a su valor original):"
echo "  1. Abrir Docker Desktop -> Settings (engranaje) -> Resources"
echo "  2. Ajustar Memory y CPUs al valor deseado"
echo "  3. Apply & Restart"
echo ""
echo "Si quieres volver a poner los limites editables:"
echo "  cp $BACKUP $COMPOSE_FILE"