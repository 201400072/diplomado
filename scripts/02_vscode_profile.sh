#!/usr/bin/env bash
set -euo pipefail

PROFILE_NAME="Diplomado"
VSCODE_USER_DATA="$HOME/Library/Application Support/Code/User"
VSCODE_BASE="$VSCODE_USER_DATA/profiles"
PROFILE_ID="$(printf '%s' "$PROFILE_NAME" | shasum -a 256 | cut -c1-32)"
PROFILE_DIR="$VSCODE_BASE/$PROFILE_ID"
EXT_DIR="$PROFILE_DIR/extensions"

mkdir -p "$EXT_DIR"
mkdir -p "$VSCODE_BASE"

PROFILES_JSON="$VSCODE_USER_DATA/profiles.json"

if [ ! -f "$PROFILES_JSON" ]; then
  cat > "$PROFILES_JSON" <<EOF
{
  "profiles": {
    "$PROFILE_ID": {
      "name": "$PROFILE_NAME",
      "extensions": []
    }
  },
  "currentProfile": "$PROFILE_ID"
}
EOF
  echo "profiles.json creado y perfil '$PROFILE_NAME' registrado."
else
  echo "profiles.json ya existe; conservando configuración previa."
fi

EXTENSIONS=(
  "ms-python.python"
  "ms-python.vscode-pylance"
  "ms-python.black-formatter"
  "ms-toolsai.datawrangler"
  "redhat.vscode-yaml"
  "ms-azuretools.vscode-docker"
  "humao.rest-client"
)

echo "Instalando extensiones en perfil '$PROFILE_NAME'..."
for ext in "${EXTENSIONS[@]}"; do
  code --extensions-dir "$EXT_DIR" --install-extension "$ext" --force >/dev/null 2>&1 || echo "  ! Fallo al instalar: $ext"
  echo "  + $ext"
done

echo ""
echo "============================================================"
echo " Perfil '$PROFILE_NAME' configurado"
echo " Ubicación: $PROFILE_DIR"
echo " Extensiones: $EXT_DIR"
echo "============================================================"
echo ""
echo "Para usarlo:"
echo "  1. Abrir VS Code"
echo "  2. Click en el icono de perfil (esquina inferior izquierda)"
echo "  3. Seleccionar 'Diplomado'"
echo ""
code --extensions-dir "$EXT_DIR" --list-extensions