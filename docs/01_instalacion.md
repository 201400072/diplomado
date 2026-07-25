# Guía de Instalación

Esta guía detalla cómo instalar y configurar el laboratorio SOC desde cero en macOS Sequoia con Apple Silicon.

## Requisitos del Sistema

### Hardware mínimo

| Recurso | Mínimo | Recomendado |
|---|---|---|
| CPU | Apple Silicon M1 | M2 Pro o superior |
| RAM | 16 GB | 32 GB |
| Disco libre | 10 GB | 20 GB |
| Docker Desktop | 4.19+ | Última versión |

### Software

| Herramienta | Versión | Cómo verificar |
|---|---|---|
| macOS | Sequoia 15+ | `sw_vers` |
| Docker Desktop | 4.19+ | `docker --version` |
| Docker Compose | v2.38+ | `docker compose version` |
| Homebrew | 6.0+ | `brew --version` |
| Python | 3.12+ | `python3.12 --version` |
| Git | 2.39+ | `git --version` |
| Visual Studio Code | Última | `code --version` |

## Instalación paso a paso

### 1. Instalar Homebrew (si no está instalado)

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

### 2. Instalar herramientas base

```bash
brew install git jq python@3.12 libomp
brew install --cask visual-studio-code
```

**libomp es crítico**: XGBoost requiere OpenMP runtime.

### 3. Instalar Docker Desktop

1. Descargar desde https://www.docker.com/products/docker-desktop/
2. Instalar el `.dmg`
3. Abrir Docker Desktop y completar el setup inicial
4. **Asignar recursos**: Settings → Resources
   - Memory: 12 GB (mínimo 10 GB)
   - CPUs: 6
   - Disk: 80 GB
   - Click "Apply & Restart"

### 4. Configurar PATH

```bash
echo 'export PATH="/opt/homebrew/opt/python@3.12/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
which python3.12
# Debe devolver /opt/homebrew/opt/python@3.12/bin/python3.12
```

### 5. Clonar el repositorio

```bash
cd "/Users/cristal/Umss/Diplomado/Modulo 6/Proyecto"
```

Si ya tienes el proyecto, ve directamente al paso 6.

### 6. Verificar prerrequisitos

```bash
bash scripts/01_prereqs.sh
```

Salida esperada:

```
Docker:       Docker version 28.3.2, build 578ccf6
Compose:      Docker Compose version v2.38.2-desktop.1
Python:       Python 3.12.11
libomp:       22.1.8
Total Memory: 11.91GiB
```

### 7. Crear perfil VS Code "Diplomado"

```bash
bash scripts/02_vscode_profile.sh
```

Esto crea un perfil aislado en VS Code con:
- Python (ms-python.python)
- Pylance (ms-python.vscode-pylance)
- Black formatter (ms-python.black-formatter)
- Data Wrangler (ms-toolsai.datawrangler)
- YAML (redhat.vscode-yaml)
- Docker (ms-azuretools.vscode-docker)
- REST Client (humao.rest-client)

### 8. Generar certificados Wazuh

```bash
docker run --rm \
  -v "$(pwd)/docker/wazuh_indexer_ssl_certs:/certificates" \
  -v "$(pwd)/docker/certs.yml:/config/certs.yml" \
  wazuh/wazuh-certs-generator:0.0.2
```

### 9. Levantar el laboratorio

```bash
bash scripts/04_up.sh
```

Esto levanta:
- `wazuh.indexer` (OpenSearch backend)
- `wazuh.manager` (SIEM)
- `wazuh.dashboard` (UI)
- `suricata` (NIDS)
- `victim.dvwa` (App vulnerable)

Espera ~3-5 minutos para que todos los servicios estén `Up (healthy)`.

### 10. Configurar entornos Python

```bash
# ML venv
cd ml
python3.12 -m venv .venv-ml
source .venv-ml/bin/activate
pip install --upgrade pip wheel setuptools
pip install pandas numpy scipy scikit-learn xgboost joblib optuna shap matplotlib seaborn jupyter ipykernel python-dotenv tqdm pyarrow lightgbm catboost
deactivate

# API venv
cd ../api
python3.12 -m venv .venv-api
source .venv-api/bin/activate
pip install --upgrade pip wheel setuptools
pip install fastapi 'uvicorn[standard]' 'pydantic[email]' pydantic-settings joblib xgboost numpy pandas opensearch-py httpx shap pytest pytest-asyncio pytest-cov python-dotenv tenacity
deactivate
```

### 11. Levantar API ML

```bash
cd api
source .venv-api/bin/activate
nohup uvicorn app.main:app --host 0.0.0.0 --port 8000 > /tmp/api.log 2>&1 &
disown
sleep 5

# Verificar
curl -s http://localhost:8000/api/v1/health | python3 -m json.tool
```

### 12. Descargar dataset CIC IDS 2017 (opcional)

```bash
cd ml
source .venv-ml/bin/activate
pip install kaggle
mkdir -p ~/.kaggle
# Obtener API token de https://www.kaggle.com/settings y colocar en ~/.kaggle/kaggle.json
chmod 600 ~/.kaggle/kaggle.json
deactivate
```

### 13. Entrenar modelo ML

```bash
cd ml
source .venv-ml/bin/activate
python src/prepare_dataset.py   # Descarga CIC y crea sample 500k
python src/features.py         # Encoding multiclase
python src/split.py            # Train/test split + scaler
python src/train.py            # Entrena XGBoost + RF
deactivate
```

El modelo se guarda en `ml/models/model.joblib`.

### 14. Configurar dashboards

```bash
bash scripts/07_setup_dashboards.sh
```

Esto crea:
- 2 index patterns
- 8 visualizaciones
- 1 dashboard con 8 paneles

## Validación post-instalación

```bash
bash scripts/06_healthcheck.sh
```

Salida esperada:

```
============================================================
 HEALTH CHECK - Laboratorio SOC
============================================================

--- Wazuh Indexer (OpenSearch) ---
  OK -   cluster: opensearch status=green nodes=1

--- Wazuh Manager API ---
  OK - token JWT valido (404 chars)
  Manager processes: 10 running, 7 stopped

--- Wazuh Dashboard ---
  OK - HTTP 302

--- DVWA (victima) ---
  OK - HTTP 200 (DVWA accesible)

--- Suricata logs ---
  OK - eve.json existe (51 lineas)
```

## URLs de acceso

| Servicio | URL | Credenciales |
|---|---|---|
| Wazuh Dashboard | https://localhost:443 | admin / SecretPassword |
| Wazuh API REST | https://localhost:55000 | wazuh-wui / MyS3cr37P450r.*- |
| Wazuh Indexer | https://localhost:9200 | admin / SecretPassword |
| DVWA | http://localhost:80 | admin / password |
| FastAPI Swagger | http://localhost:8000/docs | Header `X-API-Key` |
| FastAPI Health | http://localhost:8000/api/v1/health | Público |

## Troubleshooting

### Error: `libomp not found` al usar XGBoost

```bash
brew install libomp
```

### Error: Docker daemon not running

```bash
open -a "Docker Desktop"
```

### Error: Puerto 443 ya en uso

```bash
lsof -i :443
# Identifica el proceso y detenlo
```

### Error: Wazuh Manager reinicia en bucle

```bash
bash scripts/05_down.sh --clean
bash scripts/04_up.sh
```

### Error: API no responde `/predict`

```bash
# Verificar que la API está corriendo
pgrep -lf uvicorn
# Reiniciar si es necesario
pkill -9 -f uvicorn
cd api && source .venv-api/bin/activate
nohup uvicorn app.main:app --host 0.0.0.0 --port 8000 > /tmp/api.log 2>&1 &
disown
```

## Desinstalación

```bash
# Detener y limpiar todo
bash scripts/05_down.sh --clean

# Eliminar entornos virtuales
rm -rf ml/.venv-ml api/.venv-api

# Desinstalar paquetes Homebrew (opcional)
brew uninstall libomp jq

# Desinstalar Docker Desktop
# Applications → Docker Desktop → Move to Trash
```