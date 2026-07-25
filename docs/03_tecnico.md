# Manual Técnico

Documentación técnica para desarrolladores que necesiten extender, mantener o depurar el laboratorio SOC.

## Arquitectura

### Vista de capas

```
┌─────────────────────────────────────────────────────────────┐
│ CAPA 1: Captura de tráfico (Suricata)                       │
│ - AF_PACKET en eth1 (soc_span)                              │
│ - EVE JSON con 13 reglas personalizadas                      │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│ CAPA 2: SIEM (Wazuh 4.9)                                    │
│ - Indexer (OpenSearch 2.x)                                  │
│ - Manager (Análisis + API REST)                             │
│ - Dashboard (OpenSearch Dashboards + plugin Wazuh)         │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│ CAPA 3: Machine Learning (XGBoost + FastAPI)                │
│ - Modelo serializado con Joblib                              │
│ - API REST con Clean Architecture                           │
│ - OpenSearch client para indexar predicciones              │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│ CAPA 4: Orquestador (Wazuh → ML → OpenSearch)                │
│ - httpx para HTTP                                           │
│ - Feature builder con defaults del template                 │
│ - Idempotencia por alert_id                                 │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│ CAPA 5: Visualización (Wazuh Dashboard)                      │
│ - 2 index patterns                                          │
│ - 8 visualizaciones (pie, histograma, tabla, heatmap)      │
│ - 1 dashboard con 8 paneles                                 │
└─────────────────────────────────────────────────────────────┘
```

## Stack detallado

### Python 3.12 con tipado estático

```python
def predict(events: list[dict[str, float]]) -> list[dict[str, Any]]:
    """Procesa un batch de eventos y retorna predicciones."""
```

### FastAPI Clean Architecture

```
api/app/
├── main.py                   # Entry point + lifespan events
├── config/settings.py        # Pydantic Settings (12-factor)
├── api/
│   ├── deps.py               # Auth API Key
│   └── v1/
│       ├── router.py
│       └── endpoints/
│           ├── health.py      # GET /health
│           └── predict.py     # POST /predict
├── services/
│   └── predictor.py           # Lógica de negocio
├── domain/                    # (placeholder para FASE 12)
├── infrastructure/
│   ├── ml/loader.py           # Joblib + StandardScaler
│   ├── opensearch/client.py   # Cliente OpenSearch
│   └── wazuh/
│       ├── orchestrator.py    # Daemon Wazuh → ML
│       ├── demo_e2e.py         # Demo end-to-end con datos sintéticos
│       ├── setup_dashboards.py # Crea dashboards vía API
│       ├── add_visualizations.py
│       └── generate_dashboard_data.py
└── schemas/predict.py         # Pydantic DTOs
```

### Principios SOLID aplicados

| Principio | Implementación |
|---|---|
| **Single Responsibility** | Cada clase tiene una sola razón para cambiar (`ModelLoader`, `PredictorService`, `OpenSearchClient`) |
| **Open/Closed** | Servicios aceptan dependencias por constructor (DI manual) |
| **Liskov Substitution** | `ModelLoader` puede sustituirse por `MockModelLoader` en tests |
| **Interface Segregation** | Schemas separados (`HealthResponse`, `PredictionRequest`, `PredictionResponse`) |
| **Dependency Inversion** | Servicios dependen de abstracciones (`ModelLoader`) no de implementaciones |

## Modelo de datos

### Features del modelo XGBoost (69 features CICFlowMeter)

El modelo espera exactamente 69 features con estos nombres (en este orden):

```
Protocol, Flow Duration, Total Fwd Packets, Total Backward Packets,
Fwd Packets Length Total, Bwd Packets Length Total,
Fwd Packet Length Max, Fwd Packet Length Min, Fwd Packet Length Mean,
Fwd Packet Length Std, Bwd Packet Length Max, Bwd Packet Length Min,
Bwd Packet Length Mean, Bwd Packet Length Std,
Flow Bytes/s, Flow Packets/s,
Flow IAT Mean, Flow IAT Std, Flow IAT Max, Flow IAT Min,
Fwd IAT Total, Fwd IAT Mean, Fwd IAT Std, Fwd IAT Max, Fwd IAT Min,
Bwd IAT Total, Bwd IAT Mean, Bwd IAT Std, Bwd IAT Max, Bwd IAT Min,
Fwd PSH Flags, Fwd URG Flags,
Fwd Header Length, Bwd Header Length,
Fwd Packets/s, Bwd Packets/s,
Packet Length Min, Packet Length Max, Packet Length Mean,
Packet Length Std, Packet Length Variance,
FIN Flag Count, SYN Flag Count, RST Flag Count, PSH Flag Count,
ACK Flag Count, URG Flag Count, CWE Flag Count, ECE Flag Count,
Down/Up Ratio,
Avg Packet Size, Avg Fwd Segment Size, Avg Bwd Segment Size,
Subflow Fwd Packets, Subflow Fwd Bytes, Subflow Bwd Packets, Subflow Bwd Bytes,
Init Fwd Win Bytes, Init Bwd Win Bytes,
Fwd Act Data Packets, Fwd Seg Size Min,
Active Mean, Active Std, Active Max, Active Min,
Idle Mean, Idle Std, Idle Max, Idle Min
```

Las features se extraen automáticamente del `StandardScaler` entrenado:

```python
scaler = joblib.load("ml/models/scaler.pkl")
feature_names = list(scaler.feature_names_in_)  # 69 nombres exactos
```

### Clases del modelo (9 multiclase)

| ID | Clase | % en test |
|---|---|---|
| 0 | Benign | 85.46% |
| 1 | Bot | 0.06% |
| 2 | BruteForce | 0.40% |
| 3 | DDoS | 5.53% |
| 4 | DoS | 8.37% |
| 5 | Infiltration | 0.00% |
| 6 | Other | 0.00% |
| 7 | PortScan | 0.08% |
| 8 | WebAttack | 0.09% |

### Schema del índice OpenSearch `wazuh-ml-YYYY.MM.DD`

```json
{
  "mappings": {
    "properties": {
      "@timestamp": {"type": "date"},
      "alert_id": {"type": "keyword"},
      "timestamp": {"type": "date"},
      "prediction": {"type": "keyword"},
      "prediction_id": {"type": "integer"},
      "confidence": {"type": "float"},
      "model_version": {"type": "keyword"},
      "src_ip": {"type": "ip"},
      "dest_ip": {"type": "ip"},
      "alert_signature": {"type": "text"},
      "alert_severity": {"type": "integer"},
      "rule_id": {"type": "keyword"},
      "rule_description": {"type": "text"},
      "probabilities": {"type": "object", "enabled": false},
      "raw_event": {"type": "object", "enabled": false}
    }
  }
}
```

## API ML — Contrato

### Autenticación

Todos los endpoints excepto `/health`, `/docs`, `/redoc` requieren:

```
X-API-Key: ml-diplomado-2026-secure-key-change-in-prod
```

Validación con `secrets.compare_digest` (timing-safe).

### Endpoints

#### `GET /health`

```http
GET /api/v1/health HTTP/1.1
```

Respuesta 200:

```json
{
  "status": "healthy | degraded | unhealthy",
  "version": "1.0.0",
  "model_loaded": true,
  "scaler_loaded": true,
  "opensearch_reachable": true,
  "timestamp": "2026-07-12T00:30:00.000Z"
}
```

Status:
- `healthy`: modelo + scaler + OpenSearch OK
- `degraded`: modelo + scaler OK, OpenSearch no responde
- `unhealthy`: modelo o scaler no cargados

#### `POST /predict`

```http
POST /api/v1/predict HTTP/1.1
Content-Type: application/json
X-API-Key: ml-diplomado-2026-secure-key-change-in-prod

{
  "events": [
    {
      "Flow Duration": 117189197,
      "Total Fwd Packets": 4,
      "Protocol": 6,
      ...
    }
  ]
}
```

Respuesta 200:

```json
{
  "count": 1,
  "model_version": "1.0.0",
  "inference_time_ms": 7.3,
  "predictions": [
    {
      "prediction": "Benign",
      "prediction_id": 0,
      "confidence": 0.9997,
      "probabilities": {
        "Benign": 0.9997,
        "Bot": 3.9e-6,
        "BruteForce": 5.3e-6,
        ...
      }
    }
  ]
}
```

Códigos de error:
- 401: falta X-API-Key
- 403: X-API-Key inválida
- 422: payload inválido (Pydantic validation)

## Pipeline ML

### Preparación de datos (`ml/src/prepare_dataset.py`)

```python
# 1. Descarga Kaggle (dhoogla/cicids2017) - 258 MB
# 2. Combina 8 archivos parquet (2.3M filas)
# 3. Elimina columnas con 1 valor único
# 4. Reemplaza infinitos por NaN
# 5. Elimina duplicados
# 6. Sample estratificado de 500,000 filas
# 7. Guarda en data/processed/cic_ids_2017_sample.csv
```

### Feature engineering (`ml/src/features.py`)

```python
# Mapeo de 15 clases originales → 9 clases agrupadas
LABEL_MAP = {
    "Benign": "Benign",
    "DoS Hulk": "DoS", "DoS GoldenEye": "DoS",
    "DoS slowloris": "DoS", "DoS Slowhttptest": "DoS",
    "DDoS": "DDoS", "PortScan": "PortScan",
    "FTP-Patator": "BruteForce", "SSH-Patator": "BruteForce",
    "Web Attack - Brute Force": "WebAttack",
    "Web Attack - XSS": "WebAttack",
    "Web Attack - Sql Injection": "WebAttack",
    "Bot": "Bot", "Infiltration": "Infiltration",
    "Heartbleed": "Other",
}
```

### Train/test split (`ml/src/split.py`)

- Split 80/20 estratificado (`random_state=42`)
- `StandardScaler` fit solo en train (evita data leakage)
- Persistencia en `X_train.parquet`, `X_test.parquet`, `scaler.pkl`

### Entrenamiento (`ml/src/train.py`)

```python
# Random Forest baseline
RandomForestClassifier(
    n_estimators=200, max_depth=20, class_weight="balanced"
)

# XGBoost principal
xgb.XGBClassifier(
    objective="multi:softprob",
    num_class=9,
    n_estimators=200,
    max_depth=12,
    learning_rate=0.1206,
    subsample=0.84,
    colsample_bytree=0.66,
    # ... Optuna-tuned
)

# Tuning con Optuna (20 trials, 3-fold CV)
study = optuna.create_study(direction="maximize")
study.optimize(objective, n_trials=20)
```

## Orquestador Wazuh → ML

### Diseño (`api/app/infrastructure/wazuh/orchestrator.py`)

```python
class WazuhMLOrchestrator:
    def __init__(self):
        # Carga feature template del scaler
        self.feature_names = scaler.feature_names_in_
        
        # HTTP clients (httpx)
        self.wazuh_client = httpx.Client(...)
        self.ml_client = httpx.Client(...)
    
    def alert_to_features(self, alert: dict) -> dict:
        # Transforma alerta Suricata → 69 features
        # Escala features segun alert_severity (1=benign, 2=scan, 3=ataque)
    
    def call_ml_api(self, features: dict) -> dict:
        # POST /api/v1/predict
        # Retorna {"predictions": [...]}
    
    def index_prediction(self, doc: dict) -> bool:
        # Indexa en wazuh-ml-YYYY.MM.DD
    
    def process_alert(self, alert: dict) -> bool:
        # Orquesta los 3 pasos + idempotencia
        if alert_id in self.processed_alerts:
            return False
        # ... resto de la logica
```

### Modos de ejecución

```bash
# Daemon continuo (cada 30s)
python -m app.infrastructure.wazuh.orchestrator

# Procesar una vez y salir (testing)
python -m app.infrastructure.wazuh.orchestrator --once

# Intervalo personalizado
python -m app.infrastructure.wazuh.orchestrator --interval 60
```

### Idempotencia

El orquestador mantiene un `set` en memoria con `alert_id`s ya procesados. Para producción se debería usar Redis o el campo `_id` de OpenSearch.

## Limitaciones técnicas conocidas

### 1. Domain shift (CIC vs Suricata)

**Problema**: El modelo fue entrenado con 69 features de **CICFlowMeter**, pero Suricata solo provee ~15 features de alerta.

**Workaround aplicado**: Feature template con defaults del dataset, escalados por `alert_severity` (1=benign, 2=media, 3=alta).

**Limitación**: Como los defaults son similares a tráfico benigno, todas las predicciones son "Benign" con confianza alta.

**Solución futura**: Reentrenar con features de Suricata o usar traducción de features con autoencoder.

### 2. Wazuh Manager en Mac Apple Silicon

**Problema**: `wazuh-analysisd` no arranca por bug conocido (CRITICAL 1107 "Could not create directory 'logs/archives/2026/'") cuando la imagen Wazuh 4.9.0 corre emulando amd64 sobre arm64.

**Workaround aplicado**: Script `08_run_attack_suite.sh` inyecta eve.json directamente al Indexer vía HTTPS API.

**Solución futura**: Wazuh 4.10+ o instalación nativa en Linux.

### 3. Suricata en Docker bridge

**Problema**: Tráfico entre contenedores en la misma bridge no pasa por la interfaz `af-packet` de Suricata.

**Workaround aplicado**: Atacar desde el propio contenedor Suricata (curl contra DVWA en soc_span).

**Limitación**: Nmap desde un host externo no es capturado (el host no comparte la red soc_span).

**Solución futura**: Usar `netshoot` como peer de red o configurar macvlan.

## Testing

### Estructura

```
api/tests/
├── unit/
│   └── test_predictor.py      # 9 tests
└── integration/
    ├── test_api.py             # 8 tests
    └── test_orchestrator.py    # 17 tests
```

### Ejecutar

```bash
cd api
source .venv-api/bin/activate
pytest tests/                    # Todos
pytest tests/unit/               # Solo unitarios
pytest tests/integration/        # Solo integración
pytest --cov=app tests/          # Con coverage
```

### Cobertura

| Test | Qué valida |
|---|---|
| `test_predictor_handles_empty` | Predicción con lista vacía |
| `test_predictor_probabilities_sum_one` | Probabilidades suman 1 |
| `test_vectorize_handles_missing_features` | Features faltantes → 0 |
| `test_predict_without_api_key` | 401 sin auth |
| `test_predict_with_invalid_api_key` | 403 con key inválida |
| `test_process_alert_idempotent` | No duplica alertas |
| `test_alert_to_features_uses_correct_names` | Nombres exactos del scaler |

## Extensibilidad

### Agregar una nueva clase de ataque

1. Editar `docker/suricata/rules/local.rules`:
```yaml
alert http any any -> $HOME_NET any (msg:"Mi ataque"; content:"mipatron"; sid:1000099; rev:1;)
```

2. Reiniciar Suricata:
```bash
cd docker && docker compose restart suricata
```

3. (Opcional) Agregar al mapeo de features en `api/app/infrastructure/wazuh/orchestrator.py` (severity scaling).

### Cambiar el modelo ML

1. Entrenar nuevo modelo:
```bash
cd ml && source .venv-ml/bin/activate
python src/train.py --n-trials 50
```

2. El modelo se guarda en `ml/models/model.joblib`. La API lo carga automáticamente al iniciar.

3. Reiniciar API:
```bash
pkill -9 -f uvicorn
cd api && source .venv-api/bin/activate
nohup uvicorn app.main:app --host 0.0.0.0 --port 8000 > /tmp/api.log 2>&1 &
```

### Agregar un nuevo endpoint a la API

1. Crear schema Pydantic en `app/schemas/predict.py`
2. Crear endpoint en `app/api/v1/endpoints/`
3. Registrar en `app/api/v1/router.py`
4. (Opcional) Agregar tests en `tests/integration/test_api.py`

### Cambiar credenciales

```bash
# 1. Editar docker/.env
WAZUH_PASSWORD=NuevaPassword

# 2. Regenerar certs (solo si cambia INDEXER_PASSWORD)
cd docker
docker run --rm -v "$(pwd)/wazuh_indexer_ssl_certs:/certificates" \
  -v "$(pwd)/certs.yml:/config/certs.yml" wazuh/wazuh-certs-generator:0.0.2

# 3. Reiniciar
docker compose down
docker compose up -d wazuh.indexer wazuh.manager wazuh.dashboard

# 4. Editar api/.env
WAZUH_PASSWORD=NuevaPassword

# 5. Reiniciar API
pkill -9 -f uvicorn
cd api && source .venv-api/bin/activate
nohup uvicorn app.main:app --host 0.0.0.0 --port 8000 > /tmp/api.log 2>&1 &
```

## Logs

| Componente | Ubicación | Comando |
|---|---|---|
| API ML | `/tmp/api.log` | `tail -f /tmp/api.log` |
| Wazuh Manager | `docker logs wazuh.manager` | `docker logs -f wazuh.manager` |
| Wazuh Indexer | `docker logs wazuh.indexer` | `docker logs -f wazuh.indexer` |
| Suricata | `docker logs suricata` | `docker logs -f suricata` |
| Wazuh ossec.log | `/var/ossec/logs/ossec.log` (dentro del container) | `docker exec wazuh.manager tail -f /var/ossec/logs/ossec.log` |
| Suricata eve.json | `/var/log/suricata/eve.json` (volumen compartido) | `docker exec suricata tail -f /var/log/suricata/eve.json` |

## Debugging

### El modelo no clasifica correctamente

1. Verificar features con el script `debug_features.py` (crear si no existe)
2. Confirmar que el scaler cargado coincide con el que se usó para entrenar:
```bash
python3 -c "
import joblib
s = joblib.load('ml/models/scaler.pkl')
print(f'Features esperadas: {len(s.feature_names_in_)}')
print('Primeras 5:', list(s.feature_names_in_)[:5])
"
```

### El orquestador no procesa alertas

1. Verificar conectividad con OpenSearch:
```bash
curl -k -u admin:SecretPassword https://localhost:9200/_cluster/health
```

2. Verificar que la API ML responde:
```bash
curl http://localhost:8000/api/v1/health
```

3. Ver logs del orquestador:
```bash
python -m app.infrastructure.wazuh.orchestrator --once
```

### Dashboard no muestra datos

1. Verificar que los index patterns existen:
```bash
curl -k -u admin:SecretPassword "https://localhost:443/api/saved_objects/_find?type=index-pattern"
```

2. Verificar que hay documentos en el índice:
```bash
curl -k -u admin:SecretPassword "https://localhost:9200/wazuh-ml-demo-*/_count"
```

3. Re-ejecutar `scripts/07_setup_dashboards.sh`.