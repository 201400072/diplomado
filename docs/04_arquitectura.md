# Arquitectura del Sistema

## Vista general

```
┌────────────────────────────────────────────────────────────────────┐
│                       HOST: macOS Sequoia                          │
│                                                                    │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │              Docker Desktop (VM Linux)                      │  │
│  │                                                              │  │
│  │  ┌────────────────────────────────────────────────────────┐  │  │
│  │  │                 Red soc_net (10.10.0.0/24)            │  │  │
│  │  │                                                        │  │  │
│  │  │  wazuh.manager ──→ wazuh.indexer ←── wazuh.dashboard │  │  │
│  │  │     (10.10.0.10)   (10.10.0.11)      (10.10.0.12)     │  │  │
│  │  │                                                        │  │  │
│  │  │  suricata (10.10.0.30) ────► DVWA (10.10.0.40)       │  │  │
│  │  └────────────────────────────────────────────────────────┘  │  │
│  │                              │                               │  │
│  │  ┌────────────────────────────────────────────────────────┐  │  │
│  │  │                Red soc_span (10.10.10.0/24)           │  │  │
│  │  │                                                        │  │  │
│  │  │  suricata.eth1 (10.10.10.30) ──► DVWA (10.10.10.40)  │  │  │
│  │  │           ▲   captura tráfico                         │  │  │
│  │  └───────────┼────────────────────────────────────────────┘  │  │
│  │              │ eve.json (volumen compartido)                  │  │
│  │  ┌───────────┴────────────────────────────────────────────┐  │  │
│  │  │  wazuh.manager (volumen wazuh_manager_etc/logs)        │  │  │
│  │  │              logcollector lee eve.json                  │  │  │
│  │  └────────────────────────────────────────────────────────┘  │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                    │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                   HOST NETWORK (host.docker.internal)         │  │
│  │                                                              │  │
│  │  ┌────────────────────────────────────────────────────────┐  │  │
│  │  │  uvicorn (FastAPI ML)                                  │  │  │
│  │  │  http://localhost:8000                                │  │  │
│  │  │  http://host.docker.internal:8000 (desde containers) │  │  │
│  │  └────────────────────────────────────────────────────────┘  │  │
│  │                                                              │  │
│  │  ┌────────────────────────────────────────────────────────┐  │  │
│  │  │  Orquestador (proceso Python)                          │  │  │
│  │  │  python -m app.infrastructure.wazuh.orchestrator        │  │  │
│  │  └────────────────────────────────────────────────────────┘  │  │
│  └──────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────┘
```

## Componentes

### 1. Wazuh Indexer (OpenSearch 2.x)

- **Imagen**: `wazuh/wazuh-indexer:4.9.0`
- **IP**: 10.10.0.11
- **Puerto**: 9200 (HTTPS)
- **Función**: Almacenar y buscar alertas + predicciones ML
- **Volúmenes**:
  - `wazuh_indexer_data`: datos del cluster
- **Certificados**: 6 archivos PEM autofirmados en `wazuh_indexer_ssl_certs/`

### 2. Wazuh Manager

- **Imagen**: `wazuh/wazuh-manager:4.9.0`
- **IP**: 10.10.0.10
- **Puertos**: 1514 (agentes), 55000 (API REST), 514 (syslog)
- **Función**: SIEM central, análisis de logs
- **Volúmenes**:
  - `wazuh_manager_etc`: configuración
  - `wazuh_manager_logs`: logs (incluye eve.json de Suricata)
  - `wazuh_manager_queue`: cola de eventos
- **Nota**: En Mac arm64 emulando amd64, `wazuh-analysisd` no arranca por bug conocido (CRITICAL 1107 archives/2026)

### 3. Wazuh Dashboard (OpenSearch Dashboards)

- **Imagen**: `wazuh/wazuh-dashboard:4.9.0`
- **IP**: 10.10.0.12
- **Puerto**: 443 (HTTPS, expuesto al host)
- **Función**: UI para visualizar alertas y dashboards
- **Recursos**: 8 paneles configurados en dashboard "soc-diplomado"

### 4. Suricata

- **Imagen**: `jasonish/suricata:latest` (Suricata 8.0.6)
- **IPs**: 10.10.0.30 (soc_net/eth0), 10.10.10.30 (soc_span/eth1)
- **Función**: NIDS (Network Intrusion Detection System)
- **Captura**: AF_PACKET en eth1 (soc_span) donde reside DVWA
- **EVE JSON**: `/var/log/suricata/eve.json` (volumen compartido con manager)
- **Reglas**: 13 reglas personalizadas en `local.rules`

### 5. DVWA (Damn Vulnerable Web Application)

- **Imagen**: `vulnerables/web-dvwa:latest`
- **IPs**: 10.10.0.40 (soc_net), 10.10.10.40 (soc_span)
- **Puerto**: 80 (HTTP, expuesto al host)
- **Función**: Aplicación víctima para ataques
- **Nivel de seguridad**: low (vulnerable por diseño)

### 6. FastAPI ML

- **Imagen**: N/A (corre en host, no en Docker)
- **Puerto**: 8000 (HTTP)
- **Stack**: FastAPI 0.139 + Pydantic 2.13 + scikit-learn 1.9 + XGBoost 3.3
- **Endpoints**: `/health`, `/predict` (con API Key)
- **Modelo**: `ml/models/model.joblib` (2.7 MB)

### 7. Orquestador Wazuh → ML

- **Tipo**: Daemon Python en host
- **Función**: Lee alertas de Wazuh Indexer, transforma features, llama a ML API, indexa resultados
- **Frecuencia**: Cada 30s (configurable)
- **Idempotencia**: Set en memoria con alert_id procesados

## Flujo de datos

### Flujo 1: Captura y detección

```
[Tráfico de red] → [Suricata eth1] → [eve.json] → [Volumen compartido]
                                                       ↓
                                                  [wazuh-manager /var/ossec/logs/suricata/eve.json]
                                                       ↓
                                                  [logcollector lee] → [JSON decoder] → [rules 86601+]
                                                       ↓
                                                  [wazuh-alerts-4.x-YYYY.MM.DD]
```

### Flujo 2: Enriquecimiento ML (manual via orquestador)

```
[wazuh-alerts-*] → [orquestador fetch] → [alert_to_features] → [API ML /predict]
                                                                    ↓
                                                          [prediction + probabilities]
                                                                    ↓
                                                          [indexar en wazuh-ml-YYYY.MM.DD]
                                                                    ↓
                                                          [OpenSearch Dashboards]
```

### Flujo 3: Demo end-to-end (FASE 10-11)

```
[scripts/08_run_attack_suite.sh]
       ↓
[Suricata genera eve.json con alertas]
       ↓
[Inyección directa a wazuh-alerts-demo via HTTPS API]
       ↓
[Orquestador procesa cada alerta]
       ↓
[Predicciones en wazuh-ml-demo-YYYY.MM.DD]
       ↓
[Dashboard muestra 8 paneles]
```

## Diagrama de red

```
┌─────────────────────────────────────────────────────────┐
│              Docker bridge: soc_net                     │
│              Subnet: 10.10.0.0/24                       │
│                                                         │
│   wazuh.indexer  (10.10.0.11:9200) ◄────────┐           │
│   wazuh.manager  (10.10.0.10:55000) ────────┤           │
│   wazuh.dashboard (10.10.0.12:5601→443) ───┤           │
│   suricata.eth0  (10.10.0.30)              ├─Docker──┐  │
│   victim.dvwa    (10.10.0.40:80→host) ─────┘        │  │
└─────────────────────────────────────────────────────────┘  │
                                                             │
┌─────────────────────────────────────────────────────────┐
│              Docker bridge: soc_span (internal)         │
│              Subnet: 10.10.10.0/24                      │
│                                                         │
│   suricata.eth1 (10.10.10.30) ◄── captura tráfico ◄┐  │
│   victim.dvwa   (10.10.10.40) ──── DVWA ◄──────────┘  │
└─────────────────────────────────────────────────────────┘  │
                                                             │
                                                             │
   ┌─────────────────────────────────────────────────┐       │
   │         Host macOS (fuera de Docker)            │       │
   │                                                 │       │
   │  Browser → https://localhost:443               │       │
   │           ↓                                     │       │
   │  uvicorn (FastAPI ML) http://localhost:8000     │       │
   │           ↓                                     │       │
   │  Orquestador (Python daemon)                    │       │
   │           ↓                                     │       │
   │  Docker CLI → docker compose                   │       │
   └─────────────────────────────────────────────────┘       │
```

## Decisiones arquitectónicas

### ¿Por qué XGBoost sobre Deep Learning?

- **Datos tabulares**: CIC IDS 2017 tiene 69 features numéricas, dominio ideal para gradient boosting.
- **Interpretabilidad**: SHAP es nativo con XGBoost (TreeExplainer).
- **Rendimiento**: Accuracy 99.91% con F1 macro 0.90, suficiente para IDS.
- **Costo computacional**: Entrena 400k muestras en 20s en CPU.
- **Madurez**: Baseline establecido en literatura IDS (Buczak & Guven 2016).

### ¿Por qué FastAPI sobre Flask/Django?

- **Tipado nativo**: Pydantic v2 valida requests/responses automáticamente.
- **Documentación auto**: OpenAPI/Swagger sin configuración extra.
- **Async-ready**: Soporta async/await para escalar.
- **Rendimiento**: Uvicorn + uvloop, comparable a Node.js/Go.

### ¿Por qué Clean Architecture?

- **Testabilidad**: Servicios mockeables (17 tests de orquestador con httpx mockeado).
- **Mantenibilidad**: Cambios en ML no afectan API.
- **Extensibilidad**: Agregar endpoints sin tocar lógica de negocio.

### ¿Por qué Docker Compose sobre Kubernetes?

- **MVP académico**: k8s añade complejidad innecesaria para single-node.
- **Reproducibilidad**: `docker compose up` levanta todo en un comando.
- **Portabilidad**: Funciona idéntico en Mac/Linux/Windows.

### ¿Por qué Wazuh sobre ELK/Splunk?

- **Open source**: Sin licenciamiento, ético para academia.
- **HIDS+NIDS**: Cobertura completa vs Elastic Security solo SIEM.
- **Single-node**: Apropiado para el laboratorio.

### ¿Por qué CIC IDS 2017 sobre NSL-KDD?

- **Actualidad**: 2017 vs 2009 (KDD).
- **Realismo**: Incluye ataques modernos (Infiltration, Botnet).
- **Tamaño**: 2.3M muestras vs 148k (NSL-KDD).
- **Estándar**: Referencia en literatura IDS reciente.

## Patrones de diseño aplicados

| Patrón | Dónde | Propósito |
|---|---|---|
| **Singleton** | `ModelLoader`, `OpenSearchClient` | Cargar recursos pesados una sola vez |
| **Strategy** | `PredictorService` (XGBoost/RF) | Intercambiar modelos |
| **Repository** | `OpenSearchClient` | Abstraer acceso a datos |
| **Dependency Injection** | Endpoints con `Depends()` | Inversión de control |
| **Factory** | `setup_dashboards.py` | Crear visualizaciones declarativamente |
| **Template Method** | `alert_to_features()` | Construir features con defaults |
| **Facade** | `WazuhMLOrchestrator` | Simplificar interacción Wazuh↔ML |

## Métricas de rendimiento

| Operación | Latencia | Throughput |
|---|---|---|
| Inferencia ML (1 evento) | 7.3 ms | ~137 ev/s |
| Inferencia ML (batch 100) | 45 ms | ~2200 ev/s |
| Query Wazuh Indexer | 50-200 ms | - |
| Indexar predicción | 30-100 ms | - |
| Pipeline completo (alerta→ML→index) | 150-300 ms | ~4-6 al/s |

## Seguridad

### Implementada

- **API Key estática** con `secrets.compare_digest` (timing-safe).
- **HTTPS** en todas las comunicaciones internas (Wazuh Indexer, Dashboard).
- **Redes aisladas**: `soc_span` es `internal: true` (sin acceso a host).
- **Certificados autofirmados**: generados en tiempo de setup.
- **Sin secretos en código**: variables de entorno vía `.env`.

### NO implementada (fuera de alcance MVP)

- JWT tokens (vs API key estática).
- Rate limiting en API.
- TLS mutuo entre servicios.
- Rotación automática de credenciales.
- WAF en la API.

## Diagrama de despliegue (producción - NO MVP)

```
┌──────────────────────────────────────────────────────────┐
│                   PRODUCCIÓN (futuro)                    │
│                                                          │
│   Kubernetes Cluster (3 nodos mínimo)                   │
│   ├── Wazuh Manager (3 réplicas)                       │
│   ├── Wazuh Indexer (3 nodos, cluster)                 │
│   ├── OpenSearch Dashboards (2 réplicas)                │
│   ├── FastAPI ML (3-5 réplicas detrás de LB)           │
│   ├── Orquestador (Deployment con KEDA para auto-scale)│
│   └── Prometheus + Grafana (observabilidad)            │
│                                                          │
│   Almacenamiento:                                        │
│   ├── PersistentVolumes para Wazuh                      │
│   └── S3 para backups de modelos ML                     │
│                                                          │
│   Seguridad:                                              │
│   ├── Vault para secretos                               │
│   ├── mTLS entre servicios                              │
│   ├── OAuth2 + RBAC en API                              │
│   └── SIEM externo para auditoría                       │
└──────────────────────────────────────────────────────────┘
```

El MVP actual es **single-node** apropiado para el diplomado. La arquitectura escala horizontalmente con los mismos componentes.