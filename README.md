# Detección de Amenazas con Machine Learning

**Tema de diplomado**: *Implementación de un sistema de detección de amenazas cibernéticas mediante aprendizaje automático integrado con Wazuh y Suricata en un laboratorio de informatica.*

![Status](https://img.shields.io/badge/status-MVP-success) ![Python](https://img.shields.io/badge/python-3.12-blue) ![Docker](https://img.shields.io/badge/docker-4.9-blue) ![License](https://img.shields.io/badge/license-Academic-lightgrey)

---

## Resumen ejecutivo

Este proyecto implementa un **SOC (Security Operations Center) completo** sobre Docker Desktop en macOS Apple Silicon, integrando:

- **Wazuh 4.9.0** como SIEM central
- **Suricata 8.0** como NIDS (Network Intrusion Detection System)
- **XGBoost 3.3** como motor de Machine Learning para clasificación de amenazas
- **FastAPI + Pydantic v2** como API REST profesional con Clean Architecture
- **OpenSearch Dashboards** como capa de visualización

El sistema procesa ataques de red en tiempo real, los enriquece con predicciones ML y los visualiza en dashboards con métricas medibles.

## Stack tecnológico

| Capa | Tecnología | Versión | Rol |
|---|---|---|---|
| **SIEM** | Wazuh | 4.9.0 | Manager + Indexer + Dashboard + Agent |
| **NIDS** | Suricata | 8.0.6 | Detección de intrusiones en red |
| **Almacenamiento** | OpenSearch (vía Wazuh) | 2.x | Búsqueda e indexación |
| **Visualización** | Wazuh Dashboard | 4.9.0 | 8 paneles con métricas |
| **ML Principal** | XGBoost + Random Forest | 3.3.0 / 1.9.0 | Clasificación multiclase |
| **Tuning ML** | Optuna | 4.9.0 | Búsqueda de hiperparámetros |
| **Explicabilidad** | SHAP | 0.52.0 | (Preparado para FASE 11) |
| **Dataset** | CIC IDS 2017 | Kaggle | 500k filas estratificadas, 9 clases |
| **API** | FastAPI + Uvicorn | 0.139 / 0.51 | Endpoints REST con auth API Key |
| **Validación** | Pydantic | 2.13 | DTOs tipados |
| **Tests** | pytest | 9.1.1 | 34 tests pasando |
| **Orquestación** | Docker Compose | v2.38 | 6 servicios declarativos |
| **Lenguaje** | Python | 3.12 | Tipado estático, Clean Architecture |

## Quickstart

```bash
# 1. Clonar y preparar
cd "/Users/cristal/Umss/Diplomado/Modulo 6/Proyecto"
bash scripts/01_prereqs.sh              # Verificar entorno
bash scripts/02_vscode_profile.sh       # Crear perfil VS Code

# 2. Levantar el laboratorio
bash scripts/04_up.sh                   # Wazuh + Suricata + DVWA + API ML

# 3. Validar
bash scripts/06_healthcheck.sh          # Estado de servicios
bash scripts/08_run_attack_suite.sh     # Ejecutar ataques de prueba

# 4. Visualizar
open https://localhost:443/app/dashboards#/view/soc-diplomado
```

## Resultados del MVP

| Métrica | Valor |
|---|---|
| **Accuracy XGBoost** | 99.91% |
| **F1 macro** | 0.9034 |
| **F1 weighted** | 0.9991 |
| **Inferencia** | 7.3 ms por evento |
| **Alertas procesadas** | 14/14 (100%) |
| **Tests pasando** | 34/34 |
| **Líneas de código Python** | ~1500 (API + ML + Orquestador) |

## Estructura del proyecto

```
proyecto/
├── README.md                          # Este archivo
├── docs/                              # Documentación completa
│   ├── 00_QUICKSTART.md
│   ├── 01_instalacion.md
│   ├── 02_usuario.md
│   ├── 03_tecnico.md
│   ├── 04_arquitectura.md
│   ├── 05_compatibilidad_ml.md
│   └── 06_conclusiones_trabajo_futuro.md
│
├── docker/                              # Infraestructura
│   ├── docker-compose.yml              # 6 servicios declarativos
│   ├── .env                            # Variables de entorno
│   ├── wazuh/                          # Certs + reglas custom
│   ├── suricata/                       # Config + reglas locales
│   └── dvwa/                           # DVWA con Wazuh Agent embebido
│
├── ml/                                  # Pipeline Machine Learning
│   ├── src/
│   │   ├── prepare_dataset.py          # Descarga CIC + sampling
│   │   ├── eda.py                      # Análisis exploratorio
│   │   ├── features.py                 # Encoding multiclase
│   │   ├── split.py                    # Train/test + scaler
│   │   └── train.py                    # XGBoost + RF + Optuna
│   ├── data/                           # Dataset procesado
│   ├── models/                         # Artefactos entrenados
│   ├── reports/                        # Visualizaciones de métricas
│   └── .venv-ml/                       # Entorno Python ML
│
├── api/                                 # FastAPI Clean Architecture
│   ├── app/
│   │   ├── main.py                     # Entry point
│   │   ├── config/settings.py          # 12-factor config
│   │   ├── api/
│   │   │   ├── deps.py                 # API Key auth
│   │   │   └── v1/
│   │   │       ├── router.py
│   │   │       └── endpoints/
│   │   │           ├── health.py
│   │   │           └── predict.py
│   │   ├── services/predictor.py       # Lógica de negocio
│   │   ├── infrastructure/
│   │   │   ├── ml/loader.py            # Joblib + scaler
│   │   │   ├── opensearch/client.py    # OpenSearch indexer
│   │   │   └── wazuh/                  # Orquestador + dashboards
│   │   └── schemas/predict.py          # Pydantic DTOs
│   ├── tests/                          # 34 tests
│   └── .venv-api/                      # Entorno Python API
│
├── dashboards/                          # Export OpenSearch Dashboards
│   └── export_dashboard.ndjson          # 11 saved objects
│
├── attacks/                             # Scripts de ataque controlado
│   ├── nmap/run.sh
│   ├── bruteforce/run.sh
│   ├── dos/run.sh
│   └── sqli/run.sh
│
└── scripts/                             # Orquestación
    ├── 01_prereqs.sh
    ├── 02_vscode_profile.sh
    ├── 03_revert_resources.sh
    ├── 04_up.sh
    ├── 05_down.sh
    ├── 06_healthcheck.sh
    ├── 07_setup_dashboards.sh
    └── 08_run_attack_suite.sh
```

## Documentación detallada

- 📘 [Guía de Instalación](docs/01_instalacion.md)
- 📗 [Manual de Usuario](docs/02_usuario.md)
- 📕 [Manual Técnico](docs/03_tecnico.md)
- 📙 [Arquitectura del Sistema](docs/04_arquitectura.md)
- 📓 [Compatibilidad ML](docs/05_compatibilidad_ml.md)
- 📔 [Conclusiones y Trabajo Futuro](docs/06_conclusiones_trabajo_futuro.md)

## Autores

Proyecto de diplomado en Ciberseguridad. Implementación realizada como MVP académico.

## Licencia

Uso educativo y académico. Los datasets utilizados son públicos (Canadian Institute for Cybersecurity).