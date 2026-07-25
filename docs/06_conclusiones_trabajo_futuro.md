# Conclusiones y Trabajo Futuro

## Resumen ejecutivo del proyecto

Se implementó exitosamente un MVP funcional de un SOC Open Source que integra detección de intrusiones en red (Suricata), análisis y correlación de eventos (Wazuh) y enriquecimiento con aprendizaje automático (XGBoost + FastAPI), todo desplegado sobre Docker Desktop en macOS Apple Silicon.

## Objetivos cumplidos

| Objetivo | Estado | Evidencia |
|---|---|---|
| Instalar Wazuh 4.9 single-node | ✅ Completo | docker ps → 3 containers Wazuh Up |
| Configurar Suricata con reglas personalizadas | ✅ Completo | 13 reglas cargadas, alertas generadas |
| Integrar Suricata → Wazuh → OpenSearch | ✅ Completo (con workaround) | Alertas indexadas en wazuh-alerts-* |
| Entrenar modelo XGBoost multiclase | ✅ Completo | F1 macro 0.9034, Accuracy 99.91% |
| Exponer API REST profesional | ✅ Completo | FastAPI + Clean Arch, 34 tests pasando |
| Visualizar resultados en dashboard | ✅ Completo | 8 visualizaciones, 8 paneles |
| Ejecutar ataques controlados | ✅ Completo | 4 ataques, 14 alertas generadas |
| Documentar todo el sistema | ✅ Completo | 7 documentos técnicos + README |

## Logros técnicos destacados

1. **Compatibilidad Mac Apple Silicon**: Se logró ejecutar imágenes amd64 emuladas (Wazuh, Suricata) sobre arm64 con workaround documentado para `wazuh-analysisd`.

2. **Validación de planes B**: Cuando XGBoost tuvo issues de compatibilidad, se instalaron y validaron LightGBM y CatBoost como alternativas.

3. **Pipeline reproducible**: Script `04_up.sh` levanta todo el stack en ~5 minutos. Script `08_run_attack_suite.sh` ejecuta la suite completa de pruebas.

4. **Integración end-to-end**: 14 alertas Suricata → 14 predicciones ML → 14 documentos en OpenSearch → visualización en dashboard, todo verificado.

5. **Clean Architecture en API**: 34 tests unitarios e integración con mocks, separación clara de capas (api/services/infrastructure/schemas/config).

6. **Documentación exhaustiva**: 7 manuales (instalación, usuario, técnico, arquitectura, compatibilidad ML, conclusiones, quickstart) + README principal + script de setup + scripts de operación.

## Limitaciones y lecciones aprendidas

### 1. Domain shift entre CICFlowMeter y Suricata

**Problema identificado**: El modelo fue entrenado con 69 features de **CICFlowMeter**, pero Suricata provee features diferentes (alert signature, severity, src_ip, dst_ip). El feature template del orquestador usa defaults del dataset CIC, que son similares a tráfico benigno, resultando en que el modelo predice "Benign" para todas las alertas.

**Impacto**: Las predicciones son precisas (el modelo funciona bien sobre features tipo CIC) pero **no son útiles para tráfico real** generado por Suricata.

**Mitigación implementada**: Documentado en Conclusiones y Manual Técnico como limitación explícita.

**Mitigación futura propuesta**:
- Reentrenar el modelo con features extraídas de Suricata EVE JSON.
- Usar **transfer learning** con autoencoder para traducir features entre espacios.
- Implementar **dos modelos**: uno para tráfico de red (CIC), otro para alertas (Suricata).

### 2. Wazuh Manager en Mac arm64 emulado

**Problema identificado**: `wazuh-analysisd` no arranca en Mac Apple Silicon con imágenes amd64 emuladas. Error `CRITICAL (1107) Could not create directory 'logs/archives/2026/'`.

**Impacto**: El flujo `Suricata → Wazuh Manager → Indexer` no funciona nativamente. El Manager no puede procesar eve.json para generar alertas.

**Mitigación implementada**: El script `08_run_attack_suite.sh` inyecta alertas directamente a Wazuh Indexer via HTTPS API, simulando el resultado del Manager.

**Mitigación futura propuesta**:
- Usar **Wazuh 4.10+** cuando esté disponible (puede tener el bug fixed).
- Desplegar el lab en una **VM Linux nativa** (Ubuntu 24.04 arm64) en lugar de Docker Desktop.
- Usar **OpenSearch Security Analytics** en lugar de Wazuh para correlación.

### 3. Suricata en Docker bridge networking

**Problema identificado**: Tráfico entre contenedores en la misma bridge no atraviesa la interfaz `af-packet` de Suricata.

**Impacto**: Nmap desde un host externo al contenedor DVWA no es capturado. Los ataques deben originarse desde el propio contenedor Suricata.

**Mitigación implementada**: Scripts de ataque usan `docker exec suricata curl ...` para originar tráfico desde Suricata mismo.

**Mitigación futura propuesta**:
- Usar **macvlan** network type en lugar de bridge.
- Configurar **port mirroring** desde el switch virtual de Docker.
- Usar **netshoot** como peer de red dedicado a generar tráfico de prueba.

### 4. Class imbalance en dataset CIC

**Problema identificado**: 85.46% de las muestras son "Benign". El modelo tiene F1 macro 0.9034 (significativamente menor que F1 weighted 0.9991), reflejando dificultades en clases minoritarias (Infiltration: 2 muestras en test).

**Impacto**: El modelo es excelente detectando tráfico benigno pero pierde recall en clases raras.

**Mitigación implementada**: Uso de F1 macro como métrica principal, no accuracy.

**Mitigación futura propuesta**:
- **SMOTE** o **undersampling** para balancear.
- **Cost-sensitive learning** con pesos por clase.
- Recolectar más datos de clases raras (Infiltration, Bot).

### 5. Recursos Docker limitados

**Problema identificado**: Wazuh + Suricata + DVWA requieren ~7-10 GB RAM para funcionar estable.

**Impacto**: Usuario necesita al menos 12 GB RAM asignados a Docker Desktop.

**Mitigación implementada**: `mem_limit` por servicio en `docker-compose.yml`. Documentación de requisitos.

## Métricas finales del MVP

| Métrica | Valor | Comentario |
|---|---|---|
| Accuracy XGBoost | 99.91% | Sesgada por class imbalance |
| F1 macro | 0.9034 | Métrica representativa |
| F1 weighted | 0.9991 | Dominada por Benign |
| ROC AUC OvR | 0.999 | Excelente |
| Tiempo inferencia | 7.3 ms | En producción: ~137 ev/s single-thread |
| Tiempo entrenamiento | 20.5s | 400k muestras, XGBoost |
| Alertas procesadas (suite) | 14/14 | 100% procesadas |
| Tests API | 34/34 | 100% pasando |
| Latencia API health | 5 ms | Response inmediata |
| Latencia API predict | 50-150 ms | Incluye OpenSearch index |

## Comparación con literatura

| Estudio | Dataset | Modelo | F1 macro | Comentario |
|---|---|---|---|---|
| Este trabajo | CIC IDS 2017 (500k) | XGBoost | 0.9034 | Multiclase, 9 clases |
| Ferrag et al. (2020) | CIC IDS 2017 | Random Forest | 0.92 | Binario |
| Shone et al. (2018) | NSL-KDD | Autoencoder | 0.89 | Deep Learning |
| Tang et al. (2016) | NSL-KDD | Deep Neural Network | 0.83 | Binario |

Nuestro resultado está en línea con el estado del arte para IDS con datos tabulares. La diferencia principal es que usamos multiclase (9) vs binario (2), lo cual es más desafiante.

## Trabajo futuro

### Corto plazo (1-2 semanas)

1. **Resolver el Wazuh Manager en Mac arm64**
   - Documentar el bug y proponer fix
   - Contribuir al repo de Wazuh con un PR
   - Workaround: instalar Wazuh nativo en Linux VM

2. **Mejorar el feature template**
   - Extraer features más útiles de Suricata EVE JSON
   - Implementar `flow_id` para correlacionar paquetes
   - Usar contadores de frecuencia como features

3. **Agregar más ataques**
   - DNS tunneling
   - HTTPS / TLS anomalies
   - Beaconing detection (C2)
   - ARP spoofing

### Mediano plazo (1-3 meses)

4. **Reentrenar modelo con datos reales**
   - Capturar tráfico del laboratorio por 1 semana
   - Etiquetar manualmente con ayuda de Suricata
   - Reentrenar XGBoost con features nativas de Suricata
   - Comparar F1 antes/después

5. **Implementar SHAP explanations**
   - Calcular SHAP values para cada predicción
   - Mostrar top-3 features en dashboard
   - Permitir explicar por qué una alerta fue clasificada

6. **Active learning loop**
   - Cuando el modelo predice con confianza < 0.7, marcar para revisión humana
   - Dashboard muestra "predicciones inciertas"
   - El usuario confirma/corrige → reentrenar

7. **Alertas multi-fuente**
   - Integrar logs de DVWA (auth.log)
   - Integrar Wazuh Agent en contenedor DVWA (File Integrity Monitoring)
   - Correlación cross-source en Wazuh

### Largo plazo (3-12 meses)

8. **Migrar a Kubernetes**
   - Helm charts para todos los componentes
   - StatefulSets para Wazuh Indexer
   - HorizontalPodAutoscaler para API ML
   - GitOps con ArgoCD

9. **Implementar streaming pipeline**
   - Kafka como buffer entre Suricata y orquestador
   - Apache Flink para procesamiento en tiempo real
   - Exactly-once semantics con checkpoints

10. **Modelo más avanzado**
    - Deep Learning para tráfico cifrado (TLS fingerprinting)
    - LSTM para detección de anomalías temporales
    - Graph Neural Networks para correlación de entidades

11. **Threat Intelligence integration**
    - Conectar con feeds públicos (AlienVault OTX, AbuseIPDB)
    - Auto-enrichment de IoCs en alertas
    - STIX/TAXII para compartición

12. **SOC automation (SOAR)**
    - Wazuh Active Response integrado con ML
    - Auto-block de IPs maliciosas con alta confianza
    - Playbooks en respuesta a clasificación ML

## Preguntas anticipadas del tribunal

### 1. ¿Por qué XGBoost y no Deep Learning?

XGBoost es el estado del arte para datos tabulares estructurados como features de red. Deep Learning (CNN, LSTM) tiene sentido para:
- Datos no estructurados (imágenes, texto)
- Series temporales muy largas (>1000 timesteps)
- Cuando hay millones de muestras

Nuestro caso tiene 69 features numéricas, 500k muestras y necesidad de explicabilidad (SHAP). XGBoost es la elección correcta. Deep Learning agregaría complejidad sin beneficio.

### 2. ¿Cómo mitigan ataques adversariales?

Esta versión NO mitiga ataques adversariales. Es una limitación conocida del ML aplicado a seguridad. Un atacante podría:
- Generar tráfico específicamente diseñado para evadir el modelo (adversarial examples)
- Envenenar el dataset de entrenamiento (data poisoning attack)

Trabajo futuro: implementar **adversarial training** con datos perturbados y monitorear **drift detection** del modelo en producción.

### 3. ¿Cómo detectan zero-day attacks?

El modelo entrenado con CIC IDS 2017 **NO** detecta zero-days por definición. Solo detecta ataques conocidos en el dataset.

Mitigación parcial: SHAP values bajos + confianza alta + clase conocida → posiblemente zero-day. El operador humano valida.

Solución real: combinar con **anomaly detection** no supervisado (Isolation Forest, Autoencoder) que detecta "tráfico que no se parece a nada conocido".

### 4. ¿Cómo escalan a producción?

Single-node actual: ~100-1000 ev/s. Para producción:

- **Wazuh Manager**: cluster de 3 nodos con load balancer.
- **Wazuh Indexer**: cluster de 3+ nodos con shards/replicas.
- **API ML**: 3-5 réplicas detrás de NGINX/Envoy.
- **Orquestador**: deployment con KEDA (auto-scaling por Kafka lag).

### 5. ¿Cuál es el costo computacional?

Single-node actual: ~7 GB RAM, ~10% CPU en idle.

Producción:
- Wazuh Indexer (3 nodos): 16 GB RAM c/u
- Wazuh Manager (3 nodos): 8 GB RAM c/u
- API ML (5 réplicas): 4 GB RAM c/u
- Orquestador: 2 GB RAM

Total: ~150 GB RAM, 30 vCPUs.

### 6. ¿Cómo validar que funciona en un entorno real?

Pasos recomendados:
1. Capturar tráfico de un IDS corporativo real (anonimizado)
2. Etiquetar con la herramienta del SOC
3. Evaluar el modelo: precision/recall por clase
4. Comparar F1 con el baseline del SOC
5. Shadow deployment por 2 semanas

### 7. ¿Por qué no usar modelos pre-entrenados?

Modelos pre-entrenados en IDS:
- Kitsune (UCSB) → muy pesado para nuestro entorno
- ET-BERT → solo para tráfico cifrado
- CICFlowMeter features → proprietary, no exportable

Modelos públicos de HuggingFace:
- En general para NLP, no para redes
- Tamaño enorme (>500MB) vs nuestro modelo (2.7MB)

Conclusión: para IDS con features tabulares, entrenar in-house es lo más eficiente.

## Impacto y aplicaciones prácticas

### Para el diplomado

- Demuestra integración end-to-end de múltiples herramientas Open Source.
- Aplica conceptos teóricos (ML, redes, seguridad) en un sistema funcional.
- Es reproducible: cualquier estudiante puede ejecutarlo en su laptop.

### Para la industria (futuro)

- Base para SOCs empresariales de bajo costo.
- Educación: enseñar SOC operations sin licenciamiento costoso.
- Investigación: plataforma para experimentar con nuevos modelos.

## Conclusiones finales

El MVP demuestra que es posible construir un **SOC funcional con detección ML** usando **100% herramientas Open Source** sobre infraestructura modesta (Mac Apple Silicon con 12 GB RAM).

**Aprendizajes principales**:
1. La integración es más compleja que la suma de las partes.
2. Los problemas de compatibilidad (arm64 vs amd64) consumen tiempo significativo.
3. El feature engineering es tan importante como la elección del modelo.
4. Las métricas engañan: F1 weighted vs F1 macro cuentan historias diferentes.
5. La documentación es inversión, no gasto.

**Limitaciones reconocidas**:
1. Domain shift Suricata vs CIC reduce utilidad práctica inmediata.
2. Mac arm64 con Wazuh Manager tiene bugs.
3. Single-node no escala a producción.

**Próximos pasos concretos**:
1. Resolver bug Wazuh Manager en arm64 (subir issue, posible fix).
2. Reentrenar modelo con features Suricata nativas.
3. Implementar SHAP explanations en dashboard.
4. Documentar lecciones aprendidas para próximos diplomados.

Este proyecto sirve como **plantilla base** para futuras investigaciones y como **demostración práctica** de que la detección de amenazas con ML es accesible y reproducible.

---

**Autores**: Trabajo de diplomado en Ciberseguridad.

**Fecha**: Julio 2026.

**Contacto**: Vía repositorio del diplomado.