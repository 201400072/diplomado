# Manual de Usuario

Esta guía explica cómo usar el laboratorio SOC: levantar servicios, ejecutar ataques, visualizar resultados y consultar la API ML.

## Flujo de trabajo típico

```
1. Levantar laboratorio   →   bash scripts/04_up.sh
2. Configurar dashboards   →   bash scripts/07_setup_dashboards.sh
3. Ejecutar ataques        →   bash scripts/08_run_attack_suite.sh
4. Visualizar resultados   →   https://localhost:443/app/dashboards
5. Consultar ML API        →   http://localhost:8000/docs
6. Detener todo            →   bash scripts/05_down.sh
```

## 1. Comandos principales

| Script | Función |
|---|---|
| `bash scripts/04_up.sh` | Levantar Wazuh + Suricata + DVWA |
| `bash scripts/05_down.sh` | Detener todo (`--clean` borra volúmenes) |
| `bash scripts/05_down.sh --clean` | Reset total |
| `bash scripts/06_healthcheck.sh` | Verificar estado de servicios |
| `bash scripts/07_setup_dashboards.sh` | Crear dashboards |
| `bash scripts/08_run_attack_suite.sh` | Ejecutar suite de ataques |
| `bash scripts/01_prereqs.sh` | Verificar prerrequisitos |

## 2. Acceder al Dashboard

URL: **https://localhost:443/app/dashboards#/view/soc-diplomado**

### Paneles disponibles (8)

| Panel | Qué muestra |
|---|---|
| Cantidad de Predicciones ML por Clase | Distribución de predicciones |
| Top IPs Atacantes | IPs origen más frecuentes |
| Tipos de Ataques Detectados | Distribución de firmas Suricata |
| Amenazas por Severidad | Conteo por nivel (1=baja, 2=media, 3=alta) |
| Distribución de Confianza ML | Histograma de probabilidades |
| Timeline de Eventos por Hora | Series temporales |
| Predicciones ML Recientes | Tabla con últimas detecciones |
| Mapa de Calor IP vs Predicción | Cruce visual IP × Clase |

### Navegación

1. Click en el icono de menú hamburguesa (esquina superior izquierda)
2. Click en **Dashboard**
3. Buscar "SOC Diplomado"
4. Seleccionar "SOC Diplomado - Detección de Amenazas con ML"

## 3. Ejecutar ataques controlados

### Suite completa (recomendado)

```bash
bash scripts/08_run_attack_suite.sh
```

Ejecuta los 4 ataques en secuencia y valida que cada capa los detecta:
- Suricata genera alerta
- Wazuh Indexer recibe la alerta
- API ML predice la clase
- Dashboard muestra el resultado

### Ataques individuales

```bash
# Nmap scan
bash attacks/nmap/run.sh

# Hydra brute force
bash attacks/bruteforce/run.sh

# DoS HTTP flood
bash attacks/dos/run.sh

# SQL Injection + XSS + WebShell
bash attacks/sqli/run.sh
```

### Verificar alertas Suricata en vivo

```bash
docker exec suricata tail -f /var/log/suricata/eve.json | \
  python3 -c "
import sys, json
for line in sys.stdin:
    try:
        e = json.loads(line)
        if e.get('event_type') == 'alert':
            a = e['alert']
            print(f\"[{a['severity']}] SID {a['signature_id']}: {a['signature']}\")
    except: pass
"
```

## 4. Consultar la API ML

URL Swagger: **http://localhost:8000/docs**

### Endpoint: `GET /health`

Sin autenticación. Verifica estado del servicio.

```bash
curl -s http://localhost:8000/api/v1/health | python3 -m json.tool
```

Respuesta:

```json
{
  "status": "healthy",
  "version": "1.0.0",
  "model_loaded": true,
  "scaler_loaded": true,
  "opensearch_reachable": true,
  "timestamp": "2026-07-12T00:30:00Z"
}
```

### Endpoint: `POST /predict`

Requiere header `X-API-Key: ml-diplomado-2026-secure-key-change-in-prod`.

```bash
curl -X POST http://localhost:8000/api/v1/predict \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ml-diplomado-2026-secure-key-change-in-prod" \
  -d '{
    "events": [
      {
        "Flow Duration": 117189197,
        "Total Fwd Packets": 4,
        "Protocol": 6
      }
    ]
  }' | python3 -m json.tool
```

Respuesta:

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
        "DoS": 0.0002,
        "DDoS": 0.00004,
        ...
      }
    }
  ]
}
```

### Usar la API desde Python

```python
import httpx

headers = {"X-API-Key": "ml-diplomado-2026-secure-key-change-in-prod"}
data = {"events": [{"Flow Duration": 1000000, "Protocol": 6}]}

with httpx.Client(base_url="http://localhost:8000") as client:
    r = client.post("/api/v1/predict", json=data, headers=headers)
    prediction = r.json()["predictions"][0]
    print(f"Clase: {prediction['prediction']}")
    print(f"Confianza: {prediction['confidence']:.2%}")
```

## 5. Consultar Wazuh Indexer directamente

### Listar alertas

```bash
# Alertas de Suricata
curl -k -u admin:SecretPassword \
  "https://localhost:9200/wazuh-alerts-demo/_search?q=rule.groups:suricata&size=5&pretty"

# Predicciones ML
curl -k -u admin:SecretPassword \
  "https://localhost:9200/wazuh-ml-demo-*/_search?size=5&sort=@timestamp:desc&pretty"
```

### Agregaciones

```bash
# Conteo por prediction
curl -k -u admin:SecretPassword -X POST \
  "https://localhost:9200/wazuh-ml-demo-*/_search" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 0,
    "aggs": {
      "by_prediction": {"terms": {"field": "prediction", "size": 10}}
    }
  }' | python3 -m json.tool
```

## 6. Postman

Se incluye una colección lista para importar:

**Archivo**: `docs/postman/Wazuh_SOC_Diplomado.postman_collection.json`

**Pasos**:
1. Abrir Postman → Import
2. Arrastrar el archivo
3. Settings → desactivar "SSL certificate verification"
4. Ejecutar **"1.1 Obtener JWT Token"**
5. Las demás requests usan Bearer Token automático

## 7. Generar datos de prueba

Si necesitas datos sintéticos para demos:

```bash
cd api
source .venv-api/bin/activate

# 50 alertas aleatorias + procesarlas con ML
python -m app.infrastructure.wazuh.generate_dashboard_data

# Solo inyectar 5 alertas de demo
python -m app.infrastructure.wazuh.demo_e2e
```

## 8. Detener y limpiar

### Detener servicios (conservar datos)

```bash
bash scripts/05_down.sh
```

### Reset total (borrar volúmenes)

```bash
bash scripts/05_down.sh --clean
```

### Detener la API ML

```bash
pkill -9 -f uvicorn
```

## 9. Métricas a observar

Para una demo en vivo durante la defensa, mostrar estas métricas en orden:

1. **Dashboard actualizado**: https://localhost:443/app/dashboards#/view/soc-diplomado
2. **Predicciones en vivo**: `curl http://localhost:8000/api/v1/health`
3. **Tests pasando**: `cd api && source .venv-api/bin/activate && pytest tests/`
4. **Logs de orquestador**: `tail -f /tmp/api.log`

## FAQ

**¿Qué pasa si reinicio Docker Desktop?**
Los volúmenes se mantienen, pero los contenedores se detienen. Ejecuta `bash scripts/04_up.sh` para reiniciarlos.

**¿Cómo cambio las credenciales?**
Edita `docker/.env` y `api/.env`, luego `bash scripts/05_down.sh && bash scripts/04_up.sh`.

**¿Puedo usar mi propio modelo?**
Sí. Reemplaza `ml/models/model.joblib` con tu modelo. Debe ser compatible con la API (joblib + scikit-learn API).

**¿Cómo agrego más reglas Suricata?**
Edita `docker/suricata/rules/local.rules` y reinicia Suricata: `cd docker && docker compose restart suricata`.

**¿Por qué todas las predicciones son "Benign"?**
Limitación documentada (domain shift). El modelo fue entrenado con features CIC IDS 2017, pero Suricata provee features diferentes. Ver [Conclusiones](06_conclusiones_trabajo_futuro.md).