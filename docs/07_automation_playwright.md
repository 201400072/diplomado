# Automatización E2E con Playwright + subprocess

Esta guía explica cómo usar el script `scripts/09_e2e_automation.py` para automatizar pruebas end-to-end del SOC.

## ¿Qué hace el script?

Ejecuta una validación completa del laboratorio en 6 pasos:

1. **Docker Health Check** — Verifica que los 5 servicios (`wazuh.indexer`, `wazuh.manager`, `wazuh.dashboard`, `suricata`, `victim-dvwa`) están corriendo.

2. **API ML Health** — Verifica que FastAPI está respondiendo en `http://localhost:8001/api/v1/health`.

3. **Attack Suite** — Ejecuta `scripts/08_run_attack_suite.sh` (Nmap, Hydra, DoS, SQLi/XSS).

4. **API ML Predict** — Llama a `/api/v1/predict` con features de prueba.

5. **Wazuh Alerts Count** — Cuenta alertas en el índice `wazuh-alerts-demo`.

6. **Dashboard Screenshots** — Captura screenshots con Playwright del dashboard Wazuh, Swagger UI y health endpoint.

Al finalizar, genera un **reporte HTML** en `automation_reports/` con:
- Resumen de pasos exitosos/fallidos
- Detalles de cada paso
- Screenshots embebidas
- Artefactos descargables

## Requisitos

### Software

```bash
# Playwright Python (incluido en requirements.txt)
pip install playwright

# Navegador Chromium (~95 MB)
python -m playwright install chromium
```

### Servicios activos

```bash
bash scripts/04_up.sh        # Wazuh + Suricata + DVWA
cd api && source .venv-api/bin/activate
nohup uvicorn app.main:app --host 0.0.0.0 --port 8001 > /tmp/api.log 2>&1 &
```

## Uso

### Ejecución completa

```bash
cd api
source .venv-api/bin/activate
python ../scripts/09_e2e_automation.py
```

Salida:

```
[1/6] Verificando Docker...          OK (0.10s)
[2/6] Verificando API ML...          OK (0.07s)
[3/6] Ejecutando suite de ataques... OK (65.0s)
[4/6] Verificando API ML /predict... OK (0.30s)
[5/6] Contando alertas en Wazuh...   OK (0.03s)
[6/6] Capturando screenshots...       OK (17.0s)

Resultado final: 6/6 pasos OK en 83.2s
```

### Solo health + screenshots (sin ataques)

```bash
python ../scripts/09_e2e_automation.py --skip-attacks
```

### Browser visible (no headless)

```bash
python ../scripts/09_e2e_automation.py --headless=false
```

Útil para debug: ver el browser mientras interactúa.

## Artefactos generados

```
automation_reports/
├── automation_report_20260713_001943.html    ← Reporte principal
├── dashboard_20260713_001916.png             ← Screenshot dashboard
├── swagger_20260713_001916.png               ← Screenshot Swagger
├── health_20260713_001916.png                ← Screenshot /health
└── attack_suite_20260713_001455.log          ← Log completo del attack suite
```

## Reporte HTML

El archivo `automation_report_*.html` contiene:

- **Resumen visual**: cards con pasos exitosos/fallidos
- **Tabla detallada**: estado, duración, detalles, artefactos
- **Screenshots embebidas**: click para ampliar
- **Links a artefactos**: descargables directamente

Abrir en navegador:

```bash
open automation_reports/automation_report_*.html
```

## Estructura del script

```python
# 1. Constantes y configuración
WAZUH_DASHBOARD_URL = "https://localhost:443/..."
ML_API_URL = "http://localhost:8001"
ML_API_KEY = "..."

# 2. Helpers de subprocess
run_command(cmd, timeout)        # Ejecuta comando y retorna exitcode+stdout+stderr
docker_ps()                       # Lista containers como JSON

# 3. Steps de validación
step_docker_health()              # Verifica 5 servicios Up
step_api_health()                 # GET /health
step_run_attacks()                # bash scripts/08_run_attack_suite.sh
step_verify_predictions()         # POST /predict con features de prueba
step_wazuh_alerts_count()         # GET /_count en OpenSearch
step_dashboard_screenshots()      # Playwright: login + screenshots

# 4. Reporte
generate_html_report(report)      # Genera HTML embebido

# 5. Main
run_full_automation()             # Orquesta todos los steps
```

## Personalización

### Cambiar URLs

Editar las constantes al inicio del script:

```python
WAZUH_DASHBOARD_URL = "https://tu-dashboard.com"
ML_API_URL = "http://tu-api:8001"
WAZUH_DASHBOARD_USER = "tu_usuario"
WAZUH_DASHBOARD_PASSWORD = "tu_password"
```

### Agregar un step personalizado

```python
def step_mi_test_custom() -> TestResult:
    """Descripcion del step."""
    start = time.time()
    try:
        # Logica
        result = ...
        return TestResult(
            name="Mi Test Custom",
            success=True,
            duration_s=time.time() - start,
            details="OK",
        )
    except Exception as exc:
        return TestResult(
            name="Mi Test Custom",
            success=False,
            duration_s=time.time() - start,
            details=str(exc),
        )

# Agregar en run_full_automation():
report.results.append(step_mi_test_custom())
```

### Cambiar timeouts

```python
# En step_run_attacks():
code, out, err = run_shell("...", timeout=600)  # 10 min
```

## Troubleshooting

### "Playwright no instalado"

```bash
cd api && source .venv-api/bin/activate
pip install playwright
python -m playwright install chromium
```

### "No se puede conectar a localhost:8001"

La API no está corriendo. Iniciarla:

```bash
cd api && source .venv-api/bin/activate
nohup uvicorn app.main:app --host 0.0.0.0 --port 8001 > /tmp/api.log 2>&1 &
sleep 5
curl -s http://localhost:8001/api/v1/health
```

### "Login falla en dashboard"

Wazuh Dashboard puede haber cambiado los selectores. Inspeccionar:

```python
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page()
    page.goto("https://localhost:443/")
    page.wait_for_timeout(3000)
    
    # Listar todos los inputs
    for inp in page.locator("input").all():
        print(inp.evaluate("e => e.outerHTML"))
    
    # Listar botones
    for btn in page.locator("button").all():
        print(btn.evaluate("e => e.outerHTML"))
```

### "Timeout en screenshots"

Aumentar el timeout en `step_dashboard_screenshots()`:

```python
page.goto(WAZUH_DASHBOARD_URL, wait_until="networkidle", timeout=120000)
page.wait_for_timeout(15000)  # Mas tiempo para renderizar visualizaciones
```

### "Puerto 8000 ocupado"

Docker Desktop usa el puerto 8000 en Mac. La API ya está configurada para usar **puerto 8001** en este script. Si necesitas cambiar:

```python
# Editar la constante:
ML_API_URL = "http://localhost:8002"  # Otro puerto libre
```

Y cambiar también en `api/app/main.py` o al lanzar uvicorn.

## Integración con CI/CD

El script puede usarse en pipelines de GitHub Actions, GitLab CI, etc.:

```yaml
# .github/workflows/e2e.yml
name: E2E Tests
on: [push]

jobs:
  test:
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup environment
        run: |
          brew install python@3.12 libomp
          python3.12 -m venv api/.venv-api
          source api/.venv-api/bin/activate
          pip install -r api/requirements.txt
          python -m playwright install chromium
      
      - name: Start services
        run: bash scripts/04_up.sh
      
      - name: Run E2E automation
        run: |
          source api/.venv-api/bin/activate
          python scripts/09_e2e_automation.py
      
      - name: Upload report
        uses: actions/upload-artifact@v3
        with:
          name: automation-report
          path: automation_reports/*.html
```

## Métricas observadas

En una corrida típica (Mac Apple Silicon, 12 GB RAM Docker):

| Step | Duración |
|---|---|
| Docker Health Check | ~0.1s |
| API ML Health | ~0.1s |
| Attack Suite | ~65s |
| API ML Predict | ~0.3s |
| Wazuh Alerts Count | ~0.05s |
| Dashboard Screenshots | ~17s |
| **Total** | **~83s** |

## Archivos relacionados

- `scripts/09_e2e_automation.py` — Script principal
- `scripts/08_run_attack_suite.sh` — Suite de ataques (invocado por el script)
- `scripts/04_up.sh` — Levantar servicios
- `docs/postman/Wazuh_SOC_Diplomado.postman_collection.json` — Colección Postman (alternativa)

## Próximos pasos

- [ ] Agregar comparación de métricas entre ejecuciones
- [ ] Almacenar historial de reportes
- [ ] Integrar con GitHub Actions
- [ ] Agregar tests de regresión visual con Playwright snapshots
- [ ] Capturar screenshots de dashboards específicos (no solo el principal)