# Guía de Ejecución Rápida del Laboratorio SOC

**Estado actual**: FASE 4 completada. Wazuh indexer, manager y dashboard operativos.

---

## Paths importantes del proyecto

```
Proyecto/
├── docker/                              # Toda la infra Docker
│   ├── docker-compose.yml               # Orquestador principal
│   ├── .env                             # Variables de entorno
│   ├── certs.yml                        # Config cert generator
│   ├── wazuh_indexer_ssl_certs/         # Certs autofirmados (12 archivos)
│   ├── wazuh_cluster/etc/ossec.conf     # Config manager (montada al container)
│   ├── wazuh_indexer/wazuh.indexer.yml  # Config indexer
│   ├── wazuh_dashboard/                 # Config dashboard
│   ├── wazuh/                           # Custom rules y agent config
│   ├── suricata/                        # Config Suricata
│   └── dvwa/                            # Dockerfile para DVWA + agent
├── ml/                                  # ML pipeline (FASE 7-8)
├── api/                                 # FastAPI (FASE 9)
├── dashboards/                          # NDJSON para OpenSearch Dashboards
├── attacks/                             # Scripts de ataques
└── scripts/                             # Scripts de utilidad
    ├── 01_prereqs.sh                    # Verificar entorno
    ├── 02_vscode_profile.sh             # Crear perfil VS Code
    ├── 03_revert_resources.sh           # Revertir límites compose
    ├── 04_up.sh                         # ★ Levantar todo el lab
    ├── 05_down.sh                       # Detener todo (con --clean borra volúmenes)
    └── 06_healthcheck.sh                # Verificar estado
```

---

## Comandos esenciales (desde la raíz del proyecto)

### 1. Verificar entorno

```bash
cd "/Users/cristal/Umss/Diplomado/Modulo 6/Proyecto"
bash scripts/01_prereqs.sh
```

### 2. Crear perfil VS Code "Diplomado"

```bash
bash scripts/02_vscode_profile.sh
```

### 3. Levantar laboratorio

```bash
bash scripts/04_up.sh
```

Este script:
1. Regenera certificados Wazuh si no existen.
2. Levanta wazuh.indexer, wazuh.manager, wazuh.dashboard.
3. Espera a que indexer esté healthy.
4. Levanta suricata y victim.dvwa.
5. Muestra el estado final.

### 4. Verificar estado

```bash
bash scripts/06_healthcheck.sh
```

### 5. Detener laboratorio

```bash
# Detener conservando datos
bash scripts/05_down.sh

# Detener y limpiar volumenes (reset total)
bash scripts/05_down.sh --clean
```

---

## URLs del laboratorio en ejecución

| Servicio | URL | Credenciales |
|---|---|---|
| Wazuh Dashboard | https://localhost:443 | admin / SecretPassword |
| Wazuh Manager API | https://localhost:55000 | wazuh-wui / MyS3cr37P450r.*- |
| Wazuh Indexer (OpenSearch) | https://localhost:9200 | admin / SecretPassword |
| DVWA (víctima) | http://localhost:80 | admin / password |

---

## Credenciales hardcodeadas (NO production)

Definidas en `docker/.env` y `docker/docker-compose.yml`:

```bash
WAZUH_INDEXER_ADMIN=admin / SecretPassword
WAZUH_API_USER=wazuh-wui / MyS3cr37P450r.*-
WAZUH_DASHBOARD=kibanaserver / kibanaserver
DVWA=admin / password
```

---

## Comandos docker-compose directos (alternativa a scripts)

### Desde `docker/`

```bash
cd "/Users/cristal/Umss/Diplomado/Modulo 6/Proyecto/docker"

# Validar compose sin levantar
docker compose config --quiet

# Levantar Wazuh solo
docker compose up -d wazuh.indexer wazuh.manager wazuh.dashboard

# Levantar Suricata + DVWA
docker compose up -d suricata victim.dvwa

# Ver logs
docker compose logs -f wazuh.manager

# Estado
docker compose ps

# Detener todo
docker compose down

# Detener y limpiar volumenes
docker compose down -v
```

---

## Acceder a la API REST de Wazuh

### Obtener JWT

```bash
TOKEN=$(curl -s -k -u 'wazuh-wui:MyS3cr37P450r.*-' \
  -X POST 'https://localhost:55000/security/user/authenticate?raw=true')
echo "${TOKEN:0:80}..."
```

### Endpoints útiles

```bash
# Estado del manager
curl -s -k -H "Authorization: Bearer $TOKEN" \
  'https://localhost:55000/manager/status' | python3 -m json.tool

# Agentes conectados
curl -s -k -H "Authorization: Bearer $TOKEN" \
  'https://localhost:55000/agents' | python3 -m json.tool

# Logs del manager
curl -s -k -H "Authorization: Bearer $TOKEN" \
  'https://localhost:55000/manager/logs' | python3 -m json.tool | head -n 30

# Reglas activas
curl -s -k -H "Authorization: Bearer $TOKEN" \
  'https://localhost:55000/rules' | python3 -m json.tool | head -n 20
```

---

## Probar conectividad OpenSearch

```bash
# Health
curl -sSLk -u admin:SecretPassword 'https://localhost:9200/_cluster/health?pretty'

# Índices
curl -sSLk -u admin:SecretPassword 'https://localhost:9200/_cat/indices?v'

# Buscar alertas
curl -sSLk -u admin:SecretPassword 'https://localhost:9200/wazuh-alerts-*/_search?pretty&q=*:*&size=3'
```

---

## Troubleshooting rápido

| Problema | Solución |
|---|---|
| `docker.sock` connection refused | Docker Desktop no está corriendo. Abrir desde Aplicaciones |
| `port 443 already in use` | Otro servicio usa el puerto. Verificar con `lsof -i :443` |
| Wazuh manager reinicia en bucle | Borrar volúmenes: `bash scripts/05_down.sh --clean` y volver a levantar |
| Cert errors en filebeat | Regenerar: `bash scripts/05_down.sh --clean && bash scripts/04_up.sh` |
| `Cannot connect to Docker daemon` | Iniciar Docker Desktop: `open -a "Docker Desktop"` |
| Wazuh indexer no healthy después de 5 min | Verificar `docker logs wazuh.indexer`, posiblemente `docker compose restart wazuh.indexer` |

---

## Resumen de credenciales (para referencia rápida)

| Componente | Usuario | Password | Puerto |
|---|---|---|---|
| Wazuh Manager API | `wazuh-wui` | `MyS3cr37P450r.*-` | 55000 |
| Wazuh Indexer | `admin` | `SecretPassword` | 9200 |
| Wazuh Dashboard | `admin` | `SecretPassword` | 443 |
| DVWA | `admin` | `password` | 80 |

> Las credenciales del indexer son las mismas para el dashboard porque Wazuh internamente las propaga.