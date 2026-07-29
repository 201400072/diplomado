#!/bin/bash
set -e

# Configurar ruta de retorno hacia soc_net a traves de Suricata (10.10.10.30)
ip route replace 10.10.0.0/24 via 10.10.10.30 2>/dev/null || true

# Iniciar apache (DVWA)
service apache2 start || apachectl start

# Iniciar Wazuh agent si existe
if [ -f /var/ossec/bin/wazuh-agentd ]; then
    /var/ossec/bin/wazuh-agentd -f &
    WAZUH_PID=$!
    echo "Wazuh agent started with PID $WAZUH_PID"
fi

# Mantener contenedor corriendo
if [ -f /var/ossec/logs/ossec.log ]; then
    tail -f /var/ossec/logs/ossec.log
else
    tail -f /var/log/apache2/access.log
fi