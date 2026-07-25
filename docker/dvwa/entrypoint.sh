#!/bin/bash
set -e

# Iniciar apache (DVWA)
service apache2 start || apachectl start

# Iniciar Wazuh agent
/var/ossec/bin/wazuh-agentd -f &
WAZUH_PID=$!

echo "Wazuh agent started with PID $WAZUH_PID"

# Mantener contenedor corriendo
tail -f /var/ossec/logs/ossec.log