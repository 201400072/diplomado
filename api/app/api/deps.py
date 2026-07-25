"""
Dependencias de FastAPI: autenticacion con API Key.

Verifica que cada request (excepto /health y /docs) incluya
el header X-API-Key con el valor correcto.
"""
from __future__ import annotations

import logging
import secrets

from fastapi import Header, HTTPException, status

from app.config.settings import get_settings

logger = logging.getLogger(__name__)


def require_api_key(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> str:
    """Valida el header X-API-Key contra el valor configurado.

    Usa comparacion en tiempo constante (secrets.compare_digest) para
    evitar timing attacks.

    Returns:
        El valor del header si es valido.

    Raises:
        HTTPException 401 si falta el header.
        HTTPException 403 si el valor es incorrecto.
    """
    settings = get_settings()

    if not x_api_key:
        logger.warning("Request sin API Key")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Falta el header X-API-Key",
        )

    if not secrets.compare_digest(x_api_key, settings.api_key):
        logger.warning("API Key invalida")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API Key invalida",
        )

    return x_api_key