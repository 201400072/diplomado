"""
Configuracion central de la aplicacion (12-factor).

Carga variables de entorno con pydantic-settings y provee
valores por defecto seguros para desarrollo.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


# Path base del proyecto (api/)
BASE_DIR = Path(__file__).resolve().parent.parent.parent


class Settings(BaseSettings):
    """Configuracion de la aplicacion."""

    model_config = SettingsConfigDict(
        env_file=str(BASE_DIR / ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- App ---
    app_name: str = Field(default="SOC ML API", description="Nombre de la API")
    app_version: str = Field(default="1.0.0", description="Version")
    app_description: str = Field(
        default="API REST para prediccion de amenazas ciberneticas con XGBoost",
        description="Descripcion",
    )
    debug: bool = Field(default=False, description="Modo debug")

    # --- Server ---
    host: str = Field(default="0.0.0.0", description="Host del servidor")
    port: int = Field(default=8000, description="Puerto del servidor")
    workers: int = Field(default=1, description="Numero de workers Uvicorn")

    # --- Seguridad ---
    api_key: str = Field(
        default="ml-diplomado-2026-secure-key-change-in-prod",
        description="API Key estatica (header X-API-Key)",
    )
    api_key_header: str = Field(default="X-API-Key", description="Nombre del header")

    # --- ML Model ---
    model_path: Path = Field(
        default=BASE_DIR.parent / "ml" / "models" / "model.joblib",
        description="Ruta al modelo entrenado",
    )
    scaler_path: Path = Field(
        default=BASE_DIR.parent / "ml" / "models" / "scaler.pkl",
        description="Ruta al StandardScaler",
    )
    label_classes_path: Path = Field(
        default=BASE_DIR.parent / "ml" / "models" / "label_classes.json",
        description="Ruta al mapeo de clases",
    )
    expected_features: int = Field(default=69, description="Numero esperado de features")

    # --- OpenSearch ---
    opensearch_host: str = Field(default="localhost", description="Host OpenSearch")
    opensearch_port: int = Field(default=9200, description="Puerto OpenSearch")
    opensearch_scheme: str = Field(default="https", description="Scheme")
    opensearch_user: str = Field(default="admin", description="Usuario")
    opensearch_password: str = Field(default="SecretPassword", description="Password")
    opensearch_verify_ssl: bool = Field(default=False, description="Verificar SSL")
    opensearch_index_prefix: str = Field(
        default="wazuh-ml",
        description="Prefijo del indice para predicciones ML",
    )

    # --- Logging ---
    log_level: str = Field(default="INFO", description="Nivel de logging")
    log_format: str = Field(
        default="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        description="Formato de log",
    )

    # --- CORS ---
    cors_origins: list[str] = Field(
        default=["*"],
        description="Origenes CORS permitidos",
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Retorna la instancia cacheada de Settings."""
    return Settings()