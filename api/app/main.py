"""
Entry point de la aplicacion FastAPI.

Configura logging, middleware CORS, routers y eventos de startup/shutdown.
"""
from __future__ import annotations

import logging
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.v1.router import api_router
from app.config.settings import get_settings
from app.infrastructure.ml.loader import get_model_loader
from app.infrastructure.opensearch.client import get_opensearch_client


def setup_logging(log_level: str, log_format: str) -> None:
    """Configura el logging de la aplicacion."""
    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.INFO),
        format=log_format,
        handlers=[
            logging.StreamHandler(sys.stdout),
        ],
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Eventos de startup/shutdown."""
    settings = get_settings()
    logger = logging.getLogger(__name__)

    # Startup
    logger.info("Iniciando %s v%s", settings.app_name, settings.app_version)
    try:
        loader = get_model_loader()
        logger.info("Modelo ML cargado correctamente")
    except Exception as exc:
        logger.error("Error cargando modelo ML: %s", exc)

    # OpenSearch: chequeo NO bloqueante (timeout corto)
    try:
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as ex:
            future = ex.submit(get_opensearch_client().is_reachable)
            try:
                ok = future.result(timeout=3)
                if ok:
                    logger.info("OpenSearch alcanzable: %s:%s", settings.opensearch_host, settings.opensearch_port)
                else:
                    logger.warning("OpenSearch no responde (la API funcionara sin indexar)")
            except concurrent.futures.TimeoutError:
                logger.warning("OpenSearch timeout 3s (la API funcionara sin indexar)")
    except Exception as exc:
        logger.warning("OpenSearch no disponible: %s", exc)

    logger.info("API lista en http://%s:%s", settings.host, settings.port)
    logger.info("Documentacion Swagger: http://%s:%s/docs", settings.host, settings.port)

    yield

    # Shutdown
    logger.info("Apagando %s", settings.app_name)


def create_app() -> FastAPI:
    """Factory que crea la aplicacion FastAPI."""
    settings = get_settings()
    setup_logging(settings.log_level, settings.log_format)

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description=settings.app_description,
        debug=settings.debug,
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Router principal
    app.include_router(api_router)

    # Root endpoint
    @app.get("/", tags=["root"])
    def root():
        return {
            "name": settings.app_name,
            "version": settings.app_version,
            "docs": "/docs",
            "health": "/api/v1/health",
            "predict": "/api/v1/predict",
        }

    # Exception handler
    @app.exception_handler(Exception)
    async def global_exception_handler(request, exc):
        logger.exception("Unhandled exception: %s", exc)
        return JSONResponse(
            status_code=500,
            content={"detail": "Error interno del servidor", "error_code": "INTERNAL_ERROR"},
        )

    return app


# Instancia para uvicorn
app = create_app()


if __name__ == "__main__":
    import uvicorn
    settings = get_settings()
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        workers=settings.workers,
        reload=settings.debug,
    )