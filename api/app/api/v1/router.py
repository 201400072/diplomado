"""
Router principal de la API v1.

Agrega todos los endpoints v1 en un solo router.
"""
from fastapi import APIRouter

from app.api.v1.endpoints import health, predict

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(health.router)
api_router.include_router(predict.router)