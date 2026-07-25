"""
Cargador del modelo ML (XGBoost) y artefactos relacionados.

Singleton: el modelo se carga una sola vez al iniciar la aplicacion.
"""
from __future__ import annotations

import json
import logging
from functools import lru_cache
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)


class ModelLoader:
    """Encapsula la carga del modelo, scaler y mapeo de clases."""

    def __init__(
        self,
        model_path: Path,
        scaler_path: Path,
        label_classes_path: Path,
    ) -> None:
        self.model_path = Path(model_path)
        self.scaler_path = Path(scaler_path)
        self.label_classes_path = Path(label_classes_path)
        self._model = None
        self._scaler = None
        self._label_classes: dict[int, str] = {}
        self._feature_names: list[str] = []

    def load(self) -> None:
        """Carga todos los artefactos. Llamar una vez al startup."""
        logger.info("Cargando modelo ML desde %s", self.model_path)
        if not self.model_path.exists():
            raise FileNotFoundError(f"Modelo no encontrado: {self.model_path}")
        self._model = joblib.load(self.model_path)
        logger.info("Modelo cargado: %s", type(self._model).__name__)

        logger.info("Cargando scaler desde %s", self.scaler_path)
        if not self.scaler_path.exists():
            raise FileNotFoundError(f"Scaler no encontrado: {self.scaler_path}")
        self._scaler = joblib.load(self.scaler_path)
        logger.info("Scaler cargado")

        logger.info("Cargando label classes desde %s", self.label_classes_path)
        if not self.label_classes_path.exists():
            raise FileNotFoundError(f"Label classes no encontrado: {self.label_classes_path}")
        with open(self.label_classes_path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        # Aceptar {"0": "Benign"} o {"Benign": 0}
        if all(isinstance(v, str) for v in raw.values()):
            self._label_classes = {int(k): v for k, v in raw.items()}
        else:
            self._label_classes = {v: k for k, v in raw.items()}
        logger.info("Label classes cargadas: %d clases", len(self._label_classes))

        # Feature names: si el modelo es de sklearn/XGBoost, intentar extraer
        # del scaler (que es StandardScaler)
        if hasattr(self._scaler, "feature_names_in_"):
            self._feature_names = list(self._scaler.feature_names_in_)
            logger.info("Feature names extraidos del scaler: %d", len(self._feature_names))

    @property
    def is_loaded(self) -> bool:
        return self._model is not None and self._scaler is not None

    @property
    def model(self):
        if not self.is_loaded:
            raise RuntimeError("Modelo no cargado. Llamar load() primero.")
        return self._model

    @property
    def scaler(self) -> StandardScaler:
        if self._scaler is None:
            raise RuntimeError("Scaler no cargado.")
        return self._scaler

    @property
    def label_classes(self) -> dict[int, str]:
        return self._label_classes

    @property
    def n_classes(self) -> int:
        return len(self._label_classes)

    @property
    def feature_names(self) -> list[str]:
        return self._feature_names

    def vectorize(self, events: list[dict]) -> np.ndarray:
        """Convierte una lista de eventos (dicts) en una matriz numpy escalada.

        Eventos que no tengan todas las features se completan con 0.
        El orden de las features se toma del scaler (mismo orden que en train).
        """
        if not self.feature_names:
            raise RuntimeError("Feature names no disponibles.")

        n_events = len(events)
        n_features = len(self.feature_names)
        matrix = np.zeros((n_events, n_features), dtype=np.float32)

        for i, event in enumerate(events):
            for j, fname in enumerate(self.feature_names):
                val = event.get(fname, 0.0)
                try:
                    matrix[i, j] = float(val)
                except (TypeError, ValueError):
                    logger.warning(
                        "Feature '%s' del evento %d no es numerico (%r). Usando 0.",
                        fname, i, val,
                    )
                    matrix[i, j] = 0.0

        # Escalar
        scaled = self.scaler.transform(matrix)
        return scaled


@lru_cache(maxsize=1)
def get_model_loader() -> ModelLoader:
    """Retorna el loader singleton (cacheado)."""
    from app.config.settings import get_settings
    settings = get_settings()
    loader = ModelLoader(
        model_path=settings.model_path,
        scaler_path=settings.scaler_path,
        label_classes_path=settings.label_classes_path,
    )
    loader.load()
    return loader