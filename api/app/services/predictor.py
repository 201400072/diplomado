"""
Logica de negocio: predictor ML.

Servicio que orquesta la inferencia: vectoriza features,
ejecuta el modelo y formatea resultados.
"""
from __future__ import annotations

import logging
import time
from typing import Any

import numpy as np

from app.infrastructure.ml.loader import ModelLoader

logger = logging.getLogger(__name__)


class PredictorService:
    """Servicio de prediccion. Orquesta el modelo ML."""

    def __init__(self, model_loader: ModelLoader) -> None:
        self.model_loader = model_loader

    def predict(self, events: list[dict]) -> list[dict[str, Any]]:
        """Realiza prediccion sobre un batch de eventos.

        Args:
            events: lista de dicts feature->valor

        Returns:
            Lista de predicciones con prediction, confidence y probabilidades
        """
        if not events:
            return []

        t0 = time.perf_counter()
        X = self.model_loader.vectorize(events)

        # Prediccion (clase)
        y_pred = self.model_loader.model.predict(X)
        # Probabilidades
        proba = self.model_loader.model.predict_proba(X)

        label_classes = self.model_loader.label_classes
        # Orden de clases que devuelve el modelo (puede no coincidir con label_classes dict)
        model_classes = self.model_loader.model.classes_

        results = []
        for i in range(len(events)):
            pred_idx = int(y_pred[i])
            pred_name = label_classes.get(pred_idx, str(pred_idx))

            # Construir dict de probabilidades {nombre_clase: prob}
            probs = {}
            for j, cls in enumerate(model_classes):
                cls_int = int(cls)
                cls_name = label_classes.get(cls_int, str(cls_int))
                probs[cls_name] = float(proba[i, j])

            confidence = float(proba[i].max())
            results.append({
                "prediction": pred_name,
                "prediction_id": pred_idx,
                "confidence": confidence,
                "probabilities": probs,
            })

        elapsed_ms = (time.perf_counter() - t0) * 1000
        logger.info(
            "Prediccion completada: %d eventos en %.2f ms (%.2f ms/evento)",
            len(events), elapsed_ms, elapsed_ms / len(events),
        )
        return results

    @staticmethod
    def predict_single(event: dict) -> dict[str, Any]:
        """Prediccion de un solo evento (helper)."""
        return PredictorService.predict([event])[0]