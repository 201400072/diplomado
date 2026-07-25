# Análisis de Compatibilidad de Algoritmos ML

**Fecha de validación**: FASE 2
**Sistema**: macOS Sequoia 26.5.1 · Apple Silicon arm64 · Python 3.12.11
**Comando de verificación**: `python ml/src/compatibility_check.py`

## Resumen ejecutivo

Se validaron **6 algoritmos de Gradient Boosting / Ensemble Learning** sobre la máquina de desarrollo. **Todos funcionan correctamente**, incluyendo el algoritmo primario XGBoost.

## Tabla de compatibilidad

| # | Algoritmo | Versión | Estado | F1 macro | Tiempo train (s) | Notas |
|---|---|---|---|---|---|---|
| 1 | **XGBoost** | 3.3.0 | ✅ OK | 0.7999 | 0.33 | **Primario del proyecto** |
| 2 | **RandomForest** | (sklearn 1.9.0) | ✅ OK | 0.7897 | 0.15 | **Baseline** ya en plan |
| 3 | **HistGradientBoosting** | (sklearn 1.9.0) | ✅ OK | 0.8151 | 1.46 | Alternativa pura sklearn |
| 4 | **ExtraTrees** | (sklearn 1.9.0) | ✅ OK | 0.8220 | 0.10 | Alternativa pura sklearn |
| 5 | **LightGBM** | 4.6.0 | ✅ OK | 0.8129 | 1.23 | Plan B equivalente a XGBoost |
| 6 | **CatBoost** | 1.2.10 | ✅ OK | 0.7804 | 0.21 | Plan B con threading propio |

> **Dataset de prueba**: 2 000 muestras sintéticas, 20 features, 4 clases (no es CIC IDS 2017; es solo para validar compatibilidad binaria).

## Plan de contingencia documentado

Si durante FASE 8 (entrenamiento) XGBoost fallara por incompatibilidad con la máquina destino (por ejemplo, en una Mac Intel o Linux sin libomp), el orden de fallback es:

### 🥇 Plan B: LightGBM

- **Cuándo usarlo**: XGBoost falla por dependencia OpenMP o rendimiento.
- **Ventajas**: API casi idéntica a XGBoost, compatible con SHAP, mismo tipo de modelo.
- **Cambio mínimo**: solo la clase `LGBMClassifier` en lugar de `XGBClassifier`.
- **Trade-off**: ligeramente más lento en datasets pequeños.

### 🥈 Plan C: HistGradientBoostingClassifier (sklearn)

- **Cuándo usarlo**: ni XGBoost ni LightGBM funcionan (entornos restringidos).
- **Ventajas**: cero dependencias externas, solo scikit-learn. No requiere OpenMP.
- **Cambio mínimo**: usar la clase de sklearn directamente.
- **Trade-off**: menos hiperparámetros para tuning fino.

### 🥉 Plan D: RandomForestClassifier (baseline)

- **Cuándo usarlo**: ya está implementado como baseline del proyecto.
- **Ventajas**: robusta, rápida, sin dependencias nativas.
- **Cambio mínimo**: ninguno, ya forma parte del alcance.
- **Trade-off**: menor performance en datos muy complejos.

## Error típico en macOS y solución

```
XGBoostError: XGBoost Library (libxgboost.dylib) could not be loaded.
Library not loaded: @rpath/libomp.dylib
```

**Causa**: XGBoost está compilado con OpenMP, pero macOS no incluye esta librería por defecto.

**Solución**:
```bash
brew install libomp
```

Esta solución ya está aplicada y validada en FASE 2 (versión `libomp 22.1.8` instalada).

## Cómo volver a validar

```bash
cd ml
source .venv-ml/bin/activate
python src/compatibility_check.py --verbose
```

Salida esperada: `6/6 algoritmos disponibles` y exit code `0`.

## Justificación para la defensa

Si el tribunal pregunta *"¿por qué XGBoost y no otro?"*, la respuesta combina:

1. **Empírica**: el benchmark muestra que tiene F1 macro competitivo (0.7999 con datos sintéticos; en CIC IDS 2017 con tuning esperamos > 0.90).
2. **Académica**: XGBoost es referencia en literatura IDS (Buczak & Guven 2016, Ferrag et al. 2020).
3. **Engineering**: tiene API estable, integración con SHAP TreeExplainer, soporta multiclase nativo (`multi:softprob`).
4. **Resiliencia**: el proyecto tiene 3 planes B validados, lo que demuestra madurez técnica.

## Paquetes añadidos al entorno ML

```
lightgbm==4.6.0
catboost==1.2.10
```

Ambos se usan solo si el plan principal falla. El `requirements.txt` los congela para reproducibilidad.