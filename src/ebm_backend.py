from __future__ import annotations

from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

from .logging_utils import get_logger
from .modeling import ALL_FEATURES, build_incident_preprocessor

logger = get_logger(__name__)


class EBMUnavailableError(RuntimeError):
    pass


def train_ebm_incident_model(labeled: pd.DataFrame, artifact_path: Path) -> tuple[dict[str, Any], pd.DataFrame]:
    ebm_classifier = _build_ebm_classifier()
    logger.info("Preparing EBM training matrix rows=%s", len(labeled))
    X = labeled[ALL_FEATURES].copy()
    y = labeled["weak_label_suspicious"].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y if y.nunique() > 1 else None,
    )
    logger.info("EBM split train_rows=%s test_rows=%s positive_rate=%.4f", len(X_train), len(X_test), float(y.mean()))

    model = Pipeline(
        steps=[
            ("preprocessor", build_incident_preprocessor()),
            ("classifier", ebm_classifier),
        ]
    )
    model.fit(X_train, y_train)
    logger.info("EBM fit complete")

    test_proba = model.predict_proba(X_test)[:, 1]
    test_pred = (test_proba >= 0.5).astype(int)
    scored_all = labeled.copy()
    scored_all["ml_suspicion_proba"] = model.predict_proba(X)[:, 1]
    scored_all["ml_suspicion_pred"] = (scored_all["ml_suspicion_proba"] >= 0.5).astype(int)
    scored_all["model_type"] = "ebm"

    model_payload = {
        "model": model,
        "feature_columns": ALL_FEATURES,
        "label_column": "weak_label_suspicious",
        "model_type": "ebm",
    }
    joblib.dump(model_payload, artifact_path)
    logger.info("EBM artifact written path=%s", artifact_path)

    report = {
        "model_type": "ebm",
        "note": "Metrics are measured against rule-derived weak labels, not analyst-confirmed malicious ground truth.",
        "train_rows": int(len(X_train)),
        "test_rows": int(len(X_test)),
        "positive_rate_train": round(float(y_train.mean()), 6),
        "positive_rate_test": round(float(y_test.mean()), 6),
        "roc_auc_test": _safe_metric(lambda: roc_auc_score(y_test, test_proba)),
        "average_precision_test": _safe_metric(lambda: average_precision_score(y_test, test_proba)),
        "classification_report": classification_report(y_test, test_pred, output_dict=True),
        "top_global_explanations": _extract_top_ebm_terms(model, top_n=25),
    }
    return _jsonable(report), scored_all


def _build_ebm_classifier():
    try:
        from interpret.glassbox import ExplainableBoostingClassifier
    except ImportError as exc:  # pragma: no cover - behavior asserted indirectly
        raise EBMUnavailableError(
            "EBM training requires the 'interpret' package. Install it or use the logistic fallback."
        ) from exc
    return ExplainableBoostingClassifier(
        n_jobs=-1,
        random_state=42,
        learning_rate=0.01,
        max_rounds=300,
        interactions=8,
        early_stopping_rounds=30,
        early_stopping_tolerance=1e-4,
    )


def _extract_top_ebm_terms(model: Pipeline, top_n: int) -> list[dict[str, Any]]:
    classifier = model.named_steps["classifier"]
    names = [str(name) for name in getattr(classifier, "term_names_", [])]
    scores = list(getattr(classifier, "term_importances_", []) or [])
    ranked = sorted(zip(names, scores), key=lambda item: abs(float(item[1])), reverse=True)
    return [{"feature": name, "importance": round(float(value), 6)} for name, value in ranked[:top_n]]


def _jsonable(value: Any) -> Any:
    if hasattr(value, "item") and callable(value.item):
        try:
            return value.item()
        except Exception:
            pass
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_jsonable(item) for item in value]
    if isinstance(value, float):
        return round(value, 6)
    if isinstance(value, (pd.Timestamp,)):
        return value.isoformat()
    if value is pd.NA or (isinstance(value, float) and np.isnan(value)):
        return None
    return value


def _safe_metric(metric_fn) -> float | None:
    try:
        return round(float(metric_fn()), 6)
    except Exception:
        return None
