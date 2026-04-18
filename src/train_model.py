from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

from .ebm_backend import EBMUnavailableError, train_ebm_incident_model
from .logging_utils import configure_logging, get_logger
from .modeling import ALL_FEATURES, build_incident_preprocessor
from .weak_label import apply_weak_labels, load_label_rules

logger = get_logger(__name__)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate weak labels for incidents and train a baseline suspicion model.")
    parser.add_argument("--project-root", default=".", help="Project root containing configs/, data/, and reports/.")
    parser.add_argument(
        "--input-incidents",
        default="data/processed/incidents.parquet",
        help="Incident parquet path relative to project root.",
    )
    parser.add_argument(
        "--label-rules",
        default="configs/incident_label_rules.yaml",
        help="Weak-label rule config relative to project root.",
    )
    parser.add_argument(
        "--model-backend",
        default="ebm",
        choices=["ebm", "logistic"],
        help="Preferred model backend. EBM is attempted first and falls back to logistic when unavailable.",
    )
    parser.add_argument("--artifacts-dir", default="artifacts", help="Artifact output directory relative to project root.")
    args = parser.parse_args()

    configure_logging()
    project_root = Path(args.project_root).resolve()
    logger.info("Starting training run project_root=%s input=%s", project_root, args.input_incidents)
    incidents = pd.read_parquet(project_root / args.input_incidents)
    rules = load_label_rules(project_root / args.label_rules)
    labeled, label_report = apply_weak_labels(incidents, rules)
    logger.info("Weak labeling complete incidents=%s positives=%s", len(labeled), int(labeled["weak_label_suspicious"].sum()))

    processed_root = project_root / "data" / "processed"
    reports_root = project_root / "reports"
    artifacts_root = project_root / args.artifacts_dir
    processed_root.mkdir(parents=True, exist_ok=True)
    reports_root.mkdir(parents=True, exist_ok=True)
    artifacts_root.mkdir(parents=True, exist_ok=True)

    labeled.to_parquet(processed_root / "incidents_labeled.parquet", index=False)
    labeled.head(100000).to_csv(processed_root / "incidents_labeled_sample.csv", index=False)
    (reports_root / "incident_label_report.json").write_text(json.dumps(label_report, indent=2), encoding="utf-8")

    model_report, scored = train_incident_model(
        labeled,
        artifacts_root / "incident_suspicion_model.joblib",
        preferred_model_type=args.model_backend,
    )
    logger.info("Model training complete scored_rows=%s artifact=%s", len(scored), artifacts_root / "incident_suspicion_model.joblib")
    scored.to_parquet(processed_root / "incidents_scored.parquet", index=False)
    scored.head(100000).to_csv(processed_root / "incidents_scored_sample.csv", index=False)
    (reports_root / "incident_model_report.json").write_text(json.dumps(model_report, indent=2), encoding="utf-8")
    print(
        {
            "incidents": int(len(labeled)),
            "positives": int(labeled["weak_label_suspicious"].sum()),
            "artifact": str(artifacts_root / "incident_suspicion_model.joblib"),
            "model_type": model_report.get("model_type"),
        }
    )
    return 0


def train_incident_model(
    labeled: pd.DataFrame,
    artifact_path: Path,
    preferred_model_type: str = "ebm",
) -> tuple[dict[str, Any], pd.DataFrame]:
    if preferred_model_type == "logistic":
        return train_logistic_incident_model(labeled, artifact_path)
    try:
        logger.info("Attempting EBM training first")
        return train_ebm_incident_model(labeled, artifact_path)
    except EBMUnavailableError as exc:
        logger.warning("EBM unavailable, falling back to logistic model: %s", exc)
    except Exception:
        logger.exception("EBM training failed, falling back to logistic model")
    return train_logistic_incident_model(labeled, artifact_path)


def train_logistic_incident_model(labeled: pd.DataFrame, artifact_path: Path) -> tuple[dict[str, Any], pd.DataFrame]:
    logger.info("Preparing training matrix rows=%s", len(labeled))
    X = labeled[ALL_FEATURES].copy()
    y = labeled["weak_label_suspicious"].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y if y.nunique() > 1 else None,
    )
    logger.info("Split train_rows=%s test_rows=%s positive_rate=%.4f", len(X_train), len(X_test), float(y.mean()))

    model = Pipeline(
        steps=[
            ("preprocessor", build_incident_preprocessor()),
            (
                "classifier",
                LogisticRegression(max_iter=4000, class_weight="balanced", solver="saga"),
            ),
        ]
    )
    model.fit(X_train, y_train)
    logger.info("Baseline model fit complete")

    train_proba = model.predict_proba(X_train)[:, 1]
    test_proba = model.predict_proba(X_test)[:, 1]
    test_pred = (test_proba >= 0.5).astype(int)
    scored_all = labeled.copy()
    scored_all["ml_suspicion_proba"] = model.predict_proba(X)[:, 1]
    scored_all["ml_suspicion_pred"] = (scored_all["ml_suspicion_proba"] >= 0.5).astype(int)
    scored_all["model_type"] = "logistic"

    model_payload = {
        "model": model,
        "feature_columns": ALL_FEATURES,
        "label_column": "weak_label_suspicious",
        "model_type": "logistic",
    }
    joblib.dump(model_payload, artifact_path)
    logger.info("Model artifact written path=%s", artifact_path)

    top_coefficients = extract_top_coefficients(model, top_n=25)
    report = {
        "model_type": "logistic",
        "note": "Metrics are measured against rule-derived weak labels, not analyst-confirmed malicious ground truth.",
        "train_rows": int(len(X_train)),
        "test_rows": int(len(X_test)),
        "positive_rate_train": round(float(y_train.mean()), 6),
        "positive_rate_test": round(float(y_test.mean()), 6),
        "roc_auc_test": _safe_metric(lambda: roc_auc_score(y_test, test_proba)),
        "average_precision_test": _safe_metric(lambda: average_precision_score(y_test, test_proba)),
        "classification_report": classification_report(y_test, test_pred, output_dict=True),
        "top_positive_coefficients": top_coefficients["positive"],
        "top_negative_coefficients": top_coefficients["negative"],
    }
    logger.debug("Model metrics roc_auc_test=%s average_precision_test=%s", report["roc_auc_test"], report["average_precision_test"])
    return _jsonable(report), scored_all


def extract_top_coefficients(model: Pipeline, top_n: int = 25) -> dict[str, list[dict[str, Any]]]:
    classifier = model.named_steps["classifier"]
    preprocessor = model.named_steps["preprocessor"]
    feature_names = list(preprocessor.get_feature_names_out())
    coefficients = classifier.coef_[0]
    pairs = sorted(zip(feature_names, coefficients), key=lambda item: item[1], reverse=True)
    positive = [{"feature": name, "coefficient": round(float(value), 6)} for name, value in pairs[:top_n]]
    negative = [
        {"feature": name, "coefficient": round(float(value), 6)}
        for name, value in sorted(zip(feature_names, coefficients), key=lambda item: item[1])[:top_n]
    ]
    return {"positive": positive, "negative": negative}


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


if __name__ == "__main__":
    raise SystemExit(main())
