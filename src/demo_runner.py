from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
from typing import Any

import joblib
import numpy as np
import pandas as pd
import yaml
from sklearn.dummy import DummyClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from decision_support.service import generate_decision_support

from .build_incidents import build_incidents
from .demo_stream import DemoScenario, build_demo_scenarios, write_demo_stream
from .derive_features import derive_event_features, load_flag_rules
from .ingest import ingest_records
from .logging_utils import configure_logging, get_logger
from .modeling import ALL_FEATURES, build_incident_preprocessor
from .network_sample import build_network_evidence_package
from .normalize import normalize_records
from .services.coverage_review_service import build_coverage_review
from .train_model import train_incident_model
from .weak_label import apply_weak_labels, load_label_rules

logger = get_logger(__name__)


def run_demo_pipeline(
    project_root: str | Path = ".",
    output_dir: str | Path = "data/demo_run",
    batch_size: int = 1,
    incident_gap_minutes: int = 15,
    ordered_sequence_limit: int = 25,
    network_sample_dir: str | Path = "data/raw/cse-cic-ids2018-sample",
    model_training_input: str | Path | None = "data/processed/incidents_labeled.parquet",
) -> dict[str, Any]:
    root = _resolve_project_root(project_root)
    output_root = _resolve_output_dir(root, output_dir)
    stream_root = output_root / "stream"
    stream_records_root = stream_root / "records"
    processed_root = output_root / "processed"
    reports_root = output_root / "reports"
    if stream_root.exists():
        shutil.rmtree(stream_root)
    if processed_root.exists():
        shutil.rmtree(processed_root)
    if reports_root.exists():
        shutil.rmtree(reports_root)
    processed_root.mkdir(parents=True, exist_ok=True)
    reports_root.mkdir(parents=True, exist_ok=True)
    logger.info("Starting demo pipeline project_root=%s output_root=%s", root, output_root)

    scenarios = build_demo_scenarios()
    stream_manifest = write_demo_stream(
        stream_records_root,
        scenarios=scenarios,
        batch_size=batch_size,
        manifest_path=stream_root / "demo_manifest.json",
    )
    logger.info("Demo stream generated scenarios=%s batches=%s", len(scenarios), len(stream_manifest["batches"]))

    raw_records, ingest_metrics = ingest_records(stream_records_root)
    normalized = normalize_records(raw_records)
    flag_rules = load_flag_rules(root / "configs" / "event_flag_rules.yaml")
    events = derive_event_features(normalized, flag_rules)
    incidents = build_incidents(
        events,
        incident_gap_minutes=incident_gap_minutes,
        ordered_sequence_limit=ordered_sequence_limit,
    )
    logger.info("Demo incidents built events=%s incidents=%s", len(events), len(incidents))

    label_rules = load_label_rules(root / "configs" / "incident_label_rules.yaml")
    incidents_labeled, label_report = apply_weak_labels(incidents, label_rules)
    logger.info("Demo weak labeling complete incidents=%s positives=%s", len(incidents_labeled), int(incidents_labeled["weak_label_suspicious"].sum()))
    policy = yaml.safe_load((root / "configs" / "decision_policy.yaml").read_text(encoding="utf-8")) or {}
    network_evidence_package = build_network_evidence_package(root / network_sample_dir)
    demo_model_payload = _fit_demo_model_payload(
        incidents_labeled,
        processed_root / "demo_incident_suspicion_model.joblib",
        project_root=root,
        model_training_input=model_training_input,
    )

    scenario_outputs = []
    for scenario in scenarios:
        logger.info("Processing demo scenario scenario_id=%s title=%s", scenario.scenario_id, scenario.title)
        incident_row = _match_scenario_to_incident(incidents_labeled, scenario)
        incident_events = _build_incident_events_from_raw(incident_row, raw_records)
        detector_output = _build_detector_output(incident_row, scenario, demo_model_payload)
        coverage = _build_coverage_from_scenario(scenario)
        decision_support = generate_decision_support(
            incident=_build_incident_input(incident_row, scenario),
            detector_output=detector_output,
            coverage=coverage,
            policy=policy,
            knowledge_context={
                "playbook_snippets": [scenario.title, scenario.purpose],
                "domain_terms": [{"title": reason["rule"]} for reason in json.loads(incident_row["weak_label_reasons_json"])],
            },
            operator_context={"operator_type": "non_expert"},
        )
        evidence_record = _build_evidence_record(
            incident_row=incident_row,
            scenario=scenario,
            network_evidence_package=network_evidence_package,
            review_mode="initial",
        )
        coverage_review = build_coverage_review(
            incident_record={
                "incident_id": incident_row["incident_id"],
                "title": scenario.title,
                "summary": scenario.purpose,
                "primary_actor": {"actor_key": incident_row["actor_key"]},
                "entities": {"primary_source_ip_address": incident_row["primary_source_ip_address"]},
                "event_sequence": str(incident_row["ordered_event_name_sequence"]).split("|"),
            },
            evidence_record=evidence_record,
            detector_record={
                "risk_score": detector_output["risk_score"],
                "risk_band": detector_output["risk_band"],
                "top_signals_json": detector_output["top_signals"],
                "counter_signals_json": detector_output["counter_signals"],
            },
            coverage_record={
                "completeness_level": coverage["completeness_level"],
                "incompleteness_reasons_json": coverage["incompleteness_reasons"],
                "checks_json": coverage["checks"],
                "missing_sources_json": coverage["missing_sources"],
            },
            decision_support_result=decision_support,
        )
        initial_review = {
            "detector_output": detector_output,
            "decision_support": decision_support,
            "coverage_review": coverage_review,
        }

        double_check_review = None
        decision_changed = False
        if scenario.double_check_plan:
            logger.info("Processing demo double-check scenario scenario_id=%s", scenario.scenario_id)
            double_check_detector_output = _apply_double_check_detector_overrides(detector_output, scenario.double_check_plan)
            double_check_coverage = _apply_double_check_coverage_overrides(coverage, scenario.double_check_plan)
            double_check_decision_support = generate_decision_support(
                incident=_build_incident_input(incident_row, scenario),
                detector_output=double_check_detector_output,
                coverage=double_check_coverage,
                policy=policy,
                knowledge_context={
                    "playbook_snippets": [scenario.title, scenario.purpose, str(scenario.double_check_plan.get("summary") or "")],
                    "domain_terms": [{"title": pattern} for pattern in double_check_detector_output.get("retrieved_patterns", [])],
                },
                operator_context={"operator_type": "non_expert", "review_mode": "double_check"},
            )
            double_check_evidence_record = _build_evidence_record(
                incident_row=incident_row,
                scenario=scenario,
                network_evidence_package=network_evidence_package,
                review_mode="double_check",
            )
            double_check_coverage_review = build_coverage_review(
                incident_record={
                    "incident_id": incident_row["incident_id"],
                    "title": scenario.title,
                    "summary": scenario.purpose,
                    "primary_actor": {"actor_key": incident_row["actor_key"]},
                    "entities": {"primary_source_ip_address": incident_row["primary_source_ip_address"]},
                    "event_sequence": str(incident_row["ordered_event_name_sequence"]).split("|"),
                },
                evidence_record=double_check_evidence_record,
                detector_record={
                    "risk_score": double_check_detector_output["risk_score"],
                    "risk_band": double_check_detector_output["risk_band"],
                    "top_signals_json": double_check_detector_output["top_signals"],
                    "counter_signals_json": double_check_detector_output["counter_signals"],
                },
                coverage_record={
                    "completeness_level": double_check_coverage["completeness_level"],
                    "incompleteness_reasons_json": double_check_coverage["incompleteness_reasons"],
                    "checks_json": double_check_coverage["checks"],
                    "missing_sources_json": double_check_coverage["missing_sources"],
                },
                decision_support_result=double_check_decision_support,
            )
            decision_changed = (
                decision_support["decision_support_result"]["recommended_action"]["action_id"]
                != double_check_decision_support["decision_support_result"]["recommended_action"]["action_id"]
            )
            double_check_review = {
                "summary": scenario.double_check_plan.get("summary"),
                "expected_recommendation": scenario.double_check_plan.get("expected_recommendation"),
                "decision_changed": decision_changed,
                "detector_output": double_check_detector_output,
                "decision_support": double_check_decision_support,
                "network_evidence": _build_network_review_summary(network_evidence_package, reviewed=True),
                "coverage_review": double_check_coverage_review,
            }
        scenario_outputs.append(
            {
                "scenario_id": scenario.scenario_id,
                "title": scenario.title,
                "incident_id": incident_row["incident_id"],
                "expected_recommendation": scenario.expected_recommendation,
                "expected_blind_spot": scenario.expected_blind_spot,
                "expected_operator_move": scenario.expected_operator_move,
                "incident_events": incident_events,
                "decision_changed_after_double_check": decision_changed,
                "initial_review": initial_review,
                "double_check_review": double_check_review,
                "network_evidence": _build_network_review_summary(network_evidence_package, reviewed=False),
            }
        )
        logger.debug("Scenario output assembled scenario_id=%s incident_id=%s", scenario.scenario_id, incident_row["incident_id"])

    events.to_parquet(processed_root / "demo_events.parquet", index=False)
    incidents.to_parquet(processed_root / "demo_incidents.parquet", index=False)
    incidents_labeled.to_parquet(processed_root / "demo_incidents_labeled.parquet", index=False)

    report = {
        "stream_manifest": stream_manifest,
        "ingest_metrics": _jsonable(
            {
                "total_files_read": ingest_metrics.total_files_read,
                "total_records_parsed": ingest_metrics.total_records_parsed,
                "total_malformed_files": ingest_metrics.total_malformed_files,
                "total_malformed_records": ingest_metrics.total_malformed_records,
                "malformed_file_examples": ingest_metrics.malformed_file_examples,
                "malformed_record_reasons": ingest_metrics.malformed_record_reasons,
            }
        ),
        "event_count": int(len(events)),
        "incident_count": int(len(incidents)),
        "label_report": label_report,
        "demo_model": {
            "model_type": demo_model_payload.get("model_type"),
            "feature_columns": list(demo_model_payload.get("feature_columns") or []),
        },
        "network_evidence_package": network_evidence_package,
        "scenario_outputs": scenario_outputs,
    }
    (reports_root / "demo_run_report.json").write_text(json.dumps(_jsonable(report), indent=2), encoding="utf-8")
    logger.info("Demo report written path=%s", reports_root / "demo_run_report.json")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the current pipeline against purpose-doc demo scenarios.")
    parser.add_argument("--project-root", default=".", help="Project root.")
    parser.add_argument("--output-dir", default="data/demo_run", help="Directory under project root for demo outputs.")
    parser.add_argument("--batch-size", type=int, default=1, help="Records per generated CloudTrail JSON file.")
    args = parser.parse_args()

    configure_logging()
    report = run_demo_pipeline(
        project_root=args.project_root,
        output_dir=args.output_dir,
        batch_size=max(1, args.batch_size),
    )
    print(json.dumps({"event_count": report["event_count"], "incident_count": report["incident_count"], "scenario_count": len(report["scenario_outputs"])}, indent=2))
    return 0


def _match_scenario_to_incident(incidents: pd.DataFrame, scenario: DemoScenario) -> pd.Series:
    match = incidents
    if scenario.source_ip_hint:
        match = match.loc[match["primary_source_ip_address"] == scenario.source_ip_hint]
    if scenario.actor_hint:
        match = match.loc[match["actor_key"] == scenario.actor_hint]
    if match.empty:
        raise ValueError(f"No incident matched demo scenario {scenario.scenario_id}")
    return match.sort_values("incident_start_time").iloc[0]


def _build_incident_input(incident_row: pd.Series, scenario: DemoScenario) -> dict[str, Any]:
    return {
        "incident_id": str(incident_row["incident_id"]),
        "title": scenario.title,
        "summary": scenario.purpose,
        "severity_hint": _risk_band(float(incident_row["weak_label_score"])),
        "start_time": _stringify(incident_row.get("incident_start_time")),
        "end_time": _stringify(incident_row.get("incident_end_time")),
        "primary_actor": {"actor_key": incident_row.get("actor_key")},
        "entities": {"primary_source_ip_address": incident_row.get("primary_source_ip_address")},
        "event_sequence": str(incident_row.get("ordered_event_name_sequence") or "").split("|"),
    }


def _build_detector_output(incident_row: pd.Series, scenario: DemoScenario, demo_model_payload: dict[str, Any]) -> dict[str, Any]:
    weak_reasons = json.loads(incident_row["weak_label_reasons_json"])
    model_explanation = _build_model_explanation(incident_row, scenario, demo_model_payload, weak_reasons)
    risk_score = float(model_explanation["prediction_probability"])
    return {
        "risk_score": risk_score,
        "risk_band": _risk_band(risk_score),
        "top_signals": [{"label": item["rule"], "weight": item["weight"]} for item in weak_reasons],
        "counter_signals": [],
        "detector_labels": [item["rule"] for item in weak_reasons],
        "retrieved_patterns": _pattern_titles(incident_row, weak_reasons),
        "data_sources_used": ["demo_stream", "incident_builder", "weak_label_rules", "demo_incident_model"],
        "model_type": model_explanation["model_type"],
        "explanation": {
            **model_explanation["explanation"],
            "display_probability": model_explanation["prediction_probability"],
            "scenario_display_probability": model_explanation["scenario_display_probability"],
            "scoring_mode": "scenario_demo_calibration",
        },
        "feature_contributions": model_explanation["feature_contributions"],
    }


def _build_coverage_from_scenario(scenario: DemoScenario) -> dict[str, Any]:
    plan = scenario.coverage_plan or {}
    return {
        "completeness_level": plan.get("completeness_level", "medium"),
        "incompleteness_reasons": list(plan.get("incompleteness_reasons") or []),
        "checks": list(plan.get("checks") or []),
        "missing_sources": list(plan.get("missing_sources") or []),
    }


def _build_evidence_record(
    incident_row: pd.Series,
    scenario: DemoScenario,
    network_evidence_package: dict[str, Any] | None,
    review_mode: str,
) -> dict[str, Any]:
    summary_json: dict[str, Any] = {
        "title": scenario.title,
        "summary": scenario.purpose,
        "event_sequence": str(incident_row["ordered_event_name_sequence"]).split("|"),
        "operator_context": {"operator_type": "non_expert", "review_mode": review_mode},
    }
    if scenario.double_check_plan and review_mode == "double_check":
        summary_json["double_check_summary"] = scenario.double_check_plan.get("summary")
    network_summary = None
    if "network" in scenario.coverage_categories:
        network_summary = _build_network_review_summary(
            network_evidence_package,
            reviewed=bool(review_mode == "double_check"),
        )
    if network_summary is not None:
        summary_json["network_evidence"] = network_summary
    return {"summary_json": summary_json}


def _build_network_review_summary(
    network_evidence_package: dict[str, Any] | None,
    *,
    reviewed: bool,
) -> dict[str, Any] | None:
    if network_evidence_package is None:
        return None
    summary = {
        "status": "reviewed" if reviewed else "available_not_reviewed",
        "dataset": network_evidence_package["dataset"],
        "file_count": network_evidence_package["file_count"],
        "suspicious_flow_count": network_evidence_package["suspicious_flow_count"],
        "suspicious_ratio": network_evidence_package["suspicious_ratio"],
        "top_suspicious_labels": list(network_evidence_package.get("top_suspicious_labels") or []),
    }
    if reviewed:
        summary["suspicious_flow_examples"] = list(network_evidence_package.get("suspicious_flow_examples") or [])
    return summary


def _apply_double_check_detector_overrides(detector_output: dict[str, Any], plan: dict[str, Any]) -> dict[str, Any]:
    overrides = dict(plan.get("detector_output_overrides") or {})
    merged = {
        "risk_score": detector_output["risk_score"],
        "risk_band": detector_output["risk_band"],
        "top_signals": list(detector_output.get("top_signals") or []),
        "counter_signals": list(detector_output.get("counter_signals") or []),
        "detector_labels": list(detector_output.get("detector_labels") or []),
        "retrieved_patterns": list(detector_output.get("retrieved_patterns") or []),
        "data_sources_used": list(detector_output.get("data_sources_used") or []),
        "model_type": detector_output.get("model_type"),
        "explanation": dict(detector_output.get("explanation") or {}),
        "feature_contributions": list(detector_output.get("feature_contributions") or []),
    }
    merged.update(overrides)
    return merged


def _build_weak_label_feature_contributions(incident_row: pd.Series, weak_reasons: list[dict[str, Any]]) -> list[dict[str, Any]]:
    contributions: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in weak_reasons[:5]:
        rule = str(item["rule"])
        if rule in seen:
            continue
        seen.add(rule)
        contributions.append(
            {
                "feature": rule,
                "contribution": round(float(item["weight"]) / 10.0, 3),
                "direction": "increases suspicion",
                "plain_language": _plain_language_contribution(rule, incident_row),
            }
        )
    return contributions


def _plain_language_contribution(rule: str, incident_row: pd.Series) -> str:
    mapping = {
        "recon_plus_privilege": "Reconnaissance activity and privilege changes happened in the same incident.",
        "root_actor": "The root account was involved, which carries broader access and higher impact.",
        "contains_console_login": "An interactive console login was part of the activity.",
        "contains_privilege_change_api": "Permission or access-changing API calls were present.",
        "contains_recon_like_api": "The account was querying the environment in a way that looks like reconnaissance.",
    }
    if rule in mapping:
        return mapping[rule]
    if bool(incident_row.get("contains_resource_creation_api")) and rule == "resource_creation":
        return "New resources were created during the suspicious activity."
    return rule.replace("_", " ").capitalize() + "."


def _build_model_explanation(
    incident_row: pd.Series,
    scenario: DemoScenario,
    demo_model_payload: dict[str, Any],
    weak_reasons: list[dict[str, Any]],
) -> dict[str, Any]:
    model = demo_model_payload["model"]
    model_type = str(demo_model_payload.get("model_type") or "logistic")
    feature_columns = list(demo_model_payload.get("feature_columns") or ALL_FEATURES)
    row_frame = pd.DataFrame([{feature: incident_row.get(feature) for feature in feature_columns}])
    model_probability = _predict_positive_probability(model, row_frame)
    explanation = {
        "prediction_probability": round(model_probability, 6),
        "predicted_suspicious": bool(model_probability >= 0.5),
        "confidence": round(abs(model_probability - 0.5) * 2, 6),
    }
    try:
        if model_type == "ebm":
            feature_contributions = _extract_ebm_feature_contributions(model, row_frame, incident_row)
        else:
            feature_contributions = _extract_logistic_feature_contributions(model, row_frame, incident_row)
    except Exception:
        logger.exception("Failed to extract local model contributions, falling back to weak-label reasons incident_id=%s", incident_row.get("incident_id"))
        feature_contributions = _build_weak_label_feature_contributions(incident_row, weak_reasons)
    if not feature_contributions:
        feature_contributions = _build_weak_label_feature_contributions(incident_row, weak_reasons)
    detector_profile = dict(scenario.detector_profile or {})
    configured_display_probability = detector_profile.get("display_probability")
    prediction_probability = float(configured_display_probability) if configured_display_probability is not None else model_probability
    return {
        "model_type": model_type,
        "explanation": explanation,
        "prediction_probability": round(prediction_probability, 6),
        "scenario_display_probability": round(float(configured_display_probability), 6) if configured_display_probability is not None else None,
        "feature_contributions": feature_contributions,
    }


def _extract_ebm_feature_contributions(model: Pipeline, row_frame: pd.DataFrame, incident_row: pd.Series) -> list[dict[str, Any]]:
    preprocessor = model.named_steps["preprocessor"]
    classifier = model.named_steps["classifier"]
    transformed_row = preprocessor.transform(row_frame)
    transformed_feature_names = [str(name) for name in preprocessor.get_feature_names_out()]
    term_names = [str(name) for name in getattr(classifier, "term_names_", [])]
    if not term_names or not hasattr(classifier, "eval_terms"):
        return []
    term_scores = np.asarray(classifier.eval_terms(transformed_row))[0]
    contributions: list[dict[str, Any]] = []
    for raw_name, score in sorted(zip(term_names, term_scores), key=lambda item: abs(float(item[1])), reverse=True):
        contribution = float(score)
        if abs(contribution) < 1e-9:
            continue
        friendly_name = _friendly_feature_name(_resolve_ebm_term_name(raw_name, transformed_feature_names))
        contributions.append(
            {
                "feature": friendly_name,
                "contribution": round(contribution, 6),
                "direction": "increases suspicion" if contribution >= 0 else "reduces suspicion",
                "plain_language": _plain_language_model_contribution(friendly_name, contribution, incident_row),
            }
        )
        if len(contributions) >= 5:
            break
    return contributions


def _extract_logistic_feature_contributions(model: Pipeline, row_frame: pd.DataFrame, incident_row: pd.Series) -> list[dict[str, Any]]:
    preprocessor = model.named_steps["preprocessor"]
    classifier = model.named_steps["classifier"]
    transformed_row = preprocessor.transform(row_frame)
    feature_names = [str(name) for name in preprocessor.get_feature_names_out()]
    if hasattr(transformed_row, "toarray"):
        values = transformed_row.toarray()[0]
    else:
        values = np.asarray(transformed_row)[0]
    coefficients = np.asarray(classifier.coef_[0])
    contributions: list[dict[str, Any]] = []
    for raw_name, value in sorted(zip(feature_names, values * coefficients), key=lambda item: abs(float(item[1])), reverse=True):
        contribution = float(value)
        if abs(contribution) < 1e-9:
            continue
        friendly_name = _friendly_feature_name(raw_name)
        contributions.append(
            {
                "feature": friendly_name,
                "contribution": round(contribution, 6),
                "direction": "increases suspicion" if contribution >= 0 else "reduces suspicion",
                "plain_language": _plain_language_model_contribution(friendly_name, contribution, incident_row),
            }
        )
        if len(contributions) >= 5:
            break
    return contributions


def _plain_language_model_contribution(feature_name: str, contribution: float, incident_row: pd.Series) -> str:
    direction = "increased" if contribution >= 0 else "reduced"
    mapping = {
        "Failure ratio": f"A higher failure ratio {direction} suspicion.",
        "Event count": f"The number of events in this incident {direction} suspicion.",
        "Contains console login": f"An interactive console login {direction} suspicion.",
        "Contains privilege change api": f"Privilege-changing API calls {direction} suspicion.",
        "Contains recon like api": f"Reconnaissance-style API calls {direction} suspicion.",
        "Has recon plus privilege": f"The combination of reconnaissance and privilege changes {direction} suspicion.",
        "Actor is root": f"Use of the root account {direction} suspicion.",
    }
    if feature_name in mapping:
        return mapping[feature_name]
    top_event_name = incident_row.get("top_event_name")
    if top_event_name and feature_name.startswith("Top event name"):
        return f"The dominant event pattern around {top_event_name} {direction} suspicion."
    return f"{feature_name} {direction} suspicion in this incident."


def _friendly_feature_name(raw_name: str) -> str:
    normalized = str(raw_name)
    for prefix in ("num__", "bool__", "cat__"):
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix):]
    normalized = normalized.replace("_", " ").strip()
    return normalized[:1].upper() + normalized[1:] if normalized else "Model feature"


def _resolve_ebm_term_name(raw_name: str, transformed_feature_names: list[str]) -> str:
    if raw_name.startswith("feature_"):
        try:
            feature_index = int(raw_name.split("_", 1)[1])
        except ValueError:
            return raw_name
        if 0 <= feature_index < len(transformed_feature_names):
            return transformed_feature_names[feature_index]
    return raw_name


def _predict_positive_probability(model: Pipeline, row_frame: pd.DataFrame) -> float:
    probabilities = np.asarray(model.predict_proba(row_frame))[0]
    classifier = model.named_steps["classifier"]
    raw_classes = getattr(classifier, "classes_", None)
    classes = list(raw_classes) if raw_classes is not None else []
    if 1 in classes:
        return float(probabilities[classes.index(1)])
    if len(probabilities) == 1:
        return float(probabilities[0])
    return float(probabilities[-1])


def _fit_demo_model_payload(
    incidents_labeled: pd.DataFrame,
    artifact_path: Path,
    *,
    project_root: Path,
    model_training_input: str | Path | None,
) -> dict[str, Any]:
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    if incidents_labeled.empty:
        raise ValueError("Cannot fit demo model without incidents.")
    try:
        training_frame = incidents_labeled
        calibration_frame = incidents_labeled
        processed_labeled_path = project_root / Path(model_training_input) if model_training_input else None
        if processed_labeled_path and processed_labeled_path.exists():
            logger.info("Training demo model from processed incidents path=%s", processed_labeled_path)
            calibration_frame = pd.read_parquet(processed_labeled_path)
            training_frame = calibration_frame
            training_frame = _sample_training_rows(training_frame, max_rows=6000)
        if len(training_frame) >= 10 and training_frame["weak_label_suspicious"].nunique() > 1:
            logger.info("Training demo model with standard training path rows=%s", len(training_frame))
            train_incident_model(training_frame, artifact_path, preferred_model_type="ebm")
            payload = joblib.load(artifact_path)
            payload["calibration"] = _build_weak_label_prior_map(calibration_frame)
            return payload
    except Exception:
        logger.exception("Standard training path failed for demo model, falling back to in-memory fit")
    logger.info("Fitting compact demo model rows=%s positives=%s", len(incidents_labeled), int(incidents_labeled["weak_label_suspicious"].sum()))
    return _fit_demo_model_on_all_rows(incidents_labeled, artifact_path)


def _fit_demo_model_on_all_rows(incidents_labeled: pd.DataFrame, artifact_path: Path) -> dict[str, Any]:
    X = incidents_labeled[ALL_FEATURES].copy()
    y = incidents_labeled["weak_label_suspicious"].astype(int)
    if y.nunique() < 2:
        logger.warning("Demo training data has a single class, using constant fallback model")
        model = Pipeline(
            steps=[
                ("preprocessor", build_incident_preprocessor()),
                ("classifier", DummyClassifier(strategy="constant", constant=int(y.iloc[0]))),
            ]
        )
        model.fit(X, y)
        payload = {
            "model": model,
            "feature_columns": ALL_FEATURES,
            "label_column": "weak_label_suspicious",
            "model_type": "logistic",
            "calibration": _build_weak_label_prior_map(incidents_labeled),
        }
        joblib.dump(payload, artifact_path)
        return payload
    model_type = "ebm"
    try:
        from interpret.glassbox import ExplainableBoostingClassifier

        classifier = ExplainableBoostingClassifier(
            n_jobs=-1,
            random_state=42,
            learning_rate=0.01,
            max_rounds=200,
            interactions=4,
            early_stopping_rounds=20,
            early_stopping_tolerance=1e-4,
        )
    except Exception as exc:
        logger.warning("Demo EBM unavailable, falling back to logistic model: %s", exc)
        classifier = LogisticRegression(max_iter=4000, class_weight="balanced", solver="saga")
        model_type = "logistic"

    model = Pipeline(
        steps=[
            ("preprocessor", build_incident_preprocessor()),
            ("classifier", classifier),
        ]
    )
    try:
        model.fit(X, y)
    except Exception as exc:
        if model_type == "logistic":
            raise
        logger.warning("Demo EBM fit failed, falling back to logistic model: %s", exc)
        model = Pipeline(
            steps=[
                ("preprocessor", build_incident_preprocessor()),
                ("classifier", LogisticRegression(max_iter=4000, class_weight="balanced", solver="saga")),
            ]
        )
        model.fit(X, y)
        model_type = "logistic"

    payload = {
        "model": model,
        "feature_columns": ALL_FEATURES,
        "label_column": "weak_label_suspicious",
        "model_type": model_type,
        "calibration": _build_weak_label_prior_map(incidents_labeled),
    }
    joblib.dump(payload, artifact_path)
    return payload


def _sample_training_rows(frame: pd.DataFrame, *, max_rows: int) -> pd.DataFrame:
    if len(frame) <= max_rows:
        return frame
    label_series = frame["weak_label_suspicious"].astype(int)
    distinct_labels = int(label_series.nunique())
    if distinct_labels <= 1:
        return frame.sample(n=max_rows, random_state=42)
    rows_per_label = max(1, max_rows // distinct_labels)
    working = frame.assign(_weak_label_suspicious_int=label_series)
    sampled = working.groupby("_weak_label_suspicious_int", group_keys=False).apply(
        lambda chunk: chunk.sample(n=min(len(chunk), rows_per_label), random_state=42)
    )
    if "_weak_label_suspicious_int" in sampled.columns:
        sampled = sampled.drop(columns="_weak_label_suspicious_int")
    if len(sampled) < max_rows:
        remaining = frame.drop(index=sampled.index, errors="ignore")
        if not remaining.empty:
            sampled = pd.concat([sampled, remaining.sample(n=min(len(remaining), max_rows - len(sampled)), random_state=42)])
    return sampled.reset_index(drop=True)


def _build_weak_label_prior_map(frame: pd.DataFrame) -> dict[int, float]:
    working = frame[["weak_label_score", "weak_label_suspicious"]].copy()
    working["score_bucket"] = working["weak_label_score"].round().astype(int)
    grouped = working.groupby("score_bucket", dropna=False)["weak_label_suspicious"].mean()
    return {int(bucket): round(float(probability), 6) for bucket, probability in grouped.items()}


def _build_incident_events_from_raw(incident_row: pd.Series, raw_records: list[Any]) -> list[dict[str, Any]]:
    row_indices = json.loads(str(incident_row.get("raw_event_row_indices") or "[]"))
    event_ids = json.loads(str(incident_row.get("event_ids_in_order") or "[]"))
    incident_id = str(incident_row["incident_id"])
    events: list[dict[str, Any]] = []
    for event_index, raw_row_index in enumerate(row_indices):
        raw_record = raw_records[int(raw_row_index)]
        payload = dict(raw_record.record)
        events.append(
            {
                "incident_id": incident_id,
                "event_id": payload.get("eventID") or (event_ids[event_index] if event_index < len(event_ids) else f"{incident_id}-evt-{event_index + 1:02d}"),
                "event_time": payload.get("eventTime"),
                "event_name": payload.get("eventName"),
                "event_source": payload.get("eventSource"),
                "event_index": event_index,
                "event_payload": payload,
            }
        )
    return events


def _apply_double_check_coverage_overrides(coverage: dict[str, Any], plan: dict[str, Any]) -> dict[str, Any]:
    overrides = dict(plan.get("coverage_overrides") or {})
    merged = {
        "completeness_level": coverage["completeness_level"],
        "incompleteness_reasons": list(coverage.get("incompleteness_reasons") or []),
        "checks": list(coverage.get("checks") or []),
        "missing_sources": list(coverage.get("missing_sources") or []),
    }
    merged.update(overrides)
    return merged


def _pattern_titles(incident_row: pd.Series, weak_reasons: list[dict[str, Any]]) -> list[str]:
    patterns = []
    if any(item["rule"] == "recon_plus_privilege" for item in weak_reasons):
        patterns.append("Reconnaissance followed by privilege change")
    if bool(incident_row.get("contains_console_login")):
        patterns.append("Suspicious console login")
    if bool(incident_row.get("contains_resource_creation_api")):
        patterns.append("Resource creation after sensitive activity")
    return patterns


def _risk_band(score: float) -> str:
    if score >= 0.75:
        return "high"
    if score >= 0.4:
        return "medium"
    return "low"


def _stringify(value: Any) -> str | None:
    if value is None:
        return None
    return value.isoformat() if hasattr(value, "isoformat") else str(value)


def _jsonable(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _jsonable(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_jsonable(item) for item in value]
    if isinstance(value, pd.Timestamp):
        return value.isoformat()
    return value


def _resolve_project_root(project_root: str | Path) -> Path:
    candidate = Path(project_root).resolve()
    if (candidate / "configs" / "event_flag_rules.yaml").exists():
        return candidate
    module_root = Path(__file__).resolve().parents[1]
    if (module_root / "configs" / "event_flag_rules.yaml").exists():
        logger.debug("Falling back to module root for demo pipeline project_root=%s", module_root)
        return module_root
    return candidate


def _resolve_output_dir(project_root: Path, output_dir: str | Path) -> Path:
    output_path = Path(output_dir)
    if output_path.is_absolute():
        return output_path
    return project_root / output_path


if __name__ == "__main__":
    raise SystemExit(main())
