from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
from typing import Any

import pandas as pd
import yaml

from decision_support.service import generate_decision_support

from .build_incidents import build_incidents
from .demo_stream import DemoScenario, build_demo_scenarios, write_demo_stream
from .derive_features import derive_event_features, load_flag_rules
from .ingest import ingest_records
from .logging_utils import configure_logging, get_logger
from .normalize import normalize_records
from .services.coverage_review_service import build_coverage_review
from .weak_label import apply_weak_labels, load_label_rules

logger = get_logger(__name__)


def run_demo_pipeline(
    project_root: str | Path = ".",
    output_dir: str | Path = "data/demo_run",
    batch_size: int = 1,
    incident_gap_minutes: int = 15,
    ordered_sequence_limit: int = 25,
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

    scenario_outputs = []
    for scenario in scenarios:
        logger.info("Processing demo scenario scenario_id=%s title=%s", scenario.scenario_id, scenario.title)
        incident_row = _match_scenario_to_incident(incidents_labeled, scenario)
        detector_output = _build_detector_output(incident_row)
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
        coverage_review = build_coverage_review(
            incident_record={
                "incident_id": incident_row["incident_id"],
                "title": scenario.title,
                "summary": scenario.purpose,
                "primary_actor": {"actor_key": incident_row["actor_key"]},
                "entities": {"primary_source_ip_address": incident_row["primary_source_ip_address"]},
                "event_sequence": str(incident_row["ordered_event_name_sequence"]).split("|"),
            },
            evidence_record={
                "summary_json": {
                    "title": scenario.title,
                    "summary": scenario.purpose,
                    "event_sequence": str(incident_row["ordered_event_name_sequence"]).split("|"),
                    "operator_context": {"operator_type": "non_expert"},
                }
            },
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
            double_check_coverage_review = build_coverage_review(
                incident_record={
                    "incident_id": incident_row["incident_id"],
                    "title": scenario.title,
                    "summary": scenario.purpose,
                    "primary_actor": {"actor_key": incident_row["actor_key"]},
                    "entities": {"primary_source_ip_address": incident_row["primary_source_ip_address"]},
                    "event_sequence": str(incident_row["ordered_event_name_sequence"]).split("|"),
                },
                evidence_record={
                    "summary_json": {
                        "title": scenario.title,
                        "summary": scenario.purpose,
                        "event_sequence": str(incident_row["ordered_event_name_sequence"]).split("|"),
                        "operator_context": {"operator_type": "non_expert", "review_mode": "double_check"},
                        "double_check_summary": scenario.double_check_plan.get("summary"),
                    }
                },
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
                "decision_changed_after_double_check": decision_changed,
                "initial_review": initial_review,
                "double_check_review": double_check_review,
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


def _build_detector_output(incident_row: pd.Series) -> dict[str, Any]:
    weak_reasons = json.loads(incident_row["weak_label_reasons_json"])
    risk_score = min(float(incident_row["weak_label_score"]) / 10.0, 1.0)
    return {
        "risk_score": risk_score,
        "risk_band": _risk_band(risk_score),
        "top_signals": [{"label": item["rule"], "weight": item["weight"]} for item in weak_reasons],
        "counter_signals": [],
        "detector_labels": [item["rule"] for item in weak_reasons],
        "retrieved_patterns": _pattern_titles(incident_row, weak_reasons),
        "data_sources_used": ["demo_stream", "incident_builder", "weak_label_rules"],
    }


def _build_coverage_from_scenario(scenario: DemoScenario) -> dict[str, Any]:
    plan = scenario.coverage_plan or {}
    return {
        "completeness_level": plan.get("completeness_level", "medium"),
        "incompleteness_reasons": list(plan.get("incompleteness_reasons") or []),
        "checks": list(plan.get("checks") or []),
        "missing_sources": list(plan.get("missing_sources") or []),
    }


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
    }
    merged.update(overrides)
    return merged


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
