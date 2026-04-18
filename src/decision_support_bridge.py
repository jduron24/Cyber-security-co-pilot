from __future__ import annotations

from pathlib import Path
from typing import Any

import pandas as pd
import yaml

from decision_support.service import generate_decision_support

from .cyber_fraudlens_adapter import explain_incident, load_kb, load_model_payload
from .weak_label import load_label_rules


def build_decision_support_inputs(incident_row: dict[str, Any], explanation: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    pattern_titles = [item["title"] for item in explanation.get("pattern_kb_hits", [])]
    detector_labels = [item["rule"] for item in explanation.get("weak_label_reasons", [])]
    top_signals = [{"feature": item["display_feature"], "label": item["display_feature"], "contribution": item["contribution"]} for item in explanation.get("top_contributors", [])]
    incident = {
        "incident_id": incident_row["incident_id"],
        "title": f"Incident centered on {incident_row.get('top_event_name') or 'unknown activity'}",
        "summary": f"Actor {incident_row.get('actor_key')} produced {incident_row.get('event_count')} events.",
        "severity_hint": risk_band(explanation["ml_suspicion_proba"]),
        "start_time": stringify(incident_row.get("incident_start_time")),
        "end_time": stringify(incident_row.get("incident_end_time")),
        "primary_actor": {"actor_key": incident_row.get("actor_key")},
        "entities": {
            "primary_source_ip_address": incident_row.get("primary_source_ip_address"),
            "resource_types_seen": incident_row.get("resource_types_seen"),
            "user_agents_seen": incident_row.get("user_agents_seen"),
        },
        "event_sequence": split_pipe(incident_row.get("ordered_event_name_sequence")),
    }
    detector_output = {
        "risk_score": explanation["ml_suspicion_proba"],
        "risk_band": risk_band(explanation["ml_suspicion_proba"]),
        "top_signals": top_signals,
        "counter_signals": [],
        "detector_labels": detector_labels,
        "retrieved_patterns": pattern_titles,
        "data_sources_used": ["cloudtrail_incidents", "incident_model", "cyber_knowledge_base"],
    }
    coverage = build_coverage_input(incident_row)
    knowledge_context = {"playbook_snippets": pattern_titles, "domain_terms": explanation.get("feature_kb_hits", [])}
    operator_context = {"operator_type": "non_expert", "show_technical_details": False, "preferred_response_style": "plain_language"}
    return {
        "incident": incident,
        "detector_output": detector_output,
        "coverage": coverage,
        "policy": policy,
        "knowledge_context": knowledge_context,
        "operator_context": operator_context,
    }


def build_coverage_input(incident_row: dict[str, Any]) -> dict[str, Any]:
    reasons = ["Network telemetry was not checked."]
    checks = [{"name": "network_logs", "status": "not_checked", "detail": None}]
    if incident_row.get("resource_types_seen"):
        checks.append({"name": "resource_summary", "status": "checked_signal_found", "detail": None})
    else:
        reasons.append("No resource summary was available for this incident.")
        checks.append({"name": "resource_summary", "status": "data_unavailable", "detail": None})
    if incident_row.get("user_agents_seen"):
        checks.append({"name": "user_agent_context", "status": "checked_signal_found", "detail": None})
    else:
        reasons.append("User-agent context was missing.")
        checks.append({"name": "user_agent_context", "status": "data_unavailable", "detail": None})
    return {"completeness_level": "medium" if len(reasons) <= 2 else "low", "incompleteness_reasons": reasons, "checks": checks, "missing_sources": ["network_logs"]}


def risk_band(score: float) -> str:
    if score >= 0.75:
        return "high"
    if score >= 0.4:
        return "medium"
    return "low"


def split_pipe(value: Any) -> list[str]:
    return [part for part in str(value).split("|") if part] if value else []


def stringify(value: Any) -> str | None:
    if value is None:
        return None
    return value.isoformat() if hasattr(value, "isoformat") else str(value)


def generate_decision_support_for_incident(
    incident_id: str,
    project_root: str | Path = ".",
    incidents_path: str = "data/processed/incidents_scored.parquet",
    artifact_path: str = "artifacts/incident_suspicion_model.joblib",
    label_rules_path: str = "configs/incident_label_rules.yaml",
    decision_policy_path: str = "configs/decision_policy.yaml",
) -> dict[str, Any]:
    root = Path(project_root).resolve()
    incidents = pd.read_parquet(root / incidents_path)
    match = incidents.loc[incidents["incident_id"] == incident_id]
    if match.empty:
        raise ValueError(f"Incident not found: {incident_id}")
    model_payload = load_model_payload(root / artifact_path)
    label_rules = load_label_rules(root / label_rules_path)
    kb_df, vectorizer, matrix = load_kb(root)
    explanation = explain_incident(match.iloc[[0]], model_payload, label_rules, kb_df, vectorizer, matrix)
    policy = yaml.safe_load((root / decision_policy_path).read_text(encoding="utf-8")) or {}
    inputs = build_decision_support_inputs(match.iloc[0].to_dict(), explanation, policy)
    return generate_decision_support(**inputs)
