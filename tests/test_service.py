from decision_support.service import generate_decision_support


def test_service_happy_path():
    result = generate_decision_support(
        incident={"incident_id": "INC-1", "title": "Root activity", "summary": "Example incident"},
        detector_output={"risk_score": 0.8, "risk_band": "high", "top_signals": [{"label": "Root activity"}], "detector_labels": ["root_actor"], "retrieved_patterns": ["Root-Driven Sensitive Activity"]},
        coverage={"completeness_level": "medium", "incompleteness_reasons": ["Network telemetry was not checked."], "checks": [{"name": "network_logs", "status": "not_checked"}], "missing_sources": ["network_logs"]},
        policy={"allowed_actions": ["reset_credentials", "temporary_access_lock", "continue_monitoring", "escalate_to_expert", "collect_more_evidence"], "high_impact_actions": ["reset_credentials", "temporary_access_lock"], "default_non_expert_safe_action": "collect_more_evidence"},
        operator_context={"operator_type": "non_expert"},
    )
    assert result["validation"]["schema_valid"] is True
    assert result["decision_support_result"]["recommended_action"]["action_id"]


def test_service_deterministic_repeated_runs():
    kwargs = dict(
        incident={"incident_id": "INC-1", "title": "Root activity", "summary": "Example incident"},
        detector_output={"risk_score": 0.2, "risk_band": "low", "top_signals": [], "detector_labels": [], "retrieved_patterns": []},
        coverage={"completeness_level": "low", "incompleteness_reasons": ["Missing logs"], "checks": [{"name": "network", "status": "not_checked"}]},
        policy={"allowed_actions": ["continue_monitoring", "collect_more_evidence"], "default_non_expert_safe_action": "collect_more_evidence"},
    )
    first = generate_decision_support(**kwargs)
    second = generate_decision_support(**kwargs)
    assert first == second
