from src.services.decision_support_app_service import DecisionSupportAppService, assemble_decision_support_inputs


class FakeBundle:
    def __init__(self):
        self.saved = None

    def fetch_incident(self, incident_id: str):
        return {
            "incident_id": incident_id,
            "title": "Stored incident",
            "summary": "Stored summary",
            "severity_hint": "medium",
            "start_time": None,
            "end_time": None,
            "primary_actor": {"actor_key": "actor-1"},
            "entities": {"primary_source_ip_address": "1.2.3.4"},
            "event_sequence": ["DescribeInstances", "RunInstances"],
        }

    def fetch_latest_evidence_package(self, incident_id: str):
        return {
            "summary_json": {
                "playbook_snippets": ["Reconnaissance Burst"],
                "domain_terms": [{"title": "failure_ratio"}],
                "operator_context": {"operator_type": "non_expert"},
            }
        }

    def fetch_latest_detector_result(self, incident_id: str):
        return {
            "risk_score": 0.82,
            "risk_band": "high",
            "top_signals_json": [{"label": "High failure ratio"}],
            "counter_signals_json": [],
            "detector_labels_json": ["root_actor"],
            "retrieved_patterns_json": ["Root-Driven Sensitive Activity"],
            "data_sources_used_json": ["incident_model"],
            "model_type": "ebm",
            "explanation_json": {"prediction_probability": 0.82},
            "feature_contributions_json": [{"feature": "failure_ratio", "contribution": 0.34}],
        }

    def fetch_latest_coverage_assessment(self, incident_id: str):
        return {
            "completeness_level": "medium",
            "incompleteness_reasons_json": ["Network telemetry was not checked."],
            "checks_json": [{"name": "network_logs", "status": "not_checked"}],
            "missing_sources_json": ["network_logs"],
        }

    def fetch_policy_snapshot(self, policy_version=None):
        return {
            "policy_version": "v1",
            "policy_json": {
                "allowed_actions": [
                    "reset_credentials",
                    "temporary_access_lock",
                    "continue_monitoring",
                    "escalate_to_expert",
                    "collect_more_evidence",
                ],
                "high_impact_actions": ["reset_credentials", "temporary_access_lock"],
                "default_non_expert_safe_action": "collect_more_evidence",
            },
        }

    def save_decision_support_result(self, incident_id: str, result: dict, policy_version: str | None):
        self.saved = (incident_id, result, policy_version)


class FakeAlertingService:
    def __init__(self):
        self.calls = []

    def maybe_send_high_priority_alert(self, incident_record: dict, decision_support_result: dict):
        self.calls.append((incident_record, decision_support_result))
        return {"attempted": False, "reason": "test"}


def test_app_service_generates_and_persists_result():
    bundle = FakeBundle()
    alerting = FakeAlertingService()
    service = DecisionSupportAppService(bundle, alerting_service=alerting)
    result = service.generate_for_incident("INC-DB-1")
    assert result["decision_support_result"]["incident_id"] == "INC-DB-1"
    assert bundle.saved is not None
    assert bundle.saved[2] == "v1"
    assert len(alerting.calls) == 1


def test_assemble_inputs_carries_detector_explanation_fields():
    bundle = FakeBundle()
    detector_output = assemble_decision_support_inputs(
        incident_record=bundle.fetch_incident("INC-DB-1"),
        evidence_record=bundle.fetch_latest_evidence_package("INC-DB-1"),
        detector_record=bundle.fetch_latest_detector_result("INC-DB-1"),
        coverage_record=bundle.fetch_latest_coverage_assessment("INC-DB-1"),
        policy_record=bundle.fetch_policy_snapshot(),
    )["detector_output"]
    assert detector_output["model_type"] == "ebm"
    assert detector_output["explanation"]["prediction_probability"] == 0.82
    assert detector_output["feature_contributions"][0]["feature"] == "failure_ratio"
