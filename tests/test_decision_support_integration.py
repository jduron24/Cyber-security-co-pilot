from src.decision_support_bridge import generate_decision_support_for_incident


def test_bridge_integration_for_real_incident():
    result = generate_decision_support_for_incident("incident_000000001", project_root=".")
    assert result["decision_support_result"]["incident_id"] == "incident_000000001"
    assert result["validation"]["action_ids_valid"] is True
