from decision_support.policy import normalize_policy
from decision_support.validation import validate_final_output


def test_out_of_policy_action_causes_failure():
    policy = normalize_policy({"allowed_actions": ["collect_more_evidence"]})
    payload = {
        "decision_support_result": {
            "recommended_action": {"action_id": "reset_credentials"},
            "alternative_actions": [],
            "completeness_assessment": {"level": "medium", "reasons": []},
        },
        "llm_trace": {},
        "validation": {},
    }
    try:
        validate_final_output(payload, policy)
    except Exception as exc:
        assert "Out-of-policy" in str(exc)
    else:
        raise AssertionError("Expected validation failure")
