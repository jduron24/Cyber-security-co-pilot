from decision_support.actions import choose_actions
from decision_support.policy import normalize_policy


def test_actions_stay_within_policy():
    policy = normalize_policy({"allowed_actions": ["collect_more_evidence", "escalate_to_expert"], "default_non_expert_safe_action": "collect_more_evidence"})
    recommended, alternatives = choose_actions(
        {"incident_id": "INC"},
        {"risk_score": 0.9, "detector_labels": ["privilege_change"], "retrieved_patterns": ["privilege"]},
        "low",
        policy,
    )
    assert recommended.action_id in policy.allowed_actions
    assert all(item.action_id in policy.allowed_actions for item in alternatives)
    assert recommended.action_id not in [item.action_id for item in alternatives]
