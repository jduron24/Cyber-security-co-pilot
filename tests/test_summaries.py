from decision_support.models import CompletenessAssessment, CompletenessLevel, Priority, RecommendedAction, Reversibility
from decision_support.summaries import build_operator_guidance


def test_non_expert_summary_mentions_recommendation():
    guidance = build_operator_guidance(
        {"title": "Root activity incident"},
        {"risk_band": "high"},
        CompletenessAssessment(level=CompletenessLevel.MEDIUM, warning="This recommendation may be incomplete.", reasons=["Reason"]),
        RecommendedAction(
            action_id="collect_more_evidence",
            label="Collect more evidence",
            priority=Priority.MEDIUM,
            reason="important checks are missing",
            reversibility=Reversibility.HIGH,
            requires_human_approval=False,
        ),
        ["Review network logs"],
        operator_context={"operator_type": "non_expert"},
    )
    assert "collect more evidence" in guidance.summary.lower()
