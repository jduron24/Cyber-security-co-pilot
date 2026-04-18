from __future__ import annotations

from .models import OperatorGuidance


def build_operator_guidance(incident: dict, detector_output: dict, completeness_assessment, recommended_action, review_next: list[str], operator_context=None, llm_adapter=None) -> OperatorGuidance:
    summary = _deterministic_summary(incident, detector_output, completeness_assessment, recommended_action, operator_context or {})
    if llm_adapter is not None:
        phrased = llm_adapter.run(
            "operator_summary",
            {"summary": summary, "recommended_action": recommended_action.reason, "completeness_warning": completeness_assessment.warning},
        )
        if phrased and phrased.get("summary"):
            summary = str(phrased["summary"])
    return OperatorGuidance(
        summary=summary,
        what_to_review_next=review_next[:5],
        double_check_prompt="Would you like to review other possible explanations before acting?",
    )


def _deterministic_summary(incident: dict, detector_output: dict, completeness_assessment, recommended_action, operator_context: dict) -> str:
    subject = incident.get("title") or "This incident"
    risk_band = detector_output.get("risk_band") or "unknown"
    summary = f"{subject} is currently assessed as {risk_band} risk. The recommended next step is {recommended_action.label.lower()} because {recommended_action.reason.lower()}"
    if completeness_assessment.warning:
        summary += f" {completeness_assessment.warning}"
    if operator_context.get("operator_type") != "non_expert":
        summary += " Review the structured evidence before taking disruptive action."
    return summary
