from __future__ import annotations

from .actions import choose_actions
from .completeness import build_completeness_assessment, build_review_candidates
from .llm_adapter import LLMAdapter
from .models import DecisionSupportResult, to_dict, validate_coverage_input, validate_detector_input, validate_incident_input
from .hypotheses import build_hypotheses
from .policy import normalize_policy
from .summaries import build_operator_guidance
from .validation import validate_final_output


def generate_decision_support(incident: dict, detector_output: dict, coverage: dict, policy: dict, knowledge_context=None, operator_context=None, llm_adapter: LLMAdapter | None = None) -> dict:
    incident = validate_incident_input(incident)
    detector_output = validate_detector_input(detector_output)
    coverage = validate_coverage_input(coverage)
    policy_context = normalize_policy(policy)
    adapter = llm_adapter or LLMAdapter()
    completeness_assessment = build_completeness_assessment(coverage)
    recommended_action, alternative_actions = choose_actions(incident, detector_output, completeness_assessment.level.value, policy_context)
    hypotheses = build_hypotheses(incident, detector_output, coverage, adapter)
    review_next = build_review_candidates(coverage)
    guidance = build_operator_guidance(incident, detector_output, completeness_assessment, recommended_action, review_next, operator_context=operator_context, llm_adapter=adapter)
    result = DecisionSupportResult(
        incident_id=incident["incident_id"],
        recommended_action=recommended_action,
        alternative_actions=alternative_actions,
        alternative_hypotheses=hypotheses,
        completeness_assessment=completeness_assessment,
        operator_guidance=guidance,
    )
    assembled = {
        "decision_support_result": to_dict(result),
        "llm_trace": adapter.trace(),
        "validation": {"action_ids_valid": False, "schema_valid": False, "contains_recommended_action": False, "completeness_from_code_not_llm": False, "errors": []},
    }
    assembled["validation"] = to_dict(validate_final_output(assembled, policy_context))
    return assembled


def expand_decision_space(decision_support_result: dict, incident: dict, detector_output: dict, coverage: dict, policy: dict, knowledge_context=None, operator_context=None) -> dict:
    expanded = dict(decision_support_result)
    expanded["double_check_available"] = True
    return expanded
