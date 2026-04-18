from __future__ import annotations

from .errors import OutputValidationError
from .models import ValidationResult
from .policy import PolicyContext


def validate_final_output(result: dict, policy: PolicyContext) -> ValidationResult:
    errors = []
    dsr = result.get("decision_support_result") or {}
    recommended = dsr.get("recommended_action") or {}
    alternatives = dsr.get("alternative_actions") or []
    completeness = dsr.get("completeness_assessment") or {}
    action_ids = [recommended.get("action_id")] + [item.get("action_id") for item in alternatives]
    action_ids_valid = all(action_id in policy.allowed_actions for action_id in action_ids if action_id)
    if not action_ids_valid:
        errors.append("Out-of-policy action_id detected.")
    schema_valid = bool(dsr and result.get("llm_trace") is not None and result.get("validation") is not None)
    if not schema_valid:
        errors.append("Required output blocks are missing.")
    contains_recommended_action = bool(recommended.get("action_id"))
    if not contains_recommended_action:
        errors.append("Missing recommended action.")
    completeness_from_code_not_llm = completeness.get("level") in {"high", "medium", "low"}
    if not completeness_from_code_not_llm:
        errors.append("Invalid completeness assessment.")
    if completeness.get("level") == "low" and not completeness.get("reasons"):
        errors.append("Low completeness requires reasons.")
    validation = ValidationResult(
        action_ids_valid=action_ids_valid,
        schema_valid=schema_valid,
        contains_recommended_action=contains_recommended_action,
        completeness_from_code_not_llm=completeness_from_code_not_llm,
        errors=errors,
    )
    if errors:
        raise OutputValidationError("; ".join(errors))
    return validation
