from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
from enum import Enum
from typing import Any

from .errors import InputValidationError


class CompletenessLevel(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class CheckStatus(str, Enum):
    CHECKED_SIGNAL_FOUND = "checked_signal_found"
    CHECKED_NO_SIGNAL = "checked_no_signal"
    NOT_CHECKED = "not_checked"
    DATA_UNAVAILABLE = "data_unavailable"


class Priority(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Reversibility(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class RecommendedAction:
    action_id: str
    label: str
    priority: Priority
    reason: str
    reversibility: Reversibility
    requires_human_approval: bool


@dataclass
class AlternativeAction:
    action_id: str
    label: str
    priority: Priority
    reason: str
    tradeoff: str


@dataclass
class AlternativeHypothesis:
    hypothesis_id: str
    label: str
    supporting_evidence: list[str]
    weakening_evidence: list[str]
    missing_evidence: list[str]
    confidence: Confidence


@dataclass
class CompletenessAssessment:
    level: CompletenessLevel
    warning: str | None
    reasons: list[str]


@dataclass
class OperatorGuidance:
    summary: str
    what_to_review_next: list[str]
    double_check_prompt: str


@dataclass
class DecisionSupportResult:
    incident_id: str
    recommended_action: RecommendedAction
    alternative_actions: list[AlternativeAction]
    alternative_hypotheses: list[AlternativeHypothesis]
    completeness_assessment: CompletenessAssessment
    operator_guidance: OperatorGuidance


@dataclass
class ValidationResult:
    action_ids_valid: bool
    schema_valid: bool
    contains_recommended_action: bool
    completeness_from_code_not_llm: bool
    errors: list[str] = field(default_factory=list)


def validate_incident_input(incident: dict[str, Any]) -> dict[str, Any]:
    _require_keys("incident", incident, ["incident_id", "title", "summary"])
    return incident


def validate_detector_input(detector_output: dict[str, Any]) -> dict[str, Any]:
    _require_keys("detector_output", detector_output, ["top_signals"])
    return detector_output


def validate_coverage_input(coverage: dict[str, Any]) -> dict[str, Any]:
    _require_keys("coverage", coverage, ["completeness_level", "incompleteness_reasons", "checks"])
    if coverage["completeness_level"] not in {item.value for item in CompletenessLevel}:
        raise InputValidationError("Invalid completeness_level.")
    for check in coverage["checks"]:
        if check["status"] not in {item.value for item in CheckStatus}:
            raise InputValidationError("Invalid coverage check status.")
    return coverage


def validate_policy_input(policy: dict[str, Any]) -> dict[str, Any]:
    _require_keys("policy", policy, ["allowed_actions"])
    if not policy["allowed_actions"]:
        raise InputValidationError("policy.allowed_actions must not be empty.")
    default_action = policy.get("default_non_expert_safe_action")
    if default_action and default_action not in policy["allowed_actions"]:
        raise InputValidationError("default_non_expert_safe_action must be in allowed_actions.")
    return policy


def to_dict(value: Any) -> Any:
    if is_dataclass(value):
        return {key: to_dict(item) for key, item in asdict(value).items()}
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, list):
        return [to_dict(item) for item in value]
    if isinstance(value, dict):
        return {key: to_dict(item) for key, item in value.items()}
    return value


def _require_keys(name: str, payload: dict[str, Any], required: list[str]) -> None:
    missing = [key for key in required if key not in payload]
    if missing:
        raise InputValidationError(f"{name} missing required fields: {', '.join(missing)}")
