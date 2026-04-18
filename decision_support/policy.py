from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .errors import InputValidationError
from .models import validate_policy_input


ACTION_METADATA = {
    "reset_credentials": {"label": "Reset credentials", "priority": "high", "reversibility": "medium", "disruption": 3, "requires_human_approval": True},
    "temporary_access_lock": {"label": "Temporarily lock access", "priority": "high", "reversibility": "high", "disruption": 3, "requires_human_approval": True},
    "continue_monitoring": {"label": "Continue monitoring", "priority": "low", "reversibility": "high", "disruption": 1, "requires_human_approval": False},
    "escalate_to_expert": {"label": "Escalate to expert", "priority": "medium", "reversibility": "high", "disruption": 1, "requires_human_approval": False},
    "collect_more_evidence": {"label": "Collect more evidence", "priority": "medium", "reversibility": "high", "disruption": 1, "requires_human_approval": False},
}


@dataclass
class PolicyContext:
    allowed_actions: list[str]
    high_impact_actions: set[str]
    default_non_expert_safe_action: str | None
    escalation_rules: list[str]

    def is_high_impact(self, action_id: str) -> bool:
        return action_id in self.high_impact_actions

    def metadata(self, action_id: str) -> dict[str, Any]:
        if action_id not in ACTION_METADATA:
            raise InputValidationError(f"Unknown action_id metadata: {action_id}")
        return ACTION_METADATA[action_id]


def normalize_policy(policy: dict[str, Any]) -> PolicyContext:
    validate_policy_input(policy)
    unsupported = [action for action in policy["allowed_actions"] if action not in ACTION_METADATA]
    if unsupported:
        raise InputValidationError(f"Unsupported allowed_actions: {', '.join(unsupported)}")
    return PolicyContext(
        allowed_actions=list(policy["allowed_actions"]),
        high_impact_actions=set(policy.get("high_impact_actions") or []),
        default_non_expert_safe_action=policy.get("default_non_expert_safe_action"),
        escalation_rules=list(policy.get("escalation_rules") or []),
    )
