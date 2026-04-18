from __future__ import annotations

from .models import AlternativeAction, Priority, RecommendedAction, Reversibility
from .policy import PolicyContext


def choose_actions(incident: dict, detector_output: dict, completeness_level: str, policy: PolicyContext):
    scored_actions = []
    for action_id in policy.allowed_actions:
        meta = policy.metadata(action_id)
        score, reason = _score_action(action_id, detector_output, completeness_level, policy)
        scored_actions.append((score, action_id, meta, reason))
    scored_actions.sort(key=lambda item: (-item[0], item[1]))
    _, best_id, best_meta, best_reason = scored_actions[0]
    recommended = RecommendedAction(
        action_id=best_id,
        label=best_meta["label"],
        priority=Priority(best_meta["priority"]),
        reason=best_reason,
        reversibility=Reversibility(best_meta["reversibility"]),
        requires_human_approval=bool(best_meta["requires_human_approval"]),
    )
    alternatives = [
        AlternativeAction(
            action_id=action_id,
            label=meta["label"],
            priority=Priority(meta["priority"]),
            reason=reason,
            tradeoff=_tradeoff(action_id),
        )
        for _, action_id, meta, reason in scored_actions[1:4]
    ]
    return recommended, alternatives


def _score_action(action_id: str, detector_output: dict, completeness_level: str, policy: PolicyContext):
    score = 0.0
    risk_score = float(detector_output.get("risk_score") or 0.0)
    labels = set(detector_output.get("detector_labels") or [])
    patterns = " ".join(detector_output.get("retrieved_patterns") or []).lower()
    if action_id == "continue_monitoring":
        score += 1.0 - risk_score
    if action_id == "collect_more_evidence":
        score += 2.0 if completeness_level == "low" else 0.5
    if action_id == "escalate_to_expert":
        score += 1.5 if completeness_level == "low" else 0.5
    if action_id == "reset_credentials":
        if {"privilege_change", "root_actor"} & labels or "privilege" in patterns:
            score += 2.5
        score += risk_score
    if action_id == "temporary_access_lock":
        if risk_score >= 0.7:
            score += 2.0
        if "resource creation" in patterns or "root" in patterns:
            score += 1.5
    if completeness_level == "low" and policy.is_high_impact(action_id):
        score -= 1.5
    score -= policy.metadata(action_id)["disruption"] * 0.1
    return score, _reason_for_action(action_id)


def _reason_for_action(action_id: str) -> str:
    reasons = {
        "collect_more_evidence": "Important checks or sources are still missing.",
        "escalate_to_expert": "The incident needs expert review because the risk or missing context may exceed non-expert handling.",
        "reset_credentials": "Credential-focused containment is safer because the incident includes signals consistent with elevated account misuse.",
        "temporary_access_lock": "Temporary containment is justified because the risk appears high and ongoing access may increase impact.",
        "continue_monitoring": "Current evidence supports continued review without immediate disruptive action.",
    }
    return reasons[action_id]


def _tradeoff(action_id: str) -> str:
    if action_id in {"reset_credentials", "temporary_access_lock"}:
        return "This may disrupt legitimate access while evidence is still being reviewed."
    if action_id == "collect_more_evidence":
        return "This may delay a stronger response if the incident is already active."
    if action_id == "escalate_to_expert":
        return "This adds a handoff step but reduces the chance of overreacting."
    return "This preserves business continuity but may leave some risk unresolved."
