from __future__ import annotations

from .models import CompletenessAssessment, CompletenessLevel


def build_completeness_assessment(coverage: dict) -> CompletenessAssessment:
    level = CompletenessLevel(coverage["completeness_level"])
    reasons = list(coverage.get("incompleteness_reasons") or [])
    for source in coverage.get("missing_sources") or []:
        reason = f"Missing source: {source}"
        if reason not in reasons:
            reasons.append(reason)
    warning = None
    if level == CompletenessLevel.LOW:
        warning = "This recommendation may be incomplete because key checks or sources are missing."
    elif level == CompletenessLevel.MEDIUM and reasons:
        warning = "This recommendation may be incomplete."
    return CompletenessAssessment(level=level, warning=warning, reasons=reasons)


def build_review_candidates(coverage: dict) -> list[str]:
    suggestions = []
    for check in coverage.get("checks", []):
        if check["status"] in {"not_checked", "data_unavailable"}:
            suggestions.append(f"Review {check['name']}")
    for source in coverage.get("missing_sources") or []:
        suggestions.append(f"Review {source} if available")
    return suggestions[:5] or ["Review the incident sequence and top supporting signals"]
