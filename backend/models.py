from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str


class MessageResponse(BaseModel):
    message: str


class SearchResponse(BaseModel):
    results: list[dict[str, Any]]


class IncidentListResponse(BaseModel):
    incidents: list[dict[str, Any]]


class IncidentContextResponse(BaseModel):
    incident: dict[str, Any]
    incident_events: list[dict[str, Any]] = []
    evidence_package: dict[str, Any] | None = None
    detector_result: dict[str, Any] | None = None
    coverage_assessment: dict[str, Any] | None = None
    decision_support_result: dict[str, Any] | None = None


class DecisionSupportResponse(BaseModel):
    result: dict[str, Any]


class CoverageReviewResponse(BaseModel):
    review: dict[str, Any]


class AgentQueryRequest(BaseModel):
    user_query: str = Field(..., min_length=1)
    policy_version: str | None = None


class AgentAuthStatusResponse(BaseModel):
    result: dict[str, Any]


class AgentQueryResponse(BaseModel):
    result: dict[str, Any]


class OperatorActionRequest(BaseModel):
    actor: dict[str, Any] | None = None
    rationale: str | None = None
    policy_version: str | None = None
    used_double_check: bool = False


class AlternativeActionRequest(OperatorActionRequest):
    action_id: str = Field(..., min_length=1)


class OperatorActionResponse(BaseModel):
    result: dict[str, Any]


class OperatorHistoryResponse(BaseModel):
    latest_decision: dict[str, Any] | None = None
    recent_decisions: list[dict[str, Any]]
    review_events: list[dict[str, Any]]
