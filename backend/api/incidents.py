from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from backend.dependencies import (
    as_http_exception,
    get_coverage_review_repositories,
    get_coverage_review_service,
    get_decision_support_service,
)
from backend.models import CoverageReviewResponse, DecisionSupportResponse, IncidentContextResponse
from src.repositories.service_bundles import CoverageReviewRepositoryBundle
from src.services.coverage_review_service import CoverageReviewAppService
from src.services.decision_support_app_service import DecisionSupportAppService

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get("/{incident_id}", response_model=IncidentContextResponse)
def get_incident_context(
    incident_id: str,
    repositories: CoverageReviewRepositoryBundle = Depends(get_coverage_review_repositories),
) -> IncidentContextResponse:
    incident = repositories.fetch_incident(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident not found: {incident_id}")
    return IncidentContextResponse(
        incident=incident,
        evidence_package=repositories.fetch_latest_evidence_package(incident_id),
        detector_result=repositories.fetch_latest_detector_result(incident_id),
        coverage_assessment=repositories.fetch_latest_coverage_assessment(incident_id),
        decision_support_result=_extract_decision_support_payload(repositories.fetch_latest_decision_support_result(incident_id)),
    )


@router.get("/{incident_id}/decision-support", response_model=DecisionSupportResponse)
def get_decision_support(
    incident_id: str,
    policy_version: str | None = None,
    service: DecisionSupportAppService = Depends(get_decision_support_service),
) -> DecisionSupportResponse:
    try:
        result = service.generate_for_incident(incident_id, policy_version=policy_version)
    except ValueError as exc:
        raise as_http_exception(exc) from exc
    return DecisionSupportResponse(result=result)


@router.get("/{incident_id}/coverage-review", response_model=CoverageReviewResponse)
def get_coverage_review(
    incident_id: str,
    policy_version: str | None = None,
    service: CoverageReviewAppService = Depends(get_coverage_review_service),
) -> CoverageReviewResponse:
    try:
        review = service.build_for_incident(incident_id, policy_version=policy_version)
    except ValueError as exc:
        raise as_http_exception(exc) from exc
    return CoverageReviewResponse(review=review)


def _extract_decision_support_payload(payload: dict | None) -> dict | None:
    if payload is None:
        return None
    if "result_json" in payload:
        return payload["result_json"]
    if "decision_support_result" in payload:
        return payload["decision_support_result"]
    return payload
