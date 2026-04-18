from __future__ import annotations

from fastapi import APIRouter, Depends

from backend.dependencies import as_http_exception, get_operator_decision_service
from backend.models import AlternativeActionRequest, OperatorActionRequest, OperatorActionResponse
from src.services.operator_decision_service import OperatorDecisionAppService

router = APIRouter(prefix="/incidents/{incident_id}", tags=["operator-actions"])


@router.post("/approve", response_model=OperatorActionResponse)
def approve_recommendation(
    incident_id: str,
    request: OperatorActionRequest,
    service: OperatorDecisionAppService = Depends(get_operator_decision_service),
) -> OperatorActionResponse:
    try:
        result = service.approve_recommendation(
            incident_id=incident_id,
            actor=request.actor,
            rationale=request.rationale,
            policy_version=request.policy_version,
            used_double_check=request.used_double_check,
        )
    except ValueError as exc:
        raise as_http_exception(exc) from exc
    return OperatorActionResponse(result=result)


@router.post("/alternative", response_model=OperatorActionResponse)
def choose_alternative(
    incident_id: str,
    request: AlternativeActionRequest,
    service: OperatorDecisionAppService = Depends(get_operator_decision_service),
) -> OperatorActionResponse:
    try:
        result = service.choose_alternative(
            incident_id=incident_id,
            action_id=request.action_id,
            actor=request.actor,
            rationale=request.rationale,
            policy_version=request.policy_version,
            used_double_check=request.used_double_check,
        )
    except ValueError as exc:
        raise as_http_exception(exc) from exc
    return OperatorActionResponse(result=result)


@router.post("/escalate", response_model=OperatorActionResponse)
def escalate(
    incident_id: str,
    request: OperatorActionRequest,
    service: OperatorDecisionAppService = Depends(get_operator_decision_service),
) -> OperatorActionResponse:
    try:
        result = service.escalate(
            incident_id=incident_id,
            actor=request.actor,
            rationale=request.rationale,
            policy_version=request.policy_version,
            used_double_check=request.used_double_check,
        )
    except ValueError as exc:
        raise as_http_exception(exc) from exc
    return OperatorActionResponse(result=result)


@router.post("/double-check", response_model=OperatorActionResponse)
def request_more_analysis(
    incident_id: str,
    request: OperatorActionRequest,
    service: OperatorDecisionAppService = Depends(get_operator_decision_service),
) -> OperatorActionResponse:
    try:
        result = service.request_more_analysis(
            incident_id=incident_id,
            actor=request.actor,
            rationale=request.rationale,
            policy_version=request.policy_version,
            used_double_check=request.used_double_check or True,
        )
    except ValueError as exc:
        raise as_http_exception(exc) from exc
    return OperatorActionResponse(result=result)
