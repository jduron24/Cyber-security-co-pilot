from __future__ import annotations

from fastapi import APIRouter

from agent_backend.dependencies import as_http_exception, run_agent_query
from backend.models import AgentQueryRequest, AgentQueryResponse

router = APIRouter(prefix="/incidents/{incident_id}", tags=["agent"])


@router.post("/agent-query", response_model=AgentQueryResponse)
def agent_query(incident_id: str, request: AgentQueryRequest) -> AgentQueryResponse:
    try:
        result = run_agent_query(
            incident_id=incident_id,
            user_query=request.user_query,
            policy_version=request.policy_version,
        )
    except ValueError as exc:
        raise as_http_exception(exc) from exc
    return AgentQueryResponse(result=result)
