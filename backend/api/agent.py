from __future__ import annotations

from fastapi import APIRouter
from fastapi import HTTPException

from backend.dependencies import run_agent_query
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
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return AgentQueryResponse(result=result)
