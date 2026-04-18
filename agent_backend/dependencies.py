from __future__ import annotations

import os
from fastapi import HTTPException

from src.logging_utils import get_logger
from src.services.agent_app_service import query_incident_agent

logger = get_logger(__name__)


def get_agent_env() -> dict[str, str]:
    env = dict(os.environ)
    if env.get("DATABASE_URL") and not env.get("POSTGRES_DSN"):
        env["POSTGRES_DSN"] = env["DATABASE_URL"]
    return env


def run_agent_query(incident_id: str, user_query: str, policy_version: str | None = None) -> dict:
    logger.info("Agent service query incident_id=%s", incident_id)
    return query_incident_agent(
        incident_id=incident_id,
        user_query=user_query,
        policy_version=policy_version,
        env=get_agent_env(),
    )


def as_http_exception(exc: ValueError) -> HTTPException:
    message = str(exc)
    status_code = 400
    if "not found" in message.lower():
        status_code = 404
    return HTTPException(status_code=status_code, detail=message)
