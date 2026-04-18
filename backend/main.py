from __future__ import annotations

from fastapi import FastAPI

from src.logging_utils import configure_logging

from .api.agent import router as agent_router
from .api.health import router as health_router
from .api.incidents import router as incidents_router
from .api.operator_actions import router as operator_actions_router
from .api.search import router as search_router


def create_app() -> FastAPI:
    configure_logging()
    app = FastAPI(title="Cyber Co-Pilot API")
    app.include_router(health_router)
    app.include_router(search_router)
    app.include_router(incidents_router)
    app.include_router(operator_actions_router)
    app.include_router(agent_router)
    return app


app = create_app()
