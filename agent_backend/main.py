from __future__ import annotations

from fastapi import FastAPI

from src.logging_utils import configure_logging

from .api.agent import router as agent_router
from .api.health import router as health_router


def create_app() -> FastAPI:
    configure_logging()
    app = FastAPI(title="Cyber Co-Pilot Agent API")
    app.include_router(health_router)
    app.include_router(agent_router)
    return app


app = create_app()
