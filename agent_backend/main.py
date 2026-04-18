from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.logging_utils import configure_logging

from .api.agent import router as agent_router
from .api.health import router as health_router


def create_app() -> FastAPI:
    configure_logging()
    app = FastAPI(title="Cyber Co-Pilot Agent API")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://10.255.250.128:3000",
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(health_router)
    app.include_router(agent_router)
    return app


app = create_app()
