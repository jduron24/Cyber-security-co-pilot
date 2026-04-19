from __future__ import annotations

from uuid import uuid4

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.logging_utils import configure_logging, reset_request_id, set_request_id

from .api.health import router as health_router
from .api.incidents import router as incidents_router
from .api.operator_actions import router as operator_actions_router
from .api.search import router as search_router


def create_app() -> FastAPI:
    configure_logging()
    app = FastAPI(title="Cyber Co-Pilot API")
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

    @app.middleware("http")
    async def attach_request_id(request, call_next):
        request_id = request.headers.get("x-request-id") or uuid4().hex[:12]
        token = set_request_id(request_id)
        try:
            response = await call_next(request)
        finally:
            reset_request_id(token)
        response.headers["X-Request-ID"] = request_id
        return response

    app.include_router(health_router)
    app.include_router(search_router)
    app.include_router(incidents_router)
    app.include_router(operator_actions_router)
    return app


app = create_app()
