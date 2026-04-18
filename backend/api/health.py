from __future__ import annotations

from fastapi import APIRouter

from backend.models import HealthResponse, MessageResponse

router = APIRouter(tags=["health"])


@router.get("/", response_model=MessageResponse)
def root() -> MessageResponse:
    return MessageResponse(message="Hello from Cyber Co-Pilot API")


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok")
