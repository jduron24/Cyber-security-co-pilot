from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

from agent_backend.main import create_app


def test_agent_backend_app_exposes_health_auth_and_cors(monkeypatch):
    import agent_backend.api.agent as agent_api

    monkeypatch.setattr(
        agent_api,
        "get_agent_auth_status",
        lambda: {
            "auth_mode": "mock",
            "base_url": "https://example.test/v1",
            "model": "test-model",
            "is_production_ready": False,
        },
    )

    app = create_app()
    client = TestClient(app)

    health = client.get("/health")
    assert health.status_code == 200

    auth = client.get("/incidents/incident-1/agent-auth")
    assert auth.status_code == 200
    assert auth.json()["result"]["incident_id"] == "incident-1"
    assert auth.json()["result"]["auth_mode"] == "mock"
    assert auth.headers["x-request-id"]

    preflight = client.options(
        "/incidents/incident-1/agent-query",
        headers={
            "Origin": "http://127.0.0.1:3000",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert preflight.status_code == 200
    assert preflight.headers["access-control-allow-origin"] == "http://127.0.0.1:3000"


def test_agent_backend_app_respects_incoming_request_id_header(monkeypatch):
    import agent_backend.api.agent as agent_api

    monkeypatch.setattr(
        agent_api,
        "run_agent_query",
        lambda incident_id, user_query, policy_version=None: {"incident_id": incident_id, "answer": user_query},
    )

    client = TestClient(create_app())
    response = client.post(
        "/incidents/incident-1/agent-query",
        json={"user_query": "What happened?"},
        headers={"X-Request-ID": "req-agent-1"},
    )

    assert response.status_code == 200
    assert response.headers["x-request-id"] == "req-agent-1"
