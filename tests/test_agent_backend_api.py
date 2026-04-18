from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

from agent_backend.main import app


def test_agent_service_health_and_query(monkeypatch):
    import agent_backend.api.agent as agent_api

    monkeypatch.setattr(
        agent_api,
        "run_agent_query",
        lambda incident_id, user_query, policy_version=None: {
            "incident_id": incident_id,
            "answer": f"Handled by agent service: {user_query}",
            "policy_version": policy_version,
        },
    )

    client = TestClient(app)

    health_response = client.get("/health")
    assert health_response.status_code == 200
    assert health_response.json() == {"status": "ok"}

    agent_response = client.post(
        "/incidents/incident-1/agent-query",
        json={"user_query": "What should I do next?"},
    )
    assert agent_response.status_code == 200
    assert "Handled by agent service" in agent_response.json()["result"]["answer"]
