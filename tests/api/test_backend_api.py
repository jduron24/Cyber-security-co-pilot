from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

from backend.dependencies import (
    get_coverage_review_repositories,
    get_coverage_review_service,
    get_decision_support_service,
    get_knowledge_base_repository,
    get_operator_decision_service,
)
from backend.main import app


class FakeKnowledgeBaseRepository:
    def search(self, query: str, limit: int = 5):
        return [{"title": "T1110", "content": query, "score": 0.9}][:limit]


class FakeCoverageReviewRepositories:
    def list_incidents(self, limit: int = 25):
        return [
            {"incident_id": "incident-2", "title": "Stored incident 2", "severity_hint": "medium"},
            {"incident_id": "incident-1", "title": "Stored incident", "severity_hint": "high"},
        ][:limit]

    def fetch_incident(self, incident_id: str):
        return {"incident_id": incident_id, "title": "Stored incident"}

    def fetch_latest_evidence_package(self, incident_id: str):
        return {"summary_json": {"summary": "Stored summary"}}

    def fetch_latest_detector_result(self, incident_id: str):
        return {"risk_score": 0.8, "risk_band": "high"}

    def fetch_latest_coverage_assessment(self, incident_id: str):
        return {"completeness_level": "medium", "checks_json": []}

    def fetch_latest_decision_support_result(self, incident_id: str):
        return {"result_json": {"recommended_action": {"action_id": "collect_more_evidence"}}}


class FakeDecisionSupportService:
    def generate_for_incident(self, incident_id: str, policy_version: str | None = None):
        return {"decision_support_result": {"incident_id": incident_id, "recommended_action": {"action_id": "reset_credentials"}}}


class FakeCoverageReviewService:
    def build_for_incident(self, incident_id: str, policy_version: str | None = None):
        return {
            "incident_id": incident_id,
            "recommended_action": {"action_id": "reset_credentials"},
            "alternative_actions": [{"action_id": "escalate_to_expert"}],
            "coverage_status_by_category": [{"category": "network", "status": "not_checked"}],
            "double_check": {"available": True, "candidates": ["Review network logs"]},
            "decision_risk_note": "Review missing checks.",
        }


class FakeOperatorDecisionService:
    def approve_recommendation(self, incident_id: str, **kwargs):
        return {"incident_id": incident_id, "decision_type": "approve_recommendation"}

    def choose_alternative(self, incident_id: str, action_id: str, **kwargs):
        return {"incident_id": incident_id, "decision_type": "choose_alternative", "action_id": action_id}

    def escalate(self, incident_id: str, **kwargs):
        return {"incident_id": incident_id, "decision_type": "escalate"}

    def request_more_analysis(self, incident_id: str, **kwargs):
        return {"incident_id": incident_id, "decision_type": "request_more_analysis"}


class FakeOperatorDecisionRepositories:
    def fetch_latest_operator_decision(self, incident_id: str):
        return {"incident_id": incident_id, "decision_type": "approve_recommendation"}

    def fetch_recent_operator_decisions(self, incident_id: str, limit: int = 10):
        return [{"incident_id": incident_id, "decision_type": "approve_recommendation"}]

    def fetch_recent_review_events(self, incident_id: str, limit: int = 10):
        return [{"incident_id": incident_id, "event_type": "double_check_requested"}]


def test_backend_health_and_search_routes(monkeypatch):
    app.dependency_overrides[get_knowledge_base_repository] = lambda: FakeKnowledgeBaseRepository()
    client = TestClient(app)

    assert client.get("/health").json() == {"status": "ok"}
    response = client.get("/search", params={"q": "brute force login", "limit": 1})
    assert response.status_code == 200
    assert response.json()["results"][0]["title"] == "T1110"

    app.dependency_overrides.clear()


def test_backend_incident_routes(monkeypatch):
    app.dependency_overrides[get_coverage_review_repositories] = lambda: FakeCoverageReviewRepositories()
    app.dependency_overrides[get_decision_support_service] = lambda: FakeDecisionSupportService()
    app.dependency_overrides[get_coverage_review_service] = lambda: FakeCoverageReviewService()
    client = TestClient(app)

    list_response = client.get("/incidents", params={"limit": 2})
    assert list_response.status_code == 200
    assert list_response.json()["incidents"][0]["incident_id"] == "incident-2"

    incident_response = client.get("/incidents/incident-1")
    assert incident_response.status_code == 200
    assert incident_response.json()["incident"]["incident_id"] == "incident-1"

    decision_response = client.get("/incidents/incident-1/decision-support")
    assert decision_response.status_code == 200
    assert decision_response.json()["result"]["decision_support_result"]["recommended_action"]["action_id"] == "reset_credentials"

    review_response = client.get("/incidents/incident-1/coverage-review")
    assert review_response.status_code == 200
    assert review_response.json()["review"]["coverage_status_by_category"][0]["category"] == "network"

    app.dependency_overrides.clear()


def test_backend_operator_routes():
    app.dependency_overrides[get_operator_decision_service] = lambda: FakeOperatorDecisionService()
    from backend.dependencies import get_operator_decision_repositories

    app.dependency_overrides[get_operator_decision_repositories] = lambda: FakeOperatorDecisionRepositories()
    client = TestClient(app)

    approve_response = client.post("/incidents/incident-1/approve", json={"rationale": "Looks valid"})
    assert approve_response.status_code == 200
    assert approve_response.json()["result"]["decision_type"] == "approve_recommendation"

    alt_response = client.post("/incidents/incident-1/alternative", json={"action_id": "escalate_to_expert"})
    assert alt_response.status_code == 200
    assert alt_response.json()["result"]["decision_type"] == "choose_alternative"

    history_response = client.get("/incidents/incident-1/operator-history")
    assert history_response.status_code == 200
    assert history_response.json()["latest_decision"]["decision_type"] == "approve_recommendation"
    assert history_response.json()["review_events"][0]["event_type"] == "double_check_requested"

    app.dependency_overrides.clear()
