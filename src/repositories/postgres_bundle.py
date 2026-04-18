from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from .decision_support_repo import DecisionSupportResultsRepository
from .detector_repo import DetectorRepository
from .evidence_repo import EvidenceRepository
from .incident_notification_repo import IncidentNotificationRepository
from .incidents_repo import IncidentsRepository
from .operator_decision_repo import OperatorDecisionRepository
from .policy_repo import PolicyRepository


@dataclass
class PostgresRepositoryBundle:
    incidents_repo: IncidentsRepository
    evidence_repo: EvidenceRepository
    detector_repo: DetectorRepository
    policy_repo: PolicyRepository
    decision_support_repo: DecisionSupportResultsRepository
    operator_decision_repo: OperatorDecisionRepository
    incident_notification_repo: IncidentNotificationRepository

    @classmethod
    def from_connection_factory(cls, connection_factory: Callable[[], Any]) -> "PostgresRepositoryBundle":
        return cls(
            incidents_repo=IncidentsRepository(connection_factory),
            evidence_repo=EvidenceRepository(connection_factory),
            detector_repo=DetectorRepository(connection_factory),
            policy_repo=PolicyRepository(connection_factory),
            decision_support_repo=DecisionSupportResultsRepository(connection_factory),
            operator_decision_repo=OperatorDecisionRepository(connection_factory),
            incident_notification_repo=IncidentNotificationRepository(connection_factory),
        )

    def fetch_incident(self, incident_id: str):
        return self.incidents_repo.fetch_incident(incident_id)

    def fetch_latest_evidence_package(self, incident_id: str):
        return self.evidence_repo.fetch_latest_evidence_package(incident_id)

    def fetch_latest_detector_result(self, incident_id: str):
        return self.detector_repo.fetch_latest_detector_result(incident_id)

    def fetch_latest_coverage_assessment(self, incident_id: str):
        return self.detector_repo.fetch_latest_coverage_assessment(incident_id)

    def fetch_policy_snapshot(self, policy_version: str | None = None):
        return self.policy_repo.fetch_policy_snapshot(policy_version)

    def save_decision_support_result(self, incident_id: str, result: dict, policy_version: str | None):
        self.decision_support_repo.save_decision_support_result(incident_id, result, policy_version)

    def fetch_latest_decision_support_result(self, incident_id: str):
        return self.decision_support_repo.fetch_latest_decision_support_result(incident_id)

    def save_operator_decision(self, **kwargs):
        self.operator_decision_repo.save_operator_decision(**kwargs)

    def save_review_event(self, **kwargs):
        self.operator_decision_repo.save_review_event(**kwargs)

    def fetch_latest_operator_decision(self, incident_id: str):
        return self.operator_decision_repo.fetch_latest_operator_decision(incident_id)

    def fetch_incident_notification_by_dedupe_key(self, dedupe_key: str):
        return self.incident_notification_repo.fetch_notification_by_dedupe_key(dedupe_key)

    def save_incident_notification(self, **kwargs):
        self.incident_notification_repo.save_notification(**kwargs)
