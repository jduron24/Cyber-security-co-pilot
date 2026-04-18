from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from decision_support.service import generate_decision_support
from src.logging_utils import get_logger
from .alerting_service import AlertingService
from .dtos import CoverageRecordDTO, DecisionSupportInputsDTO, DetectorRecordDTO, EvidenceRecordDTO, IncidentRecordDTO, PolicyRecordDTO

logger = get_logger(__name__)


class RepositoryBundle(Protocol):
    def fetch_incident(self, incident_id: str) -> dict[str, Any] | None: ...
    def fetch_latest_evidence_package(self, incident_id: str) -> dict[str, Any] | None: ...
    def fetch_latest_detector_result(self, incident_id: str) -> dict[str, Any] | None: ...
    def fetch_latest_coverage_assessment(self, incident_id: str) -> dict[str, Any] | None: ...
    def fetch_policy_snapshot(self, policy_version: str | None = None) -> dict[str, Any] | None: ...
    def save_decision_support_result(self, incident_id: str, result: dict[str, Any], policy_version: str | None) -> None: ...


@dataclass
class DecisionSupportAppService:
    repositories: RepositoryBundle
    alerting_service: AlertingService | None = None

    def generate_for_incident(self, incident_id: str, policy_version: str | None = None) -> dict[str, Any]:
        logger.info("Generating decision support incident_id=%s policy_version=%s", incident_id, policy_version)
        incident_record = self.repositories.fetch_incident(incident_id)
        evidence_record = self.repositories.fetch_latest_evidence_package(incident_id)
        detector_record = self.repositories.fetch_latest_detector_result(incident_id)
        coverage_record = self.repositories.fetch_latest_coverage_assessment(incident_id)
        policy_record = self.repositories.fetch_policy_snapshot(policy_version)

        if incident_record is None:
            raise ValueError(f"Incident not found: {incident_id}")
        if detector_record is None:
            raise ValueError(f"Detector result not found: {incident_id}")
        if coverage_record is None:
            raise ValueError(f"Coverage assessment not found: {incident_id}")
        if policy_record is None:
            raise ValueError("Policy snapshot not found.")

        inputs = assemble_decision_support_inputs(
            incident_record=incident_record,
            evidence_record=evidence_record,
            detector_record=detector_record,
            coverage_record=coverage_record,
            policy_record=policy_record,
        )
        logger.debug("Decision support inputs assembled incident_id=%s has_evidence=%s", incident_id, evidence_record is not None)
        result = generate_decision_support(**inputs)
        self.repositories.save_decision_support_result(incident_id, result, policy_record["policy_version"])
        logger.info("Decision support saved incident_id=%s policy_version=%s", incident_id, policy_record["policy_version"])
        if self.alerting_service is not None:
            try:
                alert_result = self.alerting_service.maybe_send_high_priority_alert(incident_record, result)
                logger.info(
                    "Alerting evaluated incident_id=%s attempted=%s sent_count=%s skipped_count=%s",
                    incident_id,
                    alert_result.get("attempted"),
                    alert_result.get("sent_count", 0),
                    alert_result.get("skipped_count", 0),
                )
            except Exception:
                logger.exception("High-priority alerting failed incident_id=%s", incident_id)
        return result


def assemble_decision_support_inputs(
    incident_record: dict[str, Any],
    evidence_record: dict[str, Any] | None,
    detector_record: dict[str, Any],
    coverage_record: dict[str, Any],
    policy_record: dict[str, Any],
) -> dict[str, Any]:
    dto = assemble_decision_support_inputs_dto(
        IncidentRecordDTO.from_record(incident_record),
        EvidenceRecordDTO.from_record(evidence_record),
        DetectorRecordDTO.from_record(detector_record),
        CoverageRecordDTO.from_record(coverage_record),
        PolicyRecordDTO.from_record(policy_record),
    )
    return dto.to_kwargs()


def assemble_decision_support_inputs_dto(
    incident_record: IncidentRecordDTO,
    evidence_record: EvidenceRecordDTO | None,
    detector_record: DetectorRecordDTO,
    coverage_record: CoverageRecordDTO,
    policy_record: PolicyRecordDTO,
) -> DecisionSupportInputsDTO:
    logger.debug("Assembling decision support DTO incident_id=%s", incident_record.incident_id)
    summary_json = evidence_record.summary_json if evidence_record else {}
    incident = {
        "incident_id": incident_record.incident_id,
        "title": incident_record.title or summary_json.get("title") or f"Incident {incident_record.incident_id}",
        "summary": incident_record.summary or summary_json.get("summary") or "Stored incident context",
        "severity_hint": incident_record.severity_hint,
        "start_time": _stringify(incident_record.start_time),
        "end_time": _stringify(incident_record.end_time),
        "primary_actor": incident_record.primary_actor,
        "entities": incident_record.entities,
        "event_sequence": list(incident_record.event_sequence or summary_json.get("event_sequence") or []),
    }
    detector_output = {
        "risk_score": detector_record.risk_score,
        "risk_band": detector_record.risk_band,
        "top_signals": list(detector_record.top_signals),
        "counter_signals": list(detector_record.counter_signals),
        "detector_labels": list(detector_record.detector_labels),
        "retrieved_patterns": list(detector_record.retrieved_patterns),
        "data_sources_used": list(detector_record.data_sources_used),
        "model_type": detector_record.model_type,
        "explanation": dict(detector_record.explanation),
        "feature_contributions": list(detector_record.feature_contributions),
    }
    coverage = coverage_record.to_decision_support_input()
    policy = dict(policy_record.policy_json)
    knowledge_context = {
        "playbook_snippets": list(summary_json.get("playbook_snippets") or []),
        "domain_terms": list(summary_json.get("domain_terms") or []),
    }
    operator_context = dict(summary_json.get("operator_context") or {"operator_type": "non_expert"})
    return DecisionSupportInputsDTO(
        incident=incident,
        detector_output=detector_output,
        coverage=coverage,
        policy=policy,
        knowledge_context=knowledge_context,
        operator_context=operator_context,
    )


def _stringify(value: Any) -> str | None:
    if value is None:
        return None
    return value.isoformat() if hasattr(value, "isoformat") else str(value)
