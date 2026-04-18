from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class IncidentRecordDTO:
    incident_id: str
    title: str | None = None
    summary: str | None = None
    severity_hint: str | None = None
    start_time: Any = None
    end_time: Any = None
    primary_actor: dict[str, Any] | None = None
    entities: dict[str, Any] | None = None
    event_sequence: list[str] = field(default_factory=list)

    @classmethod
    def from_record(cls, record: dict[str, Any]) -> "IncidentRecordDTO":
        return cls(
            incident_id=str(record["incident_id"]),
            title=record.get("title"),
            summary=record.get("summary"),
            severity_hint=record.get("severity_hint"),
            start_time=record.get("start_time"),
            end_time=record.get("end_time"),
            primary_actor=dict(record.get("primary_actor") or {}) or None,
            entities=dict(record.get("entities") or {}) or None,
            event_sequence=list(record.get("event_sequence") or []),
        )


@dataclass(frozen=True)
class EvidenceRecordDTO:
    summary_json: dict[str, Any] = field(default_factory=dict)
    provenance_json: dict[str, Any] = field(default_factory=dict)
    raw_refs_json: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_record(cls, record: dict[str, Any] | None) -> "EvidenceRecordDTO | None":
        if record is None:
            return None
        return cls(
            summary_json=dict(record.get("summary_json") or {}),
            provenance_json=dict(record.get("provenance_json") or {}),
            raw_refs_json=dict(record.get("raw_refs_json") or {}),
        )


@dataclass(frozen=True)
class DetectorRecordDTO:
    risk_score: float | None = None
    risk_band: str | None = None
    top_signals: list[dict[str, Any]] = field(default_factory=list)
    counter_signals: list[dict[str, Any]] = field(default_factory=list)
    detector_labels: list[Any] = field(default_factory=list)
    retrieved_patterns: list[Any] = field(default_factory=list)
    data_sources_used: list[Any] = field(default_factory=list)
    model_type: str | None = None
    explanation: dict[str, Any] = field(default_factory=dict)
    feature_contributions: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_record(cls, record: dict[str, Any]) -> "DetectorRecordDTO":
        return cls(
            risk_score=record.get("risk_score"),
            risk_band=record.get("risk_band"),
            top_signals=list(record.get("top_signals_json") or record.get("top_signals") or []),
            counter_signals=list(record.get("counter_signals_json") or record.get("counter_signals") or []),
            detector_labels=list(record.get("detector_labels_json") or record.get("detector_labels") or []),
            retrieved_patterns=list(record.get("retrieved_patterns_json") or record.get("retrieved_patterns") or []),
            data_sources_used=list(record.get("data_sources_used_json") or record.get("data_sources_used") or []),
            model_type=record.get("model_type"),
            explanation=dict(record.get("explanation_json") or record.get("explanation") or {}),
            feature_contributions=list(record.get("feature_contributions_json") or record.get("feature_contributions") or []),
        )


@dataclass(frozen=True)
class CoverageRecordDTO:
    completeness_level: str
    incompleteness_reasons: list[str] = field(default_factory=list)
    checks: list[dict[str, Any]] = field(default_factory=list)
    missing_sources: list[str] = field(default_factory=list)

    @classmethod
    def from_record(cls, record: dict[str, Any]) -> "CoverageRecordDTO":
        return cls(
            completeness_level=str(record["completeness_level"]),
            incompleteness_reasons=list(record.get("incompleteness_reasons_json") or record.get("incompleteness_reasons") or []),
            checks=list(record.get("checks_json") or record.get("checks") or []),
            missing_sources=list(record.get("missing_sources_json") or record.get("missing_sources") or []),
        )

    def to_decision_support_input(self) -> dict[str, Any]:
        return {
            "completeness_level": self.completeness_level,
            "incompleteness_reasons": list(self.incompleteness_reasons),
            "checks": list(self.checks),
            "missing_sources": list(self.missing_sources),
        }


@dataclass(frozen=True)
class PolicyRecordDTO:
    policy_version: str
    policy_json: dict[str, Any]

    @classmethod
    def from_record(cls, record: dict[str, Any]) -> "PolicyRecordDTO":
        return cls(
            policy_version=str(record["policy_version"]),
            policy_json=dict(record["policy_json"]),
        )


@dataclass(frozen=True)
class DecisionSupportPayloadDTO:
    recommended_action: dict[str, Any] = field(default_factory=dict)
    alternative_actions: list[dict[str, Any]] = field(default_factory=list)
    completeness_assessment: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_payload(cls, payload: dict[str, Any] | None) -> "DecisionSupportPayloadDTO | None":
        if payload is None:
            return None
        if "decision_support_result" in payload:
            payload = payload["decision_support_result"]
        elif "result_json" in payload:
            payload = payload["result_json"]
        return cls(
            recommended_action=dict(payload.get("recommended_action") or {}),
            alternative_actions=list(payload.get("alternative_actions") or []),
            completeness_assessment=dict(payload.get("completeness_assessment") or {}),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class DecisionSupportInputsDTO:
    incident: dict[str, Any]
    detector_output: dict[str, Any]
    coverage: dict[str, Any]
    policy: dict[str, Any]
    knowledge_context: dict[str, Any]
    operator_context: dict[str, Any]

    def to_kwargs(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CoverageReviewDTO:
    incident_id: str
    incident_summary: dict[str, Any]
    recommended_action: dict[str, Any]
    alternative_actions: list[dict[str, Any]]
    coverage_status_by_category: list[dict[str, Any]]
    completeness: dict[str, Any]
    recommendation_may_be_incomplete: bool
    decision_risk_note: str
    what_could_change_the_decision: list[str]
    double_check: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
