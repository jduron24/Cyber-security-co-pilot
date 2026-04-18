from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .logging_utils import configure_logging, get_logger

logger = get_logger(__name__)


@dataclass(frozen=True)
class DemoScenario:
    scenario_id: str
    title: str
    purpose: str
    expected_recommendation: str
    expected_blind_spot: str | None
    expected_operator_move: str
    coverage_categories: list[str]
    source_ip_hint: str | None = None
    actor_hint: str | None = None
    coverage_plan: dict[str, Any] = field(default_factory=dict)
    double_check_plan: dict[str, Any] = field(default_factory=dict)
    records: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class DemoBatch:
    batch_id: str
    scenario_id: str
    event_time: str
    records: list[dict[str, Any]]


def build_demo_scenarios(base_time: datetime | None = None) -> list[DemoScenario]:
    base_time = base_time or datetime(2025, 1, 15, 14, 0, tzinfo=timezone.utc)
    return [
        _scenario_incomplete_unusual_login(base_time),
        _scenario_complete_reset_case(base_time + timedelta(minutes=20)),
        _scenario_missing_device_context(base_time + timedelta(minutes=40)),
    ]


def iter_demo_batches(
    scenarios: list[DemoScenario] | None = None,
    batch_size: int = 1,
) -> list[DemoBatch]:
    scenarios = scenarios or build_demo_scenarios()
    batches: list[DemoBatch] = []
    for scenario in scenarios:
        for index in range(0, len(scenario.records), batch_size):
            batch_records = scenario.records[index : index + batch_size]
            batch_id = f"{scenario.scenario_id}_batch_{(index // batch_size) + 1:03d}"
            batches.append(
                DemoBatch(
                    batch_id=batch_id,
                    scenario_id=scenario.scenario_id,
                    event_time=str(batch_records[0]["eventTime"]),
                    records=batch_records,
                )
            )
    return sorted(batches, key=lambda item: item.event_time)


def write_demo_stream(
    output_dir: str | Path,
    scenarios: list[DemoScenario] | None = None,
    batch_size: int = 1,
    manifest_path: str | Path | None = None,
) -> dict[str, Any]:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    scenarios = scenarios or build_demo_scenarios()
    batches = iter_demo_batches(scenarios, batch_size=batch_size)
    logger.info("Writing demo stream output_dir=%s scenarios=%s batches=%s", output_path, len(scenarios), len(batches))

    for batch in batches:
        payload = {"Records": batch.records}
        (output_path / f"{batch.batch_id}.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
        logger.debug("Wrote demo batch path=%s records=%s", output_path / f"{batch.batch_id}.json", len(batch.records))

    manifest = {
        "scenarios": [
            {
                "scenario_id": scenario.scenario_id,
                "title": scenario.title,
                "purpose": scenario.purpose,
                "expected_recommendation": scenario.expected_recommendation,
                "expected_blind_spot": scenario.expected_blind_spot,
                "expected_operator_move": scenario.expected_operator_move,
                "coverage_categories": scenario.coverage_categories,
                "source_ip_hint": scenario.source_ip_hint,
                "actor_hint": scenario.actor_hint,
                "coverage_plan": scenario.coverage_plan,
                "double_check_plan": scenario.double_check_plan,
                "record_count": len(scenario.records),
            }
            for scenario in scenarios
        ],
        "batches": [asdict(batch) for batch in batches],
    }
    resolved_manifest_path = Path(manifest_path) if manifest_path is not None else (output_path / "demo_manifest.json")
    resolved_manifest_path.parent.mkdir(parents=True, exist_ok=True)
    resolved_manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate synthetic demo CloudTrail batches for purpose-doc scenarios.")
    parser.add_argument("--output-dir", default="data/demo_stream", help="Output directory for demo JSON batches.")
    parser.add_argument("--batch-size", type=int, default=1, help="Number of records per CloudTrail JSON payload.")
    args = parser.parse_args()

    configure_logging()
    manifest = write_demo_stream(args.output_dir, batch_size=max(1, args.batch_size))
    print(json.dumps({"scenario_count": len(manifest["scenarios"]), "batch_count": len(manifest["batches"])}, indent=2))
    return 0


def _scenario_incomplete_unusual_login(base_time: datetime) -> DemoScenario:
    actor = _actor("assumed-role/SalesApp", "AROADEMO1")
    source_ip = "203.0.113.10"
    records = [
        _record(base_time, "ConsoleLogin", "signin.amazonaws.com", actor, source_ip, user_agent="Mozilla/5.0", additional_event_data={"MFAUsed": "No"}),
        _record(base_time + timedelta(minutes=1), "GetCallerIdentity", "sts.amazonaws.com", actor, source_ip),
        _record(base_time + timedelta(minutes=2), "ListUsers", "iam.amazonaws.com", actor, source_ip),
        _record(base_time + timedelta(minutes=3), "CreateAccessKey", "iam.amazonaws.com", actor, source_ip, resources=[_resource("AWS::IAM::AccessKey", "arn:aws:iam::123456789012:user/demo")]),
    ]
    return DemoScenario(
        scenario_id="unusual_login_incomplete_network",
        title="Unusual login with missing network branch",
        purpose="Demonstrates the main blind-spot case from the purpose doc: recommendation is plausible but network activity is not checked.",
        expected_recommendation="reset_credentials",
        expected_blind_spot="network activity not checked; possible lateral movement remains unseen",
        expected_operator_move="double_check or escalate after seeing the missing network branch",
        coverage_categories=["login", "identity", "network"],
        source_ip_hint=source_ip,
        actor_hint=actor["arn"],
        coverage_plan={
            "completeness_level": "medium",
            "checks": [
                {"name": "login_activity", "status": "checked_signal_found"},
                {"name": "identity_changes", "status": "checked_signal_found"},
                {"name": "network_logs", "status": "not_checked"},
            ],
            "missing_sources": ["network_logs"],
            "incompleteness_reasons": ["Network telemetry was not checked."],
        },
        double_check_plan={
            "summary": "Double check loads network telemetry and shows the session is still active across additional infrastructure.",
            "expected_recommendation": "temporary_access_lock",
            "decision_changed": True,
            "detector_output_overrides": {
                "risk_score": 0.97,
                "risk_band": "high",
                "top_signals": [
                    {"label": "suspicious_console_login", "weight": 1.2},
                    {"label": "active_network_beaconing", "weight": 2.4},
                    {"label": "resource_creation_after_login", "weight": 1.8},
                ],
                "detector_labels": [
                    "suspicious_console_login",
                    "active_network_beaconing",
                    "ongoing_session_activity",
                ],
                "retrieved_patterns": [
                    "Active network session after suspicious login",
                    "Resource creation after sensitive activity",
                ],
                "data_sources_used": [
                    "demo_stream",
                    "incident_builder",
                    "weak_label_rules",
                    "network_logs",
                ],
            },
            "coverage_overrides": {
                "completeness_level": "high",
                "checks": [
                    {"name": "login_activity", "status": "checked_signal_found"},
                    {"name": "identity_changes", "status": "checked_signal_found"},
                    {"name": "network_logs", "status": "checked_signal_found"},
                ],
                "missing_sources": [],
                "incompleteness_reasons": [],
            },
        },
        records=records,
    )


def _scenario_complete_reset_case(base_time: datetime) -> DemoScenario:
    actor = _actor("root", "ROOTDEMO1")
    source_ip = "198.51.100.44"
    records = [
        _record(base_time, "ConsoleLogin", "signin.amazonaws.com", actor, source_ip, user_agent="aws-internal/console"),
        _record(base_time + timedelta(minutes=1), "AttachUserPolicy", "iam.amazonaws.com", actor, source_ip, resources=[_resource("AWS::IAM::Policy", "arn:aws:iam::123456789012:policy/Admin")]),
        _record(base_time + timedelta(minutes=2), "CreateAccessKey", "iam.amazonaws.com", actor, source_ip, resources=[_resource("AWS::IAM::AccessKey", "arn:aws:iam::123456789012:user/root-compromise")]),
        _record(base_time + timedelta(minutes=3), "DescribeInstances", "ec2.amazonaws.com", actor, source_ip, resources=[_resource("AWS::EC2::Instance", "arn:aws:ec2:us-east-1:123456789012:instance/i-demo123")]),
    ]
    return DemoScenario(
        scenario_id="complete_root_privilege_case",
        title="Complete high-confidence credential misuse case",
        purpose="Shows a case where the system can recommend a strong action without a major blind spot.",
        expected_recommendation="reset_credentials",
        expected_blind_spot=None,
        expected_operator_move="approve recommendation",
        coverage_categories=["login", "identity", "resource_activity"],
        source_ip_hint=source_ip,
        actor_hint=actor["arn"],
        coverage_plan={
            "completeness_level": "high",
            "checks": [
                {"name": "login_activity", "status": "checked_signal_found"},
                {"name": "identity_changes", "status": "checked_signal_found"},
                {"name": "resource_activity", "status": "checked_signal_found"},
            ],
            "missing_sources": [],
            "incompleteness_reasons": [],
        },
        records=records,
    )


def _scenario_missing_device_context(base_time: datetime) -> DemoScenario:
    actor = _actor("user/contractor-demo", "AIDADMO3")
    source_ip = "192.0.2.88"
    records = [
        _record(base_time, "ConsoleLogin", "signin.amazonaws.com", actor, source_ip, user_agent=None, additional_event_data={"MFAUsed": "Yes"}),
        _record(base_time + timedelta(minutes=1), "DescribeInstances", "ec2.amazonaws.com", actor, source_ip, user_agent=None),
        _record(base_time + timedelta(minutes=2), "RunInstances", "ec2.amazonaws.com", actor, source_ip, user_agent=None, resources=[_resource("AWS::EC2::Instance", "arn:aws:ec2:us-east-1:123456789012:instance/i-demo456")]),
    ]
    return DemoScenario(
        scenario_id="device_context_unavailable",
        title="Resource launch with unavailable device context",
        purpose="Shows the difference between not checked and could not check by withholding user-agent/device context.",
        expected_recommendation="collect_more_evidence",
        expected_blind_spot="device context unavailable; legitimacy of the session remains uncertain",
        expected_operator_move="choose alternative or ask for more analysis",
        coverage_categories=["login", "resource_activity", "device"],
        source_ip_hint=source_ip,
        actor_hint=actor["arn"],
        coverage_plan={
            "completeness_level": "low",
            "checks": [
                {"name": "login_activity", "status": "checked_signal_found"},
                {"name": "resource_activity", "status": "checked_signal_found"},
                {"name": "device_context", "status": "data_unavailable"},
            ],
            "missing_sources": [],
            "incompleteness_reasons": ["Device context was unavailable for this session."],
        },
        records=records,
    )


def _record(
    event_time: datetime,
    event_name: str,
    event_source: str,
    actor: dict[str, Any],
    source_ip: str,
    user_agent: str | None = "demo-agent/1.0",
    resources: list[dict[str, Any]] | None = None,
    additional_event_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "eventVersion": "1.08",
        "userIdentity": actor,
        "eventTime": event_time.isoformat().replace("+00:00", "Z"),
        "eventSource": event_source,
        "eventName": event_name,
        "awsRegion": "us-east-1",
        "sourceIPAddress": source_ip,
        "userAgent": user_agent,
        "requestParameters": {},
        "responseElements": None,
        "additionalEventData": additional_event_data or {},
        "requestID": f"req-{event_name.lower()}-{int(event_time.timestamp())}",
        "eventID": f"evt-{event_name.lower()}-{int(event_time.timestamp())}",
        "readOnly": event_name.startswith(("Describe", "Get", "List")),
        "eventType": "AwsApiCall",
        "recipientAccountId": "123456789012",
        "resources": resources or [],
    }


def _actor(identity_suffix: str, principal_id: str) -> dict[str, Any]:
    arn = f"arn:aws:iam::123456789012:{identity_suffix}"
    return {
        "type": "AssumedRole" if "assumed-role" in identity_suffix else ("Root" if identity_suffix == "root" else "IAMUser"),
        "principalId": principal_id,
        "arn": arn,
        "accountId": "123456789012",
        "accessKeyId": f"AKIA{principal_id[-6:]}",
        "userName": identity_suffix.split("/")[-1],
        "sessionContext": {
            "attributes": {
                "mfaAuthenticated": "false",
                "creationDate": datetime(2025, 1, 15, 13, 55, tzinfo=timezone.utc).isoformat().replace("+00:00", "Z"),
            }
        },
    }


def _resource(resource_type: str, arn: str) -> dict[str, Any]:
    return {"type": resource_type, "ARN": arn, "accountId": "123456789012"}


if __name__ == "__main__":
    raise SystemExit(main())
