from __future__ import annotations

import json
from pathlib import Path

from src.demo_runner import run_demo_pipeline


def _write_network_sample(sample_dir: Path) -> None:
    sample_dir.mkdir(parents=True, exist_ok=True)
    (sample_dir / "network-sample.csv").write_text(
        "\n".join(
            [
                "Dst Port,Protocol,Timestamp,Flow Duration,Tot Fwd Pkts,Tot Bwd Pkts,Label",
                "443,6,2025-01-15 14:00:00,120,10,7,Benign",
                "22,6,2025-01-15 14:01:00,900,55,21,Infilteration",
                "80,6,2025-01-15 14:02:00,750,48,19,Infilteration",
            ]
        ),
        encoding="utf-8",
    )


def test_demo_runner_executes_current_pipeline_end_to_end(tmp_path: Path):
    sample_dir = tmp_path / "network-sample"
    _write_network_sample(sample_dir)
    report = run_demo_pipeline(project_root=".", output_dir=str(tmp_path), network_sample_dir=sample_dir, model_training_input=None)
    assert report["event_count"] > 0
    assert report["incident_count"] >= 3
    assert len(report["scenario_outputs"]) == 3
    assert report["network_evidence_package"]["suspicious_flow_count"] == 2

    scenario_map = {item["scenario_id"]: item for item in report["scenario_outputs"]}
    incomplete = scenario_map["unusual_login_incomplete_network"]
    complete = scenario_map["complete_root_privilege_case"]
    unavailable = scenario_map["device_context_unavailable"]

    assert report["demo_model"]["model_type"] in {"ebm", "logistic"}
    assert incomplete["incident_events"]
    assert incomplete["incident_events"][0]["event_payload"]["eventName"] == incomplete["incident_events"][0]["event_name"]
    assert incomplete["initial_review"]["detector_output"]["model_type"] in {"ebm", "logistic"}
    assert incomplete["initial_review"]["detector_output"]["feature_contributions"]
    assert incomplete["initial_review"]["detector_output"]["data_sources_used"][-1] == "demo_incident_model"

    assert incomplete["initial_review"]["coverage_review"]["recommendation_may_be_incomplete"] is True
    assert incomplete["initial_review"]["decision_support"]["decision_support_result"]["recommended_action"]["action_id"] == "reset_credentials"
    assert any(item["category"] == "network" for item in incomplete["initial_review"]["coverage_review"]["coverage_status_by_category"])
    assert incomplete["network_evidence"]["status"] == "available_not_reviewed"
    assert incomplete["decision_changed_after_double_check"] is True
    assert incomplete["double_check_review"] is not None
    assert incomplete["double_check_review"]["decision_support"]["decision_support_result"]["recommended_action"]["action_id"] == "temporary_access_lock"
    assert incomplete["double_check_review"]["coverage_review"]["recommendation_may_be_incomplete"] is False
    assert incomplete["double_check_review"]["network_evidence"]["status"] == "reviewed"
    assert incomplete["double_check_review"]["network_evidence"]["suspicious_flow_count"] == 2

    assert complete["initial_review"]["coverage_review"]["recommendation_may_be_incomplete"] is False
    assert complete["initial_review"]["decision_support"]["decision_support_result"]["recommended_action"]["action_id"] == "reset_credentials"
    assert complete["double_check_review"] is None

    assert unavailable["initial_review"]["coverage_review"]["recommendation_may_be_incomplete"] is True
    assert unavailable["initial_review"]["decision_support"]["decision_support_result"]["recommended_action"]["action_id"] in {
        "collect_more_evidence",
        "escalate_to_expert",
    }


def test_demo_runner_writes_report_artifacts(tmp_path: Path):
    sample_dir = tmp_path / "network-sample"
    _write_network_sample(sample_dir)
    report = run_demo_pipeline(project_root=".", output_dir=str(tmp_path), network_sample_dir=sample_dir, model_training_input=None)
    report_path = Path(tmp_path) / "reports" / "demo_run_report.json"
    assert report_path.exists()
    saved = json.loads(report_path.read_text(encoding="utf-8"))
    assert saved["incident_count"] == report["incident_count"]
    assert len(saved["scenario_outputs"]) == 3
    assert "initial_review" in saved["scenario_outputs"][0]
    assert "incident_events" in saved["scenario_outputs"][0]
    assert saved["scenario_outputs"][0]["initial_review"]["detector_output"]["feature_contributions"]
    assert saved["network_evidence_package"]["suspicious_flow_count"] == 2
