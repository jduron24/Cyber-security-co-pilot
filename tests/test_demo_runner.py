from __future__ import annotations

import json
from pathlib import Path

from src.demo_runner import run_demo_pipeline


def test_demo_runner_executes_current_pipeline_end_to_end(tmp_path: Path):
    report = run_demo_pipeline(project_root=".", output_dir=str(tmp_path))
    assert report["event_count"] > 0
    assert report["incident_count"] >= 3
    assert len(report["scenario_outputs"]) == 3

    scenario_map = {item["scenario_id"]: item for item in report["scenario_outputs"]}
    incomplete = scenario_map["unusual_login_incomplete_network"]
    complete = scenario_map["complete_root_privilege_case"]
    unavailable = scenario_map["device_context_unavailable"]

    assert incomplete["initial_review"]["coverage_review"]["recommendation_may_be_incomplete"] is True
    assert incomplete["initial_review"]["decision_support"]["decision_support_result"]["recommended_action"]["action_id"] == "reset_credentials"
    assert any(item["category"] == "network" for item in incomplete["initial_review"]["coverage_review"]["coverage_status_by_category"])
    assert incomplete["decision_changed_after_double_check"] is True
    assert incomplete["double_check_review"] is not None
    assert incomplete["double_check_review"]["decision_support"]["decision_support_result"]["recommended_action"]["action_id"] == "temporary_access_lock"
    assert incomplete["double_check_review"]["coverage_review"]["recommendation_may_be_incomplete"] is False

    assert complete["initial_review"]["coverage_review"]["recommendation_may_be_incomplete"] is False
    assert complete["initial_review"]["decision_support"]["decision_support_result"]["recommended_action"]["action_id"] == "reset_credentials"
    assert complete["double_check_review"] is None

    assert unavailable["initial_review"]["coverage_review"]["recommendation_may_be_incomplete"] is True
    assert unavailable["initial_review"]["decision_support"]["decision_support_result"]["recommended_action"]["action_id"] in {
        "collect_more_evidence",
        "escalate_to_expert",
    }


def test_demo_runner_writes_report_artifacts(tmp_path: Path):
    report = run_demo_pipeline(project_root=".", output_dir=str(tmp_path))
    report_path = Path(tmp_path) / "reports" / "demo_run_report.json"
    assert report_path.exists()
    saved = json.loads(report_path.read_text(encoding="utf-8"))
    assert saved["incident_count"] == report["incident_count"]
    assert len(saved["scenario_outputs"]) == 3
    assert "initial_review" in saved["scenario_outputs"][0]
