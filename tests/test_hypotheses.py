from decision_support.hypotheses import build_hypotheses


def test_hypotheses_include_missing_evidence():
    hypotheses = build_hypotheses(
        {"incident_id": "INC"},
        {"top_signals": [{"label": "Root activity"}], "detector_labels": ["root_actor"], "retrieved_patterns": []},
        {"incompleteness_reasons": ["Network telemetry missing"]},
    )
    assert hypotheses
    assert "Network telemetry missing" in hypotheses[0].missing_evidence
