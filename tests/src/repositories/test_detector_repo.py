from __future__ import annotations

import psycopg

from src.repositories.detector_repo import DetectorRepository


def test_fetch_latest_detector_and_coverage_return_newest(repository_connection_factory, repository_test_dsn, seeded_incident):
    with psycopg.connect(repository_test_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO detector_results (
                    incident_id, risk_score, risk_band, top_signals_json, counter_signals_json,
                    detector_labels_json, retrieved_patterns_json, data_sources_used_json, model_type,
                    explanation_json, feature_contributions_json, model_version
                )
                VALUES (%s, %s, %s, %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb, %s, %s::jsonb, %s::jsonb, %s)
                """,
                (seeded_incident, 0.4, "medium", '[]', '[]', '["older"]', '[]', '["test"]', "logistic", '{"prediction_probability":0.4}', '[{"feature":"event_count","contribution":0.1}]', "v1"),
            )
            cur.execute(
                """
                INSERT INTO detector_results (
                    incident_id, risk_score, risk_band, top_signals_json, counter_signals_json,
                    detector_labels_json, retrieved_patterns_json, data_sources_used_json, model_type,
                    explanation_json, feature_contributions_json, model_version
                )
                VALUES (%s, %s, %s, %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb, %s, %s::jsonb, %s::jsonb, %s)
                """,
                (seeded_incident, 0.9, "high", '[]', '[]', '["newer"]', '["pattern"]', '["test","network_logs"]', "ebm", '{"prediction_probability":0.9}', '[{"feature":"failure_ratio","contribution":0.44}]', "v2"),
            )
            cur.execute(
                """
                INSERT INTO coverage_assessments (
                    incident_id, completeness_level, incompleteness_reasons_json, checks_json, missing_sources_json
                )
                VALUES (%s, %s, %s::jsonb, %s::jsonb, %s::jsonb)
                """,
                (seeded_incident, "low", '["older"]', '[{"name":"login","status":"checked"}]', '["network_logs"]'),
            )
            cur.execute(
                """
                INSERT INTO coverage_assessments (
                    incident_id, completeness_level, incompleteness_reasons_json, checks_json, missing_sources_json
                )
                VALUES (%s, %s, %s::jsonb, %s::jsonb, %s::jsonb)
                """,
                (seeded_incident, "high", '[]', '[{"name":"login","status":"checked"},{"name":"network","status":"checked"}]', '[]'),
            )
        conn.commit()

    repo = DetectorRepository(repository_connection_factory)
    detector = repo.fetch_latest_detector_result(seeded_incident)
    coverage = repo.fetch_latest_coverage_assessment(seeded_incident)

    assert detector is not None
    assert detector["risk_band"] == "high"
    assert detector["detector_labels_json"] == ["newer"]
    assert detector["model_type"] == "ebm"
    assert detector["feature_contributions_json"][0]["feature"] == "failure_ratio"
    assert coverage is not None
    assert coverage["completeness_level"] == "high"
