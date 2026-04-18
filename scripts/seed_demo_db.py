from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import yaml
import psycopg

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.demo_runner import run_demo_pipeline
from src.demo_stream import build_demo_scenarios
from src.logging_utils import configure_logging, get_logger


logger = get_logger(__name__)


def main() -> int:
    configure_logging()
    repo_root = REPO_ROOT
    dsn = os.environ.get("POSTGRES_DSN") or os.environ.get("DATABASE_URL")
    if not dsn:
        state_path = repo_root / ".local" / "services" / "embedded_postgres.json"
        if state_path.exists():
            dsn = json.loads(state_path.read_text(encoding="utf-8"))["database_uri"]
    if not dsn:
        raise RuntimeError("Set POSTGRES_DSN or DATABASE_URL before seeding demo data.")

    report = run_demo_pipeline(
        project_root=repo_root,
        output_dir=repo_root / ".local" / "demo_seed",
        batch_size=1,
    )
    scenario_map = {scenario.scenario_id: scenario for scenario in build_demo_scenarios()}
    policy_path = repo_root / "configs" / "decision_policy.yaml"
    policy_json = yaml.safe_load(policy_path.read_text(encoding="utf-8")) or {}
    policy_version = "local-demo-v1"

    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            _apply_sql(cur, repo_root / "src" / "db" / "schema.sql")
            _apply_sql(cur, repo_root / "backend" / "schema.sql")
            _apply_sql(cur, repo_root / "backend" / "search_setup.sql")

            cur.execute(
                """
                INSERT INTO policy_snapshots (policy_version, policy_json)
                VALUES (%s, %s::jsonb)
                ON CONFLICT (policy_version)
                DO UPDATE SET policy_json = EXCLUDED.policy_json
                """,
                (policy_version, json.dumps(policy_json)),
            )

            for scenario_output in report["scenario_outputs"]:
                scenario_id = scenario_output["scenario_id"]
                scenario = scenario_map[scenario_id]
                incident_id = scenario_output["incident_id"]
                initial_review = scenario_output["initial_review"]
                summary = {
                    "title": scenario_output["title"],
                    "summary": scenario.purpose,
                    "event_sequence": initial_review["coverage_review"]["incident_summary"]["event_sequence"],
                    "playbook_snippets": [scenario.title, scenario.purpose],
                    "domain_terms": [{"title": label} for label in initial_review["detector_output"]["detector_labels"]],
                    "operator_context": {"operator_type": "non_expert"},
                }

                _delete_existing(cur, incident_id)

                cur.execute(
                    """
                    INSERT INTO incidents (
                        incident_id, title, summary, severity_hint, primary_actor, entities, event_sequence
                    )
                    VALUES (%s, %s, %s, %s, %s::jsonb, %s::jsonb, %s::jsonb)
                    """,
                    (
                        incident_id,
                        scenario_output["title"],
                        scenario.purpose,
                        initial_review["detector_output"]["risk_band"],
                        json.dumps(initial_review["coverage_review"]["incident_summary"]["primary_actor"] or {}),
                        json.dumps(initial_review["coverage_review"]["incident_summary"]["entities"] or {}),
                        json.dumps(initial_review["coverage_review"]["incident_summary"]["event_sequence"]),
                    ),
                )

                for event in scenario_output.get("incident_events") or []:
                    cur.execute(
                        """
                        INSERT INTO incident_events (
                            incident_id, event_id, event_time, event_name, event_source, event_index, event_payload
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb)
                        """,
                        (
                            event["incident_id"],
                            event["event_id"],
                            event["event_time"],
                            event["event_name"],
                            event["event_source"],
                            event["event_index"],
                            json.dumps(event["event_payload"]),
                        ),
                    )

                cur.execute(
                    """
                    INSERT INTO evidence_packages (incident_id, summary_json, provenance_json, raw_refs_json)
                    VALUES (%s, %s::jsonb, %s::jsonb, %s::jsonb)
                    """,
                    (
                        incident_id,
                        json.dumps(summary),
                        json.dumps({"source": "demo_runner", "scenario_id": scenario_id}),
                        json.dumps({"coverage_categories": scenario.coverage_categories}),
                    ),
                )

                detector_output = initial_review["detector_output"]
                cur.execute(
                    """
                    INSERT INTO detector_results (
                        incident_id, risk_score, risk_band, top_signals_json, counter_signals_json,
                        detector_labels_json, retrieved_patterns_json, data_sources_used_json,
                        model_type, explanation_json, feature_contributions_json, model_version
                    )
                    VALUES (%s, %s, %s, %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb, %s, %s::jsonb, %s::jsonb, %s)
                    """,
                    (
                        incident_id,
                        detector_output["risk_score"],
                        detector_output["risk_band"],
                        json.dumps(detector_output["top_signals"]),
                        json.dumps(detector_output["counter_signals"]),
                        json.dumps(detector_output["detector_labels"]),
                        json.dumps(detector_output["retrieved_patterns"]),
                        json.dumps(detector_output["data_sources_used"]),
                        detector_output.get("model_type"),
                        json.dumps(detector_output.get("explanation") or {}),
                        json.dumps(detector_output.get("feature_contributions") or []),
                        f"demo-{detector_output.get('model_type') or 'model'}",
                    ),
                )

                coverage_plan = scenario.coverage_plan or {}
                cur.execute(
                    """
                    INSERT INTO coverage_assessments (
                        incident_id, completeness_level, incompleteness_reasons_json, checks_json, missing_sources_json
                    )
                    VALUES (%s, %s, %s::jsonb, %s::jsonb, %s::jsonb)
                    """,
                    (
                        incident_id,
                        coverage_plan.get("completeness_level", "medium"),
                        json.dumps(list(coverage_plan.get("incompleteness_reasons") or [])),
                        json.dumps(list(coverage_plan.get("checks") or [])),
                        json.dumps(list(coverage_plan.get("missing_sources") or [])),
                    ),
                )

                decision_support = initial_review["decision_support"]
                cur.execute(
                    """
                    INSERT INTO decision_support_results (
                        incident_id, result_json, validation_json, llm_trace_json, policy_version
                    )
                    VALUES (%s, %s::jsonb, %s::jsonb, %s::jsonb, %s)
                    """,
                    (
                        incident_id,
                        json.dumps(decision_support["decision_support_result"]),
                        json.dumps(decision_support["validation"]),
                        json.dumps(decision_support["llm_trace"]),
                        policy_version,
                    ),
                )

        conn.commit()

    print(
        json.dumps(
            {
                "seeded_incidents": [item["incident_id"] for item in report["scenario_outputs"]],
                "policy_version": policy_version,
                "dsn": dsn,
            },
            indent=2,
        )
    )
    return 0


def _apply_sql(cur: psycopg.Cursor, path: Path) -> None:
    logger.info("Applying sql path=%s", path)
    cur.execute(path.read_text(encoding="utf-8"))


def _delete_existing(cur: psycopg.Cursor, incident_id: str) -> None:
    for table in (
        "decision_review_events",
        "operator_decisions",
        "decision_support_results",
        "coverage_assessments",
        "detector_results",
        "evidence_packages",
        "incident_events",
        "incidents",
    ):
        cur.execute(f"DELETE FROM {table} WHERE incident_id = %s", (incident_id,))


if __name__ == "__main__":
    raise SystemExit(main())
