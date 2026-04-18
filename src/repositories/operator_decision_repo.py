from __future__ import annotations

import json
from typing import Any, Callable

from src.logging_utils import get_logger

logger = get_logger(__name__)


class OperatorDecisionRepository:
    def __init__(self, connection_factory: Callable[[], Any]):
        self._connection_factory = connection_factory

    def save_operator_decision(
        self,
        incident_id: str,
        decision_type: str,
        selected_from: str,
        chosen_action_id: str | None,
        chosen_action_label: str | None,
        rationale: str | None,
        used_double_check: bool,
        actor: dict[str, Any] | None,
        coverage_review: dict[str, Any],
        decision_support_result: dict[str, Any] | None,
    ) -> None:
        logger.info("Persisting operator decision incident_id=%s decision_type=%s chosen_action_id=%s", incident_id, decision_type, chosen_action_id)
        query = """
        INSERT INTO operator_decisions (
            incident_id, decision_type, selected_from, chosen_action_id, chosen_action_label,
            rationale, used_double_check, actor_json, coverage_review_json, decision_support_result_json
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s::jsonb)
        """
        params = (
            incident_id,
            decision_type,
            selected_from,
            chosen_action_id,
            chosen_action_label,
            rationale,
            used_double_check,
            json.dumps(actor or {}),
            json.dumps(coverage_review),
            json.dumps(decision_support_result) if decision_support_result is not None else None,
        )
        with self._connection_factory() as conn:
            with conn.cursor() as cur:
                cur.execute(query, params)
            conn.commit()

    def save_review_event(
        self,
        incident_id: str,
        event_type: str,
        payload: dict[str, Any],
        actor: dict[str, Any] | None = None,
    ) -> None:
        logger.info("Persisting review event incident_id=%s event_type=%s", incident_id, event_type)
        query = """
        INSERT INTO decision_review_events (incident_id, event_type, actor_json, payload_json)
        VALUES (%s, %s, %s::jsonb, %s::jsonb)
        """
        params = (
            incident_id,
            event_type,
            json.dumps(actor or {}),
            json.dumps(payload),
        )
        with self._connection_factory() as conn:
            with conn.cursor() as cur:
                cur.execute(query, params)
            conn.commit()

    def fetch_latest_operator_decision(self, incident_id: str) -> dict[str, Any] | None:
        logger.debug("Fetching latest operator decision incident_id=%s", incident_id)
        query = """
        SELECT incident_id, decision_type, selected_from, chosen_action_id, chosen_action_label, rationale,
               used_double_check, actor_json, coverage_review_json, decision_support_result_json, created_at
        FROM operator_decisions
        WHERE incident_id = %s
        ORDER BY created_at DESC, operator_decision_id DESC
        LIMIT 1
        """
        with self._connection_factory() as conn:
            with conn.cursor() as cur:
                cur.execute(query, (incident_id,))
                row = cur.fetchone()
                logger.debug("Operator decision query finished incident_id=%s found=%s", incident_id, row is not None)
                return dict(row) if row is not None else None

    def fetch_recent_operator_decisions(self, incident_id: str, limit: int = 10) -> list[dict[str, Any]]:
        logger.debug("Fetching recent operator decisions incident_id=%s limit=%s", incident_id, limit)
        query = """
        SELECT incident_id, decision_type, selected_from, chosen_action_id, chosen_action_label, rationale,
               used_double_check, actor_json, coverage_review_json, decision_support_result_json, created_at
        FROM operator_decisions
        WHERE incident_id = %s
        ORDER BY created_at DESC, operator_decision_id DESC
        LIMIT %s
        """
        with self._connection_factory() as conn:
            with conn.cursor() as cur:
                cur.execute(query, (incident_id, limit))
                rows = cur.fetchall()
                return [dict(row) for row in rows]

    def fetch_recent_review_events(self, incident_id: str, limit: int = 10) -> list[dict[str, Any]]:
        logger.debug("Fetching recent review events incident_id=%s limit=%s", incident_id, limit)
        query = """
        SELECT incident_id, event_type, actor_json, payload_json, created_at
        FROM decision_review_events
        WHERE incident_id = %s
        ORDER BY created_at DESC, decision_review_event_id DESC
        LIMIT %s
        """
        with self._connection_factory() as conn:
            with conn.cursor() as cur:
                cur.execute(query, (incident_id, limit))
                rows = cur.fetchall()
                return [dict(row) for row in rows]
