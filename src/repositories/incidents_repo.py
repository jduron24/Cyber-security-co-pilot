from __future__ import annotations

from typing import Any, Callable

from src.logging_utils import get_logger

logger = get_logger(__name__)


class IncidentsRepository:
    def __init__(self, connection_factory: Callable[[], Any]):
        self._connection_factory = connection_factory

    def list_incidents(self, limit: int = 25) -> list[dict[str, Any]]:
        logger.debug("Listing incidents limit=%s", limit)
        query = """
        SELECT incident_id, title, summary, severity_hint, start_time, end_time, primary_actor, entities, event_sequence
        FROM incidents
        ORDER BY updated_at DESC NULLS LAST, created_at DESC NULLS LAST, incident_id DESC
        LIMIT %s
        """
        return _fetch_all(self._connection_factory, query, (limit,), context=f"limit={limit}")

    def list_recent_high_severity_incidents(self, lookback_hours: int = 1, limit: int = 100) -> list[dict[str, Any]]:
        logger.debug("Listing recent high-severity incidents lookback_hours=%s limit=%s", lookback_hours, limit)
        query = """
        SELECT incident_id, title, summary, severity_hint, start_time, end_time,
               primary_actor, entities, event_sequence, created_at, updated_at
        FROM incidents
        WHERE LOWER(COALESCE(severity_hint, '')) = 'high'
          AND COALESCE(updated_at, created_at, NOW()) >= NOW() - (%s * INTERVAL '1 hour')
        ORDER BY COALESCE(updated_at, created_at) DESC, incident_id DESC
        LIMIT %s
        """
        return _fetch_all(
            self._connection_factory,
            query,
            (lookback_hours, limit),
            context=f"lookback_hours={lookback_hours} limit={limit}",
        )

    def fetch_incident(self, incident_id: str) -> dict[str, Any] | None:
        logger.debug("Fetching incident incident_id=%s", incident_id)
        query = """
        SELECT incident_id, title, summary, severity_hint, start_time, end_time, primary_actor, entities, event_sequence
        FROM incidents
        WHERE incident_id = %s
        """
        return _fetch_one(self._connection_factory, query, (incident_id,), context=f"incident_id={incident_id}")


def _fetch_one(connection_factory: Callable[[], Any], query: str, params: tuple[Any, ...], context: str | None = None) -> dict[str, Any] | None:
    with connection_factory() as conn:
        with conn.cursor() as cur:
            cur.execute(query, params)
            row = cur.fetchone()
            logger.debug("Incident query finished found=%s %s", row is not None, context or "")
            return dict(row) if row is not None else None


def _fetch_all(connection_factory: Callable[[], Any], query: str, params: tuple[Any, ...], context: str | None = None) -> list[dict[str, Any]]:
    with connection_factory() as conn:
        with conn.cursor() as cur:
            cur.execute(query, params)
            rows = cur.fetchall()
            logger.debug("Incident list query finished count=%s %s", len(rows), context or "")
            return [dict(row) for row in rows]
