from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Callable

from src.logging_utils import get_logger

logger = get_logger(__name__)


class IncidentNotificationRepository:
    def __init__(self, connection_factory: Callable[[], Any]):
        self._connection_factory = connection_factory

    def fetch_notification_by_dedupe_key(self, dedupe_key: str) -> dict[str, Any] | None:
        logger.debug("Fetching incident notification dedupe_key=%s", dedupe_key)
        query = """
        SELECT incident_notification_id, incident_id, channel, alert_type, recipient, dedupe_key, status,
               provider_message_id, payload_json, sent_at, created_at
        FROM incident_notifications
        WHERE dedupe_key = %s
        LIMIT 1
        """
        with self._connection_factory() as conn:
            with conn.cursor() as cur:
                cur.execute(query, (dedupe_key,))
                row = cur.fetchone()
                return dict(row) if row is not None else None

    def save_notification(
        self,
        incident_id: str,
        channel: str,
        alert_type: str,
        recipient: str,
        dedupe_key: str,
        status: str,
        payload: dict[str, Any],
        provider_message_id: str | None = None,
        sent_at: datetime | None = None,
    ) -> None:
        logger.info(
            "Persisting incident notification incident_id=%s channel=%s recipient=%s status=%s",
            incident_id,
            channel,
            recipient,
            status,
        )
        query = """
        INSERT INTO incident_notifications (
            incident_id, channel, alert_type, recipient, dedupe_key, status,
            provider_message_id, payload_json, sent_at
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s)
        ON CONFLICT (dedupe_key) DO NOTHING
        """
        params = (
            incident_id,
            channel,
            alert_type,
            recipient,
            dedupe_key,
            status,
            provider_message_id,
            json.dumps(payload),
            sent_at,
        )
        with self._connection_factory() as conn:
            with conn.cursor() as cur:
                cur.execute(query, params)
            conn.commit()
