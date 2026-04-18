from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol

from src.logging_utils import get_logger

logger = get_logger(__name__)


class AlertingRepositoryBundle(Protocol):
    def fetch_incident_notification_by_dedupe_key(self, dedupe_key: str) -> dict[str, Any] | None: ...
    def save_incident_notification(self, **kwargs) -> None: ...
    def save_review_event(self, **kwargs) -> None: ...


@dataclass(frozen=True)
class ResendConfig:
    api_key: str | None
    from_email: str | None
    recipients: tuple[str, ...]
    enabled: bool = True

    @classmethod
    def from_env(cls, env: dict[str, str]) -> "ResendConfig":
        raw_recipients = env.get("ALERT_EMAIL_TO", "")
        recipients = tuple(
            entry.strip()
            for entry in raw_recipients.replace(";", ",").split(",")
            if entry.strip()
        )
        return cls(
            api_key=env.get("RESEND_API_KEY"),
            from_email=env.get("ALERT_EMAIL_FROM"),
            recipients=recipients,
            enabled=env.get("ALERT_EMAIL_ENABLED", "true").lower() not in {"0", "false", "no"},
        )

    @property
    def is_configured(self) -> bool:
        return self.enabled and bool(self.api_key and self.from_email and self.recipients)


class EmailClient(Protocol):
    def send(self, *, sender: str, recipient: str, subject: str, text: str) -> str | None: ...


class ResendEmailClient:
    endpoint = "https://api.resend.com/emails"

    def __init__(self, api_key: str):
        self._api_key = api_key

    def send(self, *, sender: str, recipient: str, subject: str, text: str) -> str | None:
        payload = {
            "from": sender,
            "to": [recipient],
            "subject": subject,
            "text": text,
        }
        request = urllib.request.Request(
            self.endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
                "User-Agent": "sentinel/1.0",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                body = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Resend request failed with {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Resend request failed: {exc.reason}") from exc

        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            return None
        return payload.get("id")


@dataclass
class AlertingService:
    repositories: AlertingRepositoryBundle
    config: ResendConfig
    email_client: EmailClient | None = None

    def maybe_send_high_priority_alert(
        self,
        incident_record: dict[str, Any],
        decision_support_result: dict[str, Any],
    ) -> dict[str, Any]:
        incident_id = str(incident_record.get("incident_id") or "")
        severity_hint = str(incident_record.get("severity_hint") or "").lower()
        if severity_hint != "high":
            return {"attempted": False, "reason": "severity_not_high", "incident_id": incident_id}
        if not self.config.is_configured:
            logger.info("Alerting skipped incident_id=%s configured=%s", incident_id, self.config.is_configured)
            return {"attempted": False, "reason": "alerting_not_configured", "incident_id": incident_id}

        recommended_action = _extract_recommended_action(decision_support_result)
        sent_count = 0
        skipped_count = 0
        for recipient in self.config.recipients:
            dedupe_key = f"{incident_id}:high_priority_email:{recipient}"
            if self.repositories.fetch_incident_notification_by_dedupe_key(dedupe_key) is not None:
                skipped_count += 1
                continue

            subject = f"[Sentinel] High-priority incident detected: {incident_id}"
            body = _build_email_body(incident_record, recommended_action)
            provider_message_id = self._send_email(
                sender=self.config.from_email or "",
                recipient=recipient,
                subject=subject,
                text=body,
            )
            payload = {
                "subject": subject,
                "text": body,
                "severity_hint": severity_hint,
                "recommended_action": recommended_action,
            }
            sent_at = datetime.now(timezone.utc)
            self.repositories.save_incident_notification(
                incident_id=incident_id,
                channel="email",
                alert_type="high_priority_incident",
                recipient=recipient,
                dedupe_key=dedupe_key,
                status="sent",
                provider_message_id=provider_message_id,
                payload=payload,
                sent_at=sent_at,
            )
            self.repositories.save_review_event(
                incident_id=incident_id,
                event_type="notification_email_sent",
                actor={"service": "sentinel_alerting"},
                payload={
                    "recipient": recipient,
                    "subject": subject,
                    "alert_type": "high_priority_incident",
                    "provider": "resend",
                    "provider_message_id": provider_message_id,
                    "sent_at": sent_at.isoformat(),
                },
            )
            sent_count += 1

        return {
            "attempted": True,
            "incident_id": incident_id,
            "sent_count": sent_count,
            "skipped_count": skipped_count,
        }

    def _send_email(self, *, sender: str, recipient: str, subject: str, text: str) -> str | None:
        client = self.email_client
        if client is None:
            if not self.config.api_key:
                raise RuntimeError("RESEND_API_KEY is not configured.")
            client = ResendEmailClient(self.config.api_key)
        return client.send(sender=sender, recipient=recipient, subject=subject, text=text)


def _extract_recommended_action(decision_support_result: dict[str, Any]) -> dict[str, Any]:
    payload = decision_support_result.get("decision_support_result", decision_support_result)
    recommended = payload.get("recommended_action")
    return dict(recommended) if isinstance(recommended, dict) else {}


def _build_email_body(incident_record: dict[str, Any], recommended_action: dict[str, Any]) -> str:
    incident_id = str(incident_record.get("incident_id") or "unknown")
    title = str(incident_record.get("title") or f"Incident {incident_id}")
    summary = str(incident_record.get("summary") or "No summary available.")
    severity = str(incident_record.get("severity_hint") or "unknown").capitalize()
    action_label = str(recommended_action.get("label") or recommended_action.get("action_id") or "Review in Sentinel")
    action_reason = str(recommended_action.get("reason") or "A response is ready for operator review.")
    return "\n".join(
        [
            "Sentinel detected a high-priority incident.",
            "",
            f"Incident: {incident_id}",
            f"Title: {title}",
            f"Priority: {severity}",
            f"Summary: {summary}",
            f"Recommended action: {action_label}",
            f"Why Sentinel is recommending it: {action_reason}",
            "",
            "Open Sentinel to review and approve the next step.",
        ]
    )
