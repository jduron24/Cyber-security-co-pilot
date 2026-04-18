from src.services.alerting_service import AlertingService, ResendConfig


class FakeRepositories:
    def __init__(self):
        self.notifications = {}
        self.saved_notifications = []
        self.review_events = []

    def fetch_incident_notification_by_dedupe_key(self, dedupe_key: str):
        return self.notifications.get(dedupe_key)

    def save_incident_notification(self, **kwargs):
        self.notifications[kwargs["dedupe_key"]] = dict(kwargs)
        self.saved_notifications.append(dict(kwargs))

    def save_review_event(self, **kwargs):
        self.review_events.append(dict(kwargs))


class FakeEmailClient:
    def __init__(self):
        self.sent = []

    def send(self, *, sender: str, recipient: str, subject: str, text: str):
        self.sent.append(
            {
                "sender": sender,
                "recipient": recipient,
                "subject": subject,
                "text": text,
            }
        )
        return "re_test_123"


def test_alerting_service_sends_once_for_high_severity():
    repositories = FakeRepositories()
    email_client = FakeEmailClient()
    service = AlertingService(
        repositories=repositories,
        config=ResendConfig(
            api_key="test-key",
            from_email="alerts@example.org",
            recipients=("ops@example.org",),
        ),
        email_client=email_client,
    )

    incident = {
        "incident_id": "incident_000000001",
        "title": "Unusual login",
        "summary": "Suspicious access pattern detected.",
        "severity_hint": "high",
    }
    decision_support = {
        "decision_support_result": {
            "recommended_action": {
                "action_id": "temporary_access_lock",
                "label": "Temporarily lock access",
                "reason": "The activity is high risk and should be contained.",
            }
        }
    }

    result = service.maybe_send_high_priority_alert(incident, decision_support)

    assert result["sent_count"] == 1
    assert len(email_client.sent) == 1
    assert repositories.saved_notifications[0]["status"] == "sent"
    assert repositories.review_events[0]["event_type"] == "notification_email_sent"

    second = service.maybe_send_high_priority_alert(incident, decision_support)
    assert second["sent_count"] == 0
    assert second["skipped_count"] == 1
    assert len(email_client.sent) == 1


def test_alerting_service_skips_non_high_severity():
    repositories = FakeRepositories()
    email_client = FakeEmailClient()
    service = AlertingService(
        repositories=repositories,
        config=ResendConfig(
            api_key="test-key",
            from_email="alerts@example.org",
            recipients=("ops@example.org",),
        ),
        email_client=email_client,
    )

    result = service.maybe_send_high_priority_alert(
        {
            "incident_id": "incident_000000002",
            "title": "Low-risk event",
            "summary": "No action needed.",
            "severity_hint": "medium",
        },
        {"decision_support_result": {"recommended_action": {}}},
    )

    assert result["attempted"] is False
    assert result["reason"] == "severity_not_high"
    assert email_client.sent == []
    assert repositories.saved_notifications == []
