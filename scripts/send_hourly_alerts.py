from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.dependencies import get_backend_env, get_connection_factory
from src.logging_utils import configure_logging, get_logger
from src.repositories.service_bundles import DecisionSupportRepositoryBundle
from src.services.alerting_service import AlertingService, ResendConfig
from src.services.decision_support_app_service import DecisionSupportAppService

logger = get_logger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scan recent high-severity incidents and send deduplicated email alerts."
    )
    parser.add_argument(
        "--lookback-hours",
        type=int,
        default=1,
        help="How many recent hours of incidents to scan. Default: 1",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=100,
        help="Maximum number of incidents to scan per run. Default: 100",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    configure_logging()

    env = get_backend_env()
    connection_factory = get_connection_factory()
    repositories = DecisionSupportRepositoryBundle.from_connection_factory(connection_factory)
    alerting_service = AlertingService(repositories=repositories, config=ResendConfig.from_env(env))
    decision_support_service = DecisionSupportAppService(repositories=repositories, alerting_service=alerting_service)

    incidents = repositories.list_recent_high_severity_incidents(
        lookback_hours=args.lookback_hours,
        limit=args.limit,
    )
    logger.info(
        "Hourly alert scan started lookback_hours=%s limit=%s candidates=%s",
        args.lookback_hours,
        args.limit,
        len(incidents),
    )

    processed: list[dict[str, str]] = []
    failed: list[dict[str, str]] = []
    for incident in incidents:
        incident_id = str(incident.get("incident_id") or "")
        try:
            decision_support_service.generate_for_incident(incident_id)
            processed.append({"incident_id": incident_id, "status": "processed"})
        except Exception as exc:
            logger.exception("Hourly alert scan failed incident_id=%s", incident_id)
            failed.append({"incident_id": incident_id, "status": "failed", "error": str(exc)})

    output = {
        "lookback_hours": args.lookback_hours,
        "limit": args.limit,
        "candidates": len(incidents),
        "processed": processed,
        "failed": failed,
    }
    print(json.dumps(output, indent=2))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
