from __future__ import annotations

import os
from functools import lru_cache
from typing import Any, Callable

from dotenv import load_dotenv
from fastapi import HTTPException

from src.db.connection import create_connection, load_postgres_config
from src.repositories.service_bundles import (
    CoverageReviewRepositoryBundle,
    DecisionSupportRepositoryBundle,
    OperatorDecisionRepositoryBundle,
)
from src.services.coverage_review_service import CoverageReviewAppService
from src.services.decision_support_app_service import DecisionSupportAppService
from src.services.operator_decision_service import OperatorDecisionAppService

from .knowledge_base import KnowledgeBaseRepository

load_dotenv()


def get_backend_env() -> dict[str, str]:
    env = dict(os.environ)
    if env.get("DATABASE_URL") and not env.get("POSTGRES_DSN"):
        env["POSTGRES_DSN"] = env["DATABASE_URL"]
    return env


@lru_cache(maxsize=1)
def get_connection_factory() -> Callable[[], Any]:
    env = get_backend_env()
    config = load_postgres_config(env)

    def connection_factory():
        return create_connection(config)

    return connection_factory


def get_decision_support_service() -> DecisionSupportAppService:
    repos = DecisionSupportRepositoryBundle.from_connection_factory(get_connection_factory())
    return DecisionSupportAppService(repositories=repos)


def get_coverage_review_service() -> CoverageReviewAppService:
    repos = CoverageReviewRepositoryBundle.from_connection_factory(get_connection_factory())
    decision_support_service = get_decision_support_service()
    return CoverageReviewAppService(repositories=repos, decision_support_service=decision_support_service)


def get_operator_decision_service() -> OperatorDecisionAppService:
    repos = OperatorDecisionRepositoryBundle.from_connection_factory(get_connection_factory())
    coverage_review_service = get_coverage_review_service()
    return OperatorDecisionAppService(repositories=repos, coverage_review_service=coverage_review_service)


def get_operator_decision_repositories() -> OperatorDecisionRepositoryBundle:
    return OperatorDecisionRepositoryBundle.from_connection_factory(get_connection_factory())


def get_coverage_review_repositories() -> CoverageReviewRepositoryBundle:
    return CoverageReviewRepositoryBundle.from_connection_factory(get_connection_factory())


def get_knowledge_base_repository() -> KnowledgeBaseRepository:
    return KnowledgeBaseRepository(connection_factory=get_connection_factory())


def as_http_exception(exc: ValueError) -> HTTPException:
    message = str(exc)
    status_code = 400
    lowered = message.lower()
    if "not found" in lowered:
        status_code = 404
    return HTTPException(status_code=status_code, detail=message)
