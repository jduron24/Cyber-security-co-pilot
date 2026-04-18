from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from backend.dependencies import get_knowledge_base_repository
from backend.knowledge_base import KnowledgeBaseRepository
from backend.models import SearchResponse

router = APIRouter(tags=["knowledge-base"])


@router.get("/search", response_model=SearchResponse)
def search(
    q: str = Query(..., min_length=1),
    limit: int = Query(5, ge=1, le=25),
    repository: KnowledgeBaseRepository = Depends(get_knowledge_base_repository),
) -> SearchResponse:
    return SearchResponse(results=repository.search(q, limit))
