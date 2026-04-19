from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable

from src.logging_utils import get_logger

logger = get_logger(__name__)


def normalize_query(text: str) -> str:
    text = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "", text)
    text = re.sub(r":\d{2,5}\b", "", text)
    text = re.sub(r"\d{4}-\d{2}-\d{2}T[\d:Z.]+", "", text)
    tokens = [token for token in text.strip().split() if len(token) > 3]
    return " & ".join(tokens)


@dataclass
class KnowledgeBaseRepository:
    connection_factory: Callable[[], Any]

    def search(self, query: str, limit: int = 5) -> list[dict[str, Any]]:
        tsquery = normalize_query(query)
        if not tsquery:
            return []
        logger.debug(
            "Searching knowledge base limit=%s query_chars=%s token_count=%s",
            limit,
            len(query or ""),
            len(tsquery.split(" & ")),
        )
        sql = """
        SELECT title, content, entry_type, kd.name AS domain,
               ts_rank(ke.search_vector, to_tsquery('english', %s)) AS score
        FROM knowledge_entries ke
        LEFT JOIN knowledge_domains kd ON ke.domain_id = kd.id
        WHERE ke.search_vector @@ to_tsquery('english', %s)
        ORDER BY score DESC
        LIMIT %s
        """
        with self.connection_factory() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, (tsquery, tsquery, limit))
                rows = cur.fetchall()
                return [dict(row) for row in rows]
