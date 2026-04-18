from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.db.connection import create_connection, load_postgres_config
from src.logging_utils import get_logger

logger = get_logger(__name__)


class McpClientError(RuntimeError):
    """Raised when MCP cyber context retrieval fails."""


@dataclass(frozen=True)
class McpCyberContextClient:
    project_root: Path
    enabled: bool = False
    env: dict[str, str] | None = None

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None, project_root: str | Path | None = None) -> "McpCyberContextClient":
        env = env or os.environ
        resolved_root = Path(project_root or Path(__file__).resolve().parents[2])
        return cls(
            project_root=resolved_root,
            enabled=_is_truthy(env.get("AGENT_USE_MCP_CYBER_CONTEXT")) or _is_truthy(env.get("USE_MCP_CYBER_CONTEXT")),
            env=dict(env),
        )

    def search(self, query: str, limit: int = 5) -> list[dict[str, Any]]:
        if not self.enabled:
            return []
        query = str(query or "").strip()
        if not query:
            return []
        try:
            return self._search_via_mcp(query=query, limit=limit)
        except McpClientError as exc:
            logger.warning("Falling back to Postgres KB search for MCP cyber context error=%s", exc)
            return self._search_via_postgres(query=query, limit=limit)

    def _search_via_mcp(self, query: str, limit: int) -> list[dict[str, Any]]:
        npm_executable = _resolve_npm()
        mcp_root = self.project_root / "mcp_server"
        if not (mcp_root / "package.json").exists():
            raise McpClientError(f"MCP server package not found at {mcp_root}")

        command = [
            npm_executable,
            "run",
            "--silent",
            "query",
            "--",
            "--tool",
            "search_kb",
            "--query",
            query,
            "--limit",
            str(limit),
        ]
        child_env = os.environ.copy()
        if self.env:
            child_env.update({key: str(value) for key, value in self.env.items() if value is not None})
        if child_env.get("POSTGRES_DSN") and not child_env.get("DATABASE_URL"):
            child_env["DATABASE_URL"] = child_env["POSTGRES_DSN"]
        logger.info("Querying MCP cyber context query=%s limit=%s", query, limit)
        completed = subprocess.run(
            command,
            cwd=str(mcp_root),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            env=child_env,
        )
        if completed.returncode != 0:
            raise McpClientError((completed.stderr or completed.stdout or "MCP tool call failed.").strip())
        return _parse_tool_rows(completed.stdout)

    def _search_via_postgres(self, query: str, limit: int) -> list[dict[str, Any]]:
        logger.info("Querying fallback Postgres cyber context query=%s limit=%s", query, limit)
        config = load_postgres_config(self.env)
        tsquery = _normalize_query(query)
        if not tsquery:
            return []
        sql = """
        SELECT title, content, entry_type, kd.name AS domain,
               ts_rank(ke.search_vector, to_tsquery('english', %s)) AS score
        FROM knowledge_entries ke
        LEFT JOIN knowledge_domains kd ON ke.domain_id = kd.id
        WHERE ke.search_vector @@ to_tsquery('english', %s)
        ORDER BY score DESC
        LIMIT %s
        """
        with create_connection(config) as conn:
            with conn.cursor() as cur:
                cur.execute(sql, (tsquery, tsquery, limit))
                rows = cur.fetchall()
                return [dict(row) for row in rows]


def _parse_tool_rows(raw: str) -> list[dict[str, Any]]:
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise McpClientError("MCP client returned invalid JSON.") from exc
    content = parsed.get("content") or []
    if not isinstance(content, list):
        return []
    for item in content:
        if isinstance(item, dict) and item.get("type") == "text":
            text = item.get("text", "").strip()
            if not text:
                return []
            try:
                rows = json.loads(text)
            except json.JSONDecodeError as exc:
                raise McpClientError("MCP tool text payload was not valid JSON.") from exc
            return rows if isinstance(rows, list) else []
    return []


def _resolve_npm() -> str:
    for candidate in ("npm.cmd", "npm"):
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    raise McpClientError("npm was not found. Install Node.js or add npm to PATH.")


def _normalize_query(text: str) -> str:
    sanitized = "".join(ch if ch.isalnum() or ch.isspace() else " " for ch in text)
    tokens = [token for token in sanitized.strip().split() if len(token) > 3]
    return " & ".join(tokens)


def _is_truthy(value: str | None) -> bool:
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "yes", "on"}
