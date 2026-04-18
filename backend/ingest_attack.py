import json
import os
from pathlib import Path

from dotenv import load_dotenv

from src.db.connection import create_connection, load_postgres_config
from src.logging_utils import configure_logging, get_logger

load_dotenv()
configure_logging()
logger = get_logger(__name__)

DATA_PATH = Path(__file__).resolve().parents[1] / "data" / "enterprise.json"
SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"


def _load_env() -> dict[str, str]:
    env = dict(os.environ)
    if env.get("DATABASE_URL") and not env.get("POSTGRES_DSN"):
        env["POSTGRES_DSN"] = env["DATABASE_URL"]
    return env


def _ensure_schema(cur) -> None:
    cur.execute(SCHEMA_PATH.read_text(encoding="utf-8"))


def _technique_ref(obj: dict) -> str:
    for reference in obj.get("external_references", []):
        external_id = reference.get("external_id")
        if reference.get("source_name") == "mitre-attack" and external_id:
            return str(external_id)
    return str(obj.get("id", ""))


def main() -> None:
    env = _load_env()
    config = load_postgres_config(env)

    with DATA_PATH.open("r", encoding="utf-8") as handle:
        bundle = json.load(handle)

    tactics_loaded = 0
    techniques_loaded = 0

    with create_connection(config) as conn:
        with conn.cursor() as cur:
            _ensure_schema(cur)

            # Remove legacy ATT&CK rows created before external refs were tracked.
            cur.execute(
                """
                DELETE FROM knowledge_entries
                WHERE source = 'mitre_attack'
                  AND external_ref IS NULL
                """
            )

            for obj in bundle["objects"]:
                otype = obj.get("type")

                if otype == "x-mitre-tactic":
                    cur.execute(
                        """
                        INSERT INTO knowledge_domains (name, description)
                        VALUES (%s, %s)
                        ON CONFLICT (name) DO UPDATE
                        SET description = EXCLUDED.description
                        """,
                        (obj["name"], obj.get("description", "")),
                    )
                    tactics_loaded += 1
                    continue

                if otype != "attack-pattern":
                    continue

                phases = obj.get("kill_chain_phases", [])
                tactic = phases[0].get("phase_name", "unknown") if phases else "unknown"

                cur.execute("SELECT id FROM knowledge_domains WHERE name = %s", (tactic,))
                row = cur.fetchone()
                domain_id = row["id"] if row else None
                external_ref = _technique_ref(obj)

                cur.execute(
                    """
                    INSERT INTO knowledge_entries
                      (domain_id, title, content, entry_type, source, external_ref, confidence)
                    VALUES (%s, %s, %s, 'threat', 'mitre_attack', %s, 0.95)
                    ON CONFLICT (source, external_ref) DO UPDATE
                    SET domain_id = EXCLUDED.domain_id,
                        title = EXCLUDED.title,
                        content = EXCLUDED.content,
                        entry_type = EXCLUDED.entry_type,
                        confidence = EXCLUDED.confidence
                    """,
                    (
                        domain_id,
                        obj.get("name"),
                        obj.get("description", ""),
                        external_ref,
                    ),
                )
                techniques_loaded += 1

        conn.commit()

    logger.info(
        "Knowledge base ingest complete tactics=%s techniques=%s",
        tactics_loaded,
        techniques_loaded,
    )
    print(
        f"Done - {tactics_loaded} tactics and {techniques_loaded} ATT&CK techniques synchronized into knowledge_entries"
    )


if __name__ == "__main__":
    main()
