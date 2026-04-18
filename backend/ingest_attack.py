import json
import os
from pathlib import Path

from dotenv import load_dotenv

from src.db.connection import create_connection, load_postgres_config
from src.logging_utils import configure_logging, get_logger

load_dotenv()
configure_logging()
logger = get_logger(__name__)

env = dict(os.environ)
if env.get("DATABASE_URL") and not env.get("POSTGRES_DSN"):
    env["POSTGRES_DSN"] = env["DATABASE_URL"]
conn = create_connection(load_postgres_config(env))
cur = conn.cursor()

DATA_PATH = Path(__file__).resolve().parents[1] / "data" / "enterprise.json"

with DATA_PATH.open("r", encoding="utf-8") as f:
    bundle = json.load(f)

tactics_inserted = 0
techniques_inserted = 0

for obj in bundle["objects"]:
    otype = obj.get("type")

    if otype == "x-mitre-tactic":
        cur.execute("""
            INSERT INTO knowledge_domains (name, description)
            VALUES (%s, %s) ON CONFLICT (name) DO NOTHING
        """, (obj["name"], obj.get("description", "")))
        tactics_inserted += 1

    if otype == "attack-pattern":
        phases = obj.get("kill_chain_phases", [])
        tactic = phases[0].get("phase_name", "unknown") if phases else "unknown"

        cur.execute("SELECT id FROM knowledge_domains WHERE name = %s", (tactic,))
        row = cur.fetchone()
        domain_id = row[0] if row else None

        cur.execute("""
            INSERT INTO knowledge_entries
              (domain_id, title, content, entry_type, source, confidence)
            VALUES (%s, %s, %s, 'threat', 'mitre_attack', 0.95)
        """, (
            domain_id,
            obj.get("name"),
            obj.get("description", ""),
        ))
        techniques_inserted += 1

conn.commit()
cur.close()
conn.close()

logger.info("Knowledge base ingest complete tactics=%s techniques=%s", tactics_inserted, techniques_inserted)
print(f"Done - {tactics_inserted} tactics, {techniques_inserted} techniques loaded into knowledge_entries")
