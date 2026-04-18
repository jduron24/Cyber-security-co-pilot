import json
import psycopg2
import os
from dotenv import load_dotenv

load_dotenv()

DB_URL = os.getenv("DATABASE_URL", "postgresql://localhost/cyber_copilot")

conn = psycopg2.connect(DB_URL)
cur = conn.cursor()

DATA_PATH = os.path.join(os.path.dirname(__file__), "../data/enterprise.json")

with open(DATA_PATH) as f:
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

print(f"Done — {tactics_inserted} tactics, {techniques_inserted} techniques loaded into knowledge_entries")
