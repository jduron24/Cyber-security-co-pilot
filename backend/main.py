import os
import re
import psycopg2
import psycopg2.extras
from fastapi import FastAPI, Query
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()
DB_URL = os.getenv("DATABASE_URL", "postgresql://jonathanduron@localhost:5432/cyber_copilot")


def get_conn():
    return psycopg2.connect(DB_URL)


def normalize_query(text: str) -> str:
    text = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '', text)
    text = re.sub(r':\d{2,5}\b', '', text)
    text = re.sub(r'\d{4}-\d{2}-\d{2}T[\d:Z.]+', '', text)
    tokens = [w for w in text.strip().split() if len(w) > 3]
    return ' & '.join(tokens)


def search_kb(query: str, limit: int = 5) -> list:
    tsquery = normalize_query(query)
    if not tsquery:
        return []
    conn = get_conn()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT title, content, entry_type, kd.name AS domain,
               ts_rank(ke.search_vector, to_tsquery('english', %s)) AS score
        FROM knowledge_entries ke
        LEFT JOIN knowledge_domains kd ON ke.domain_id = kd.id
        WHERE ke.search_vector @@ to_tsquery('english', %s)
        ORDER BY score DESC
        LIMIT %s
    """, (tsquery, tsquery, limit))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return [dict(r) for r in rows]


@app.get("/")
def root():
    return {"message": "Hello from Cyber Co-Pilot API"}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/search")
def search(q: str = Query(...), limit: int = 5):
    return {"results": search_kb(q, limit)}
