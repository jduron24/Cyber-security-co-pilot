# Running the Backend

## 1. Create and activate virtual environment
```bash
python -m venv .venv
. .venv/bin/activate
```

## 2. Install dependencies
```bash
pip install -r requirements.txt
```

## 3. Configure environment
Edit `.env` and set your database URL:
```
POSTGRES_DSN=postgresql://jonathanduron@localhost:5432/cyber_copilot
```

## 4. Start PostgreSQL
```bash
brew services start postgresql@15
```

## 5. Set up the database (first time only)
```bash
# Create the main application tables
psql -U jonathanduron -d cyber_copilot -f ../src/db/schema.sql

# Create the knowledge-base tables
psql -U jonathanduron -d cyber_copilot -f schema.sql

# Add full-text search index
psql -d cyber_copilot -f search_setup.sql

# Ingest MITRE ATT&CK data
python ingest_attack.py
```

## 6. Start the API
```bash
uvicorn backend.main:app --reload
```

API runs at: http://localhost:8000
Docs at:     http://localhost:8000/docs

## Endpoints
| Method | Path      | Description                        |
|--------|-----------|------------------------------------|
| GET    | /         | Health check                       |
| GET    | /health   | Status check                       |
| GET    | /search   | Search MITRE KB by keyword         |
| GET    | /incidents/{id} | Load stored incident context  |
| GET    | /incidents/{id}/decision-support | Generate or fetch decision support |
| GET    | /incidents/{id}/coverage-review | Build operator-facing coverage review |
| POST   | /incidents/{id}/approve | Record recommendation approval |
| POST   | /incidents/{id}/alternative | Record alternative choice |
| POST   | /incidents/{id}/escalate | Record escalation |
| POST   | /incidents/{id}/double-check | Record request for more analysis |
| POST   | /incidents/{id}/agent-query | Run the grounded incident agent |

### Example search
```bash
curl "http://localhost:8000/search?q=brute+force+login"
```
