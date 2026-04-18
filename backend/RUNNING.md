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
RESEND_API_KEY=re_xxxxxxxxx
ALERT_EMAIL_FROM=Sentinel <alerts@yourdomain.com>
ALERT_EMAIL_TO=you@example.com,ops@example.com
ALERT_EMAIL_ENABLED=true
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

### Example high-priority alert trigger
If an incident has `severity_hint = high`, generating decision support will automatically attempt a Resend email alert once per incident/recipient:

```bash
curl "http://localhost:8000/incidents/incident_000000001/decision-support"
```

### Hourly alert scan
To scan the last hour of high-severity incidents and send deduplicated email alerts:

```bash
backend/.venv/bin/python scripts/send_hourly_alerts.py --lookback-hours 1 --limit 100
```

Example cron entry to run the scan every hour:

```bash
0 * * * * cd /Users/jonathanduron/Desktop/gitRepos/cyber-co-pilot && /Users/jonathanduron/Desktop/gitRepos/cyber-co-pilot/backend/.venv/bin/python scripts/send_hourly_alerts.py --lookback-hours 1 --limit 100 >> /tmp/sentinel-hourly-alerts.log 2>&1
```
