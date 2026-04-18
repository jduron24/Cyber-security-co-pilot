# Running the Backend

## 1. Create and activate virtual environment
```bash
python -m venv .venv
source .venv/bin/activate
```

## 2. Install dependencies
```bash
pip install -r requirements.txt
```

## 3. Configure environment
Edit `.env` and set your database URL:
```
DATABASE_URL=postgresql://jonathanduron@localhost:5432/cyber_copilot
```

## 4. Start PostgreSQL
```bash
brew services start postgresql@15
```

## 5. Set up the database (first time only)
```bash
# Create tables
psql -U jonathanduron -d cyber_copilot -f schema.sql

# Add full-text search index
psql -d cyber_copilot -f search_setup.sql

# Ingest MITRE ATT&CK data
python ingest_attack.py
```

## 6. Start the API
```bash
uvicorn main:app --reload
```

API runs at: http://localhost:8000
Docs at:     http://localhost:8000/docs

## Endpoints
| Method | Path      | Description                        |
|--------|-----------|------------------------------------|
| GET    | /         | Health check                       |
| GET    | /health   | Status check                       |
| GET    | /search   | Search MITRE KB by keyword         |

### Example search
```bash
curl "http://localhost:8000/search?q=brute+force+login"
```
