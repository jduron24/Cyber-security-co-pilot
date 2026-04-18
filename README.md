# Cyber-security-co-pilot

CloudTrail normalization pipeline for the flaws.cloud dataset.

## Run

From the project root:

```bash
python -m src.main --project-root .
```

To increase log detail during integration/debugging:

```bash
LOG_LEVEL=DEBUG python -m src.main --project-root .
```

To generate the purpose-doc demo stream with synthetic CloudTrail batches for the blind-spot scenarios:

```bash
python -m src.demo_stream --output-dir data/demo_stream --batch-size 1
```

To run the current pipeline against the purpose-doc demo scenarios end to end:

```bash
python -m src.demo_runner --project-root . --output-dir data/demo_run --batch-size 1
```

To generate weak suspiciousness labels on incidents and train the baseline incident model:

```bash
python -m src.train_model --project-root .
```

To use the FraudLens-style cyber adapter for single-incident explanation:

```bash
python -m src.cyber_fraudlens_adapter --project-root . --incident-id incident_000000001
```

To score a batch of incidents through the same adapter:

```bash
python -m src.cyber_fraudlens_adapter --project-root . --output data/processed/incidents_adapter_scored.parquet
```

To generate non-expert-facing decision support for a scored incident:

```bash
python -c "from src.decision_support_bridge import generate_decision_support_for_incident; import json; print(json.dumps(generate_decision_support_for_incident('incident_000000001', project_root='.'), indent=2))"
```

To use the Postgres-ready application layer, create the schema from [`src/db/schema.sql`](C:/Users/ejtal/Downloads/judgment_drift/Cyber-security-co-pilot/src/db/schema.sql), store incident context, evidence packages, detector results, coverage assessments, and policy snapshots, then call the app service around the pure `decision_support` package.

To run the FastAPI backend as the HTTP wrapper around the shared service layer:

```bash
uvicorn backend.main:app --reload
```

To start the local backend service with one command on Windows PowerShell:

```powershell
.\scripts\start_local.ps1
```

To also start the MCP server:

```powershell
.\scripts\start_local.ps1 -IncludeMcpServer
```

To stop the locally started services:

```powershell
.\scripts\stop_local.ps1
```

The startup script writes logs and PID/state metadata under `.local/services/`.

To build the operator-facing coverage review object that emphasizes blind spots and double-check paths:

```bash
python -c "from src.services.coverage_review_service import CoverageReviewAppService; print('Use CoverageReviewAppService with the Postgres repository bundle to assemble operator review payloads.')"
```

To record the human decision and audit trail after review:

```bash
python -c "from src.services.operator_decision_service import OperatorDecisionAppService; print('Use OperatorDecisionAppService to record approved recommendations, alternative choices, escalations, and double-check requests.')"
```

To query the new model-agnostic agent against a Postgres-backed incident using any OpenAI-compatible chat endpoint:

```bash
python -c "from src.services.agent_app_service import query_incident_agent; import json; print(json.dumps(query_incident_agent('incident_000000001', 'What should I do next?', env={'POSTGRES_DSN':'postgresql://user:pass@localhost:5432/cyber', 'OPENAI_MODEL':'gpt-4.1-mini', 'OPENAI_BASE_URL':'https://your-endpoint.example/v1', 'OPENAI_API_KEY':'token'}), indent=2))"
```

The agent is model-agnostic at the application boundary and now uses a bounded ReAct loop:
- it loads incident context, evidence packages, detector outputs, coverage state, and prior decision-support results from Postgres
- it lets the model choose among grounded tools such as `load_incident`, `load_detector_result`, `load_coverage_assessment`, `load_decision_support`, and `generate_decision_support`
- it generates decision support on demand if the database does not already have one
- it sends a standard OpenAI-style `chat/completions` request to the configured endpoint
- it limits reasoning to `AGENT_MAX_REASONING_STEPS` to keep execution bounded and auditable

For local testing, the agent can also reuse the Codex desktop auth token instead of a normal API key:

```powershell
$env:OPENAI_BASE_URL="https://api.openai.com/v1"
$env:OPENAI_MODEL="gpt-4.1-mini"
$env:AGENT_USE_CODEX_AUTH="1"
```

Notes:
- this reads the access token from `~/.codex/auth.json`
- it is intended for local testing only
- it is only supported against `https://api.openai.com/v1`
- for any other OpenAI-compatible endpoint, set `OPENAI_API_KEY` normally

Default config lives in `configs/pipeline_config.yaml` and behavioral flag rules live in `configs/event_flag_rules.yaml`.

## Outputs

- `data/processed/events_flat.parquet`
- `data/processed/events_flat.csv`
- `data/processed/events_flat/` partitioned by `event_date`
- `data/processed/incidents.parquet`
- `data/processed/incidents/` partitioned by `incident_start_date`
- `reports/data_quality_report.json`
- `reports/schema.json`
- `reports/feature_dictionary.md`
- `data/processed/incidents_labeled.parquet`
- `data/processed/incidents_scored.parquet`
- `reports/incident_label_report.json`
- `reports/incident_model_report.json`
- `artifacts/incident_suspicion_model.joblib`
- `.doc/cyber_knowledge_base_features.csv`
- `.doc/cyber_knowledge_base_patterns.md`
- `configs/decision_policy.yaml`
- `src/db/schema.sql`

## Structure

- `src/ingest.py`: scans input files and tar archives, parses CloudTrail payloads, and preserves provenance
- `src/normalize.py`: flattens CloudTrail records into a canonical event table
- `src/derive_features.py`: adds ordering keys, convenience flags, missingness states, and rolling counts
- `src/build_incidents.py`: groups ordered events into inactivity-bounded incidents
- `src/demo_stream.py`: generates synthetic CloudTrail-style demo scenarios for incomplete, complete, and unavailable-context operator flows
- `src/demo_runner.py`: runs the existing ingestion, normalization, feature, incident, weak-label, decision-support, and coverage-review flow over the demo scenarios
- `src/validate.py`: builds schema metadata and validation summaries
- `src/export.py`: writes parquet, CSV, and report artifacts
- `src/weak_label.py`: assigns rule-based weak suspiciousness labels to incidents
- `src/train_model.py`: trains and scores the baseline incident suspicion model
- `src/cyber_fraudlens_adapter.py`: FraudLens-style scoring and explanation adapter for incident review
- `src/decision_support_bridge.py`: converts scored incidents into decision-support inputs and calls the standalone service
- `src/db/`: Postgres connection utilities and starter schema
- `src/repositories/`: Postgres repository layer for incident context, evidence packages, detector outputs, policy snapshots, and saved decision-support results
- `src/repositories/service_bundles.py`: narrow repository bundles for decision support, coverage review, operator workflow, and agent access
- `src/services/decision_support_app_service.py`: application service that assembles DB records into the pure decision-support inputs
- `src/services/coverage_review_service.py`: operator-facing blind-spot review service that assembles recommendation, alternatives, completeness, and double-check candidates
- `src/services/operator_decision_service.py`: records operator approvals, alternative choices, escalations, and double-check requests with snapshots of what the user saw
- `src/services/dtos.py`: typed service-layer DTOs used to reduce dict-shape coupling between services
- `src/agent/`: model-agnostic ReAct agent module that grounds chat responses in Postgres-backed context and decision-support outputs
- `src/services/agent_app_service.py`: application factory and convenience entrypoint for OpenAI-compatible incident queries
- `decision_support/`: standalone package for deterministic non-expert decision guidance
- `notebooks/sanity_checks.ipynb`: starter notebook for quick inspection
## Sentinel UI

The Streamlit demo client in [sentinel_app.py](/C:/Users/ejtal/Downloads/judgment_drift/Cyber-security-co-pilot/sentinel_app.py) is wired to the FastAPI backend over HTTP.

Start the backend locally:

```powershell
.\scripts\start_local.ps1
```

This starts the core FastAPI backend on `:8000` and the dedicated agent service on `:8001`.

Run the Sentinel UI:

```powershell
$env:SENTINEL_BACKEND_URL="http://127.0.0.1:8000"
$env:SENTINEL_AGENT_URL="http://127.0.0.1:8001"
.\.venv\Scripts\python.exe -m streamlit run .\sentinel_app.py
```

If the backend is unavailable, the app falls back to a built-in mock incident bundle so the UI still renders.
