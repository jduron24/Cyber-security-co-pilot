
<p align="center">
  © 2025 Jonathan Duron, Eli Talbert, Anthony Cordetti, Maryam Shahbaz Ali
  <br>
  Released under the MIT License.
</p>

---

# Cyber Security Co-Pilot - From Logs to Decisions: Interpretable AI for Security Operations

Cyber Security Co-Pilot is an interpretable incident-analysis system designed to transform raw AWS CloudTrail logs into structured incidents, explainable risk signals, and actionable decision support. The system combines a deterministic data pipeline, weak supervision, baseline modeling, and a FraudLens-style explanation layer to convert complex event streams into clear, human-readable security insights. It is built for transparency, auditability, and effective analyst workflows in modern cloud security operations.

---

## Key features

* **End-to-end CloudTrail pipeline** – ingests raw logs (including archives), normalizes them into a canonical schema, derives features, and groups events into time-bounded incidents while preserving provenance and context.
* **Weak supervision and baseline modeling** – generates rule-based suspiciousness labels and trains a baseline incident scoring model to prioritize and triage potential threats.
* **FraudLens-style explainability adapter** – translates model outputs into interpretable, feature-level explanations that highlight why an incident is considered risky.
* **Decision-support engine** – produces structured, non-expert-facing recommendations, alternative actions, and escalation paths based on incident context and policy rules.
* **Model-agnostic agent (ReAct-based)** – enables grounded querying of incidents using OpenAI-compatible APIs, with tool-based reasoning over incident context, evidence, and decision-support outputs.
* **Backend and UI integration** – includes a FastAPI backend, Streamlit Sentinel UI, and optional MCP-based cyber knowledge integration for extended context retrieval.

---

## Repository layout

```Cyber-security-co-pilot/
│
├── src/                                # Core pipeline and logic
│   ├── ingest.py
│   ├── normalize.py
│   ├── derive_features.py
│   ├── build_incidents.py
│   ├── weak_label.py
│   ├── train_model.py
│   ├── cyber_fraudlens_adapter.py
│   ├── decision_support_bridge.py
│   ├── demo_stream.py
│   ├── demo_runner.py
│   ├── validate.py
│   ├── export.py
│   │
│   ├── services/                       # Application services
│   ├── repositories/                   # Postgres data layer
│   ├── db/                             # Schema and DB utilities
│   └── agent/                          # ReAct agent module
│
├── backend/                            # FastAPI backend
├── frontend/                           # Frontend components
├── agent_backend/                      # Agent service wrapper
├── decision_support/                   # Decision engine package
├── mcp_server/                         # Optional knowledge server
├── configs/                            # Pipeline and policy configs
├── scripts/                            # Local startup scripts
├── data/                               # Input and processed data
├── reports/                            # Reports and outputs
├── artifacts/                          # Trained models
├── .doc/                               # Knowledge base (features + patterns)
├── tests/                              # Unit and integration tests
├── notebooks/                          # Exploration notebooks
├── sentinel_app.py                     # Streamlit UI
├── requirements.txt                    # Dependencies
├── README.md                           # Main README
└── LICENSE                             # MIT License
```

---

## Getting started

### Prerequisites

* Python 3.10+
* Optional: PostgreSQL database for full system functionality
* Optional: OpenAI-compatible API endpoint
* Optional: Node.js (for MCP server integration)

---

### Installation

1. Create and activate a virtual environment (optional but recommended).
2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

---

### Running the pipeline

From the project root:

```bash
python -m src.main --project-root .
```

Enable debug logging:

```bash
LOG_LEVEL=DEBUG python -m src.main --project-root .
```

---

### Demo scenarios

Generate synthetic CloudTrail scenarios:

```bash
python -m src.demo_stream --output-dir data/demo_stream --batch-size 1
```

Run the full pipeline on demo data:

```bash
python -m src.demo_runner --project-root . --output-dir data/demo_run --batch-size 1
```

---

### Model training

```bash
python -m src.train_model --project-root .
```

---

### Explainability (FraudLens adapter)

Single incident:

```bash
python -m src.cyber_fraudlens_adapter --project-root . --incident-id incident_000000001
```

Batch scoring:

```bash
python -m src.cyber_fraudlens_adapter --project-root . --output data/processed/incidents_adapter_scored.parquet
```

---

### Decision support

```bash
python -c "from src.decision_support_bridge import generate_decision_support_for_incident; import json; print(json.dumps(generate_decision_support_for_incident('incident_000000001', project_root='.'), indent=2))"
```

---

### Backend services

Run FastAPI backend:

```bash
uvicorn backend.main:app --reload
```

Start locally (Windows):

```powershell
.\scripts\start_local.ps1
```

Start with MCP server:

```powershell
.\scripts\start_local.ps1 -IncludeMcpServer
```

Stop services:

```powershell
.\scripts\stop_local.ps1
```

---

### Agent usage

```bash
python -c "from src.services.agent_app_service import query_incident_agent; import json; print(json.dumps(query_incident_agent('incident_000000001', 'What should I do next?', env={'POSTGRES_DSN':'postgresql://user:pass@localhost:5432/cyber','OPENAI_MODEL':'gpt-5.4','OPENAI_API_KEY':'your_key'}), indent=2))"
```

The agent:

* loads incident context, evidence, and detector outputs from Postgres
* selects grounded tools for reasoning
* generates decision support when needed
* enforces bounded reasoning for auditability

---

## Outputs

* Processed events and incident datasets
* Labeled and scored incident data
* Model evaluation reports
* Decision-support outputs
* Knowledge base artifacts

---

## Configuration

* `configs/pipeline_config.yaml`
* `configs/event_flag_rules.yaml`
* `configs/decision_policy.yaml`

---

## Acknowledgments

This project was developed to advance interpretable AI in cybersecurity, focusing on transparency, auditability, and human-centered decision-making in security operations.

---

## License
