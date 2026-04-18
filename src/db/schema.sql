CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    title TEXT,
    summary TEXT,
    severity_hint TEXT,
    start_time TIMESTAMPTZ,
    end_time TIMESTAMPTZ,
    primary_actor JSONB,
    entities JSONB,
    event_sequence JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS incident_events (
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    event_id TEXT NOT NULL,
    event_time TIMESTAMPTZ,
    event_name TEXT,
    event_source TEXT,
    event_index INTEGER,
    event_payload JSONB NOT NULL,
    PRIMARY KEY (incident_id, event_id)
);

CREATE TABLE IF NOT EXISTS evidence_packages (
    evidence_package_id BIGSERIAL PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    summary_json JSONB NOT NULL,
    provenance_json JSONB,
    raw_refs_json JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_evidence_packages_incident_id ON evidence_packages(incident_id);
CREATE INDEX IF NOT EXISTS idx_evidence_packages_summary_json_gin ON evidence_packages USING GIN(summary_json);

CREATE TABLE IF NOT EXISTS detector_results (
    detector_result_id BIGSERIAL PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    risk_score DOUBLE PRECISION,
    risk_band TEXT,
    top_signals_json JSONB NOT NULL,
    counter_signals_json JSONB,
    detector_labels_json JSONB,
    retrieved_patterns_json JSONB,
    data_sources_used_json JSONB,
    model_type TEXT,
    explanation_json JSONB,
    feature_contributions_json JSONB,
    model_version TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE detector_results ADD COLUMN IF NOT EXISTS model_type TEXT;
ALTER TABLE detector_results ADD COLUMN IF NOT EXISTS explanation_json JSONB;
ALTER TABLE detector_results ADD COLUMN IF NOT EXISTS feature_contributions_json JSONB;

CREATE INDEX IF NOT EXISTS idx_detector_results_incident_id ON detector_results(incident_id);

CREATE TABLE IF NOT EXISTS coverage_assessments (
    coverage_assessment_id BIGSERIAL PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    completeness_level TEXT NOT NULL,
    incompleteness_reasons_json JSONB NOT NULL,
    checks_json JSONB NOT NULL,
    missing_sources_json JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_coverage_assessments_incident_id ON coverage_assessments(incident_id);

CREATE TABLE IF NOT EXISTS policy_snapshots (
    policy_version TEXT PRIMARY KEY,
    policy_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS decision_support_results (
    decision_support_result_id BIGSERIAL PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    result_json JSONB NOT NULL,
    validation_json JSONB NOT NULL,
    llm_trace_json JSONB NOT NULL,
    policy_version TEXT REFERENCES policy_snapshots(policy_version),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_decision_support_results_incident_id ON decision_support_results(incident_id);

CREATE TABLE IF NOT EXISTS operator_decisions (
    operator_decision_id BIGSERIAL PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    decision_type TEXT NOT NULL,
    selected_from TEXT NOT NULL,
    chosen_action_id TEXT,
    chosen_action_label TEXT,
    rationale TEXT,
    used_double_check BOOLEAN NOT NULL DEFAULT FALSE,
    actor_json JSONB,
    coverage_review_json JSONB NOT NULL,
    decision_support_result_json JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_operator_decisions_incident_id ON operator_decisions(incident_id);

CREATE TABLE IF NOT EXISTS decision_review_events (
    decision_review_event_id BIGSERIAL PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    actor_json JSONB,
    payload_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_decision_review_events_incident_id ON decision_review_events(incident_id);

CREATE TABLE IF NOT EXISTS incident_notifications (
    incident_notification_id BIGSERIAL PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    channel TEXT NOT NULL,
    alert_type TEXT NOT NULL,
    recipient TEXT NOT NULL,
    dedupe_key TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL,
    provider_message_id TEXT,
    payload_json JSONB NOT NULL,
    sent_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_incident_notifications_incident_id ON incident_notifications(incident_id);
