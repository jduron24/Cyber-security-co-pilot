"use client";

import { useEffect, useMemo, useState } from "react";

import { ApiError, listIncidents, loadIncidentWorkspace } from "@/lib/api";
import type { RecordShape } from "@/types/api";

const fallbackQueue = [
  { id: "INC-1042", site: "Water Plant East", severity: "High", state: "Needs review" },
  { id: "INC-1038", site: "County Records", severity: "Medium", state: "Monitoring" },
  { id: "INC-1033", site: "City Hospital Annex", severity: "Low", state: "Closed" },
];

const fallbackSignals = [
  "17 failed sign-in attempts in 3 minutes from an unfamiliar source",
  "The same account moved from sign-in failures into identity lookups",
  "Access-key related activity appeared after the login burst",
];

const fallbackTimeline = [
  {
    time: "08:41",
    title: "Unusual sign-in activity detected",
    detail: "Sentinel saw repeated failed attempts against a privileged operations account.",
    tone: "critical",
  },
  {
    time: "08:44",
    title: "Behavior changed from login failures to account discovery",
    detail: "The same source began calling identity and account-related APIs.",
    tone: "warning",
  },
  {
    time: "08:47",
    title: "Recommended response prepared for human approval",
    detail: "Sentinel selected the safest immediate step and flagged the remaining uncertainty.",
    tone: "action",
  },
];

const fallbackCoverage = [
  { label: "Login telemetry", status: "Checked", note: "Suspicious pattern confirmed" },
  { label: "Identity activity", status: "Checked", note: "Privilege-related actions present" },
  { label: "Network telemetry", status: "Missing", note: "Still needed before final containment" },
];

const fallbackActions = [
  {
    label: "Temporarily lock access",
    kind: "Recommended",
    detail: "Fastest safe containment step while preserving time for a supervisor review.",
  },
  {
    label: "Escalate to expert",
    kind: "Alternative",
    detail: "Best if this account supports essential services or if downtime risk is high.",
  },
  {
    label: "Collect more evidence",
    kind: "Alternative",
    detail: "Use if the operator needs the missing network branch before approving disruption.",
  },
];

const auditTrail = [
  "08:48 AM — Recommendation created and marked as approval-required.",
  "08:49 AM — Coverage warning added: network telemetry missing.",
  "08:50 AM — Operator opened incident workspace for review.",
];

function StatusPill({
  children,
  tone = "neutral",
}: {
  children: React.ReactNode;
  tone?: "critical" | "warning" | "safe" | "neutral";
}) {
  return <span className={`status-pill status-pill--${tone}`}>{children}</span>;
}

function asRecord(value: unknown): RecordShape {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as RecordShape) : {};
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function asString(value: unknown, fallback = "Unavailable"): string {
  return typeof value === "string" && value.trim() ? value : fallback;
}

function toSentenceCase(value: string): string {
  if (!value) return "Unavailable";
  return value
    .split(/[_-]/g)
    .map((part) => (part ? part[0].toUpperCase() + part.slice(1) : part))
    .join(" ");
}

const signalExplanationMap: Record<string, string> = {
  recon_activity: "This account was looking around the environment before taking further action.",
  privilege_change: "Permissions or access levels were changed during this incident.",
  resource_creation: "New resources or infrastructure were created.",
  console_login: "Someone signed in through the AWS console.",
  root_actor: "The AWS root account was involved, which carries extra risk.",
  assumed_role_actor: "An assumed role was used, which can make activity harder to trace quickly.",
  high_failure_ratio: "A large share of the activity failed, which can point to misuse or trial-and-error behavior.",
  failure_burst: "There was a burst of failed activity in a short period.",
  event_burst: "A high number of actions happened in a short window.",
  broad_surface_area: "The activity touched many different actions or services.",
  iam_sequence: "The sequence included IAM activity related to identity and permissions.",
  sts_sequence: "The sequence included temporary credential or role-assumption activity.",
  ec2_sequence: "The sequence included EC2 infrastructure activity.",
  recon_plus_privilege: "The actor first explored the environment, then changed permissions.",
  recon_plus_resource_creation: "The actor first explored the environment, then created resources.",
  privilege_plus_resource_creation: "Permissions changed and new resources were created in the same incident.",
  root_plus_privilege: "The root account was used together with permission-changing activity.",
};

function explainSignal(value: string): string {
  const normalized = value.trim().toLowerCase();
  if (!normalized) return "Suspicious activity was detected.";
  return signalExplanationMap[normalized] ?? toSentenceCase(value);
}

function mapQueueItem(item: RecordShape) {
  const entities = asRecord(item.entities);
  return {
    id: asString(item.incident_id, "incident"),
    site: asString(entities.primary_source_ip_address ?? item.title, "Unknown site"),
    severity: toSentenceCase(asString(item.severity_hint, "unknown")),
    state: "Needs review",
  };
}

export default function Home() {
  const [selectedView, setSelectedView] = useState<"active" | "audit">("active");
  const [showDebug, setShowDebug] = useState(false);
  const [queue, setQueue] = useState(fallbackQueue);
  const [queueError, setQueueError] = useState<string | null>(null);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string>(fallbackQueue[0].id);
  const [incident, setIncident] = useState<RecordShape | null>(null);
  const [decisionSupport, setDecisionSupport] = useState<RecordShape | null>(null);
  const [coverageReview, setCoverageReview] = useState<RecordShape | null>(null);
  const [incidentLoading, setIncidentLoading] = useState(false);
  const [incidentError, setIncidentError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function loadQueue() {
      try {
        const result = await listIncidents();
        if (cancelled || result.length === 0) return;
        const mapped = result.map(mapQueueItem);
        setQueue(mapped);
        setSelectedIncidentId(mapped[0].id);
        setQueueError(null);
      } catch (error) {
        if (cancelled) return;
        setQueueError(error instanceof ApiError ? error.message : "Could not load incidents.");
      }
    }

    void loadQueue();

    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;

    async function loadDetails() {
      if (!selectedIncidentId.startsWith("incident_")) {
        return;
      }
      setIncidentLoading(true);
      setIncidentError(null);
      try {
        const result = await loadIncidentWorkspace(selectedIncidentId);
        if (cancelled) return;
        setIncident(result.incident);
        setDecisionSupport(result.decisionSupport);
        setCoverageReview(result.coverageReview);
      } catch (error) {
        if (cancelled) return;
        setIncidentError(error instanceof ApiError ? error.message : "Could not load incident details.");
        setIncident(null);
        setDecisionSupport(null);
        setCoverageReview(null);
      } finally {
        if (!cancelled) {
          setIncidentLoading(false);
        }
      }
    }

    void loadDetails();

    return () => {
      cancelled = true;
    };
  }, [selectedIncidentId]);

  const summary = useMemo(() => {
    const coverageReviewRecord = asRecord(coverageReview);
    const incidentSummary = asRecord(coverageReviewRecord.incident_summary);
    const decisionSupportRecord = asRecord(decisionSupport);
    const decisionSupportResult = asRecord(decisionSupportRecord.decision_support_result);
    const recommendedAction = asRecord(decisionSupportResult.recommended_action);

    const signals = asArray(incidentSummary.top_signals)
      .map((item) => explainSignal(asString(asRecord(item).label, "Signal")))
      .filter(Boolean);

    const coverageItems = asArray(coverageReviewRecord.coverage_status_by_category).map((item) => {
      const row = asRecord(item);
      return {
        label: toSentenceCase(asString(row.category, "coverage")),
        status: toSentenceCase(asString(row.status, "unknown")),
        note:
          asArray(row.missing_sources).map((source) => asString(source, "")).filter(Boolean).join(", ") ||
          `${toSentenceCase(asString(row.status, "unknown"))} coverage state`,
      };
    });

    const alternatives = asArray(coverageReviewRecord.alternative_actions).map((item) => {
      const row = asRecord(item);
      return {
        label: asString(row.label ?? row.action_id, "Alternative"),
        kind: "Alternative",
        detail: asString(row.tradeoff ?? row.reason, "No tradeoff available."),
      };
    });

    const timeline = asArray(asRecord(incident).event_sequence).slice(0, 5).map((item, index) => ({
      time: `Step ${index + 1}`,
      title: asString(item, "Activity"),
      detail: index === 0 ? "Part of the observed incident sequence." : "Observed later in the same incident.",
      tone: index === 0 ? "critical" : "warning",
    }));

    return {
      title: asString(incidentSummary.title ?? asRecord(incident).title, "Suspicious access activity"),
      incidentId: asString(asRecord(incident).incident_id, selectedIncidentId),
      severity: toSentenceCase(asString(incidentSummary.risk_band ?? asRecord(incident).severity_hint, "high")),
      site: asString(
        asRecord(asRecord(incident).entities).primary_source_ip_address ?? asRecord(incident).title,
        "Unknown site",
      ),
      summary: asString(
        incidentSummary.summary ?? asRecord(incident).summary,
        "Sentinel is ready to summarize this incident once backend detail is available.",
      ),
      recommendedAction: {
        label: asString(recommendedAction.label ?? recommendedAction.action_id, fallbackActions[0].label),
        detail: asString(
          recommendedAction.reason ?? coverageReviewRecord.decision_risk_note,
          fallbackActions[0].detail,
        ),
      },
      confidence:
        typeof incidentSummary.risk_score === "number" ? Math.round(incidentSummary.risk_score * 100) : 84,
      signals: signals.length ? signals : fallbackSignals,
      coverage: coverageItems.length ? coverageItems : fallbackCoverage,
      actions: alternatives.length ? alternatives : fallbackActions,
      timeline: timeline.length ? timeline : fallbackTimeline,
    };
  }, [coverageReview, decisionSupport, incident, selectedIncidentId]);

  return (
    <main className="sentinel-shell">
      <div className="sentinel-orb sentinel-orb--left" />
      <div className="sentinel-orb sentinel-orb--right" />

      <div className="app-frame reveal reveal-delay-1">
        <aside className="left-rail">
          <div className="brand-block">
            <p className="eyebrow">Sentinel</p>
            <h1>Operator Console</h1>
            <p>Clear cyber guidance for teams without dedicated security staff.</p>
          </div>

          <nav className="nav-stack">
            <button
              className={`nav-item${selectedView === "active" ? " nav-item--active" : ""}`}
              onClick={() => setSelectedView("active")}
            >
              Active incident
            </button>
            <button
              className={`nav-item${selectedView === "audit" ? " nav-item--active" : ""}`}
              onClick={() => setSelectedView("audit")}
            >
              Audit trail
            </button>
            <button
              className={`nav-item${showDebug ? " nav-item--active" : ""}`}
              onClick={() => setShowDebug((value) => !value)}
            >
              {showDebug ? "Hide debug" : "Show debug"}
            </button>
          </nav>

          <section className="queue-panel">
            <div className="rail-heading">
              <span>Incident queue</span>
              <strong>{queue.length} loaded</strong>
            </div>
            {queueError ? <p className="queue-error">{queueError}</p> : null}
            <div className="queue-list">
              {queue.map((item) => (
                <button
                  className={`queue-item${item.id === selectedIncidentId ? " queue-item--active" : ""}`}
                  key={item.id}
                  onClick={() => setSelectedIncidentId(item.id)}
                  type="button"
                >
                  <div>
                    <strong>{item.id}</strong>
                    <p>{item.site}</p>
                  </div>
                  <div className="queue-meta">
                    <span>{item.severity}</span>
                    <small>{item.state}</small>
                  </div>
                </button>
              ))}
            </div>
          </section>
        </aside>

        <section className="workspace">
          {selectedView === "active" ? (
            <>
              <header className="topbar">
                <div>
                  <p className="eyebrow">Current incident</p>
                  <h2>{summary.incidentId} • {summary.site}</h2>
                </div>
                <div className="topbar-meta">
                  <StatusPill tone="critical">{summary.severity}</StatusPill>
                  <StatusPill tone="warning">{incidentLoading ? "Loading details" : "Details loaded"}</StatusPill>
                  <StatusPill tone="safe">Audit active</StatusPill>
                </div>
              </header>

              {incidentError ? <div className="warning-banner">{incidentError}</div> : null}

              <section className="hero-strip reveal reveal-delay-2">
                <article className="card card--hero-main">
                  <div className="card-heading">
                    <span className="card-kicker">Plain-language summary</span>
                    <StatusPill tone="critical">Live</StatusPill>
                  </div>
                  <h3>{summary.title}</h3>
                  <p>{summary.summary}</p>
                </article>

                <article className="card card--hero-side">
                  <div className="card-heading">
                    <span className="card-kicker">Recommended action</span>
                    <StatusPill tone="warning">Human in the loop</StatusPill>
                  </div>
                  <h3>{summary.recommendedAction.label}</h3>
                  <p>{summary.recommendedAction.detail}</p>
                  <div className="action-stack">
                    <button className="cta cta--primary">Approve action</button>
                    <button className="cta cta--secondary">Review alternatives</button>
                  </div>
                </article>
              </section>

              <section className="dashboard-grid dashboard-grid--app">
                <article className="card card--primary reveal reveal-delay-2">
                  <div className="card-heading">
                    <span className="card-kicker">Why Sentinel is concerned</span>
                    <StatusPill tone="warning">{summary.signals.length} strong signals</StatusPill>
                  </div>
                  <ul className="signal-list">
                    {summary.signals.map((signal) => (
                      <li key={signal}>{signal}</li>
                    ))}
                  </ul>
                </article>

                <article className="card reveal reveal-delay-3">
                  <div className="card-heading">
                    <span className="card-kicker">Confidence</span>
                    <strong className="metric-value">{summary.confidence}%</strong>
                  </div>
                  <p className="muted">High enough to recommend action, but not high enough to skip review.</p>
                  <div className="meter">
                    <div className="meter-track" aria-hidden="true">
                      <span className="meter-fill" style={{ width: `${summary.confidence}%` }} />
                    </div>
                  </div>
                </article>

                <article className="card reveal reveal-delay-3">
                  <div className="card-heading">
                    <span className="card-kicker">Investigation timeline</span>
                    <StatusPill tone="neutral">Recent</StatusPill>
                  </div>
                  <div className="timeline">
                    {summary.timeline.map((item) => (
                      <div className="timeline-row" key={item.time + item.title}>
                        <div className={`timeline-dot timeline-dot--${item.tone}`} />
                        <div className="timeline-content">
                          <div className="timeline-meta">
                            <span>{item.time}</span>
                            <strong>{item.title}</strong>
                          </div>
                          <p>{item.detail}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </article>

                <article className="card reveal reveal-delay-4">
                  <div className="card-heading">
                    <span className="card-kicker">Coverage and blind spots</span>
                    <StatusPill tone="warning">{summary.coverage.length} items</StatusPill>
                  </div>
                  <div className="check-grid">
                    {summary.coverage.map((check) => (
                      <div className="check-card" key={check.label}>
                        <div className="check-header">
                          <strong>{check.label}</strong>
                          <span>{check.status}</span>
                        </div>
                        <p>{check.note}</p>
                      </div>
                    ))}
                  </div>
                </article>

                <article className="card reveal reveal-delay-4">
                  <div className="card-heading">
                    <span className="card-kicker">Decision workspace</span>
                    <StatusPill tone="safe">Operator review</StatusPill>
                  </div>
                  <div className="decision-list">
                    {summary.actions.map((action) => (
                      <div className="decision-item" key={action.label}>
                        <div>
                          <div className="decision-label-row">
                            <strong>{action.label}</strong>
                            <span>{action.kind}</span>
                          </div>
                          <p>{action.detail}</p>
                        </div>
                        <button className="decision-button">Open</button>
                      </div>
                    ))}
                  </div>
                </article>
              </section>
            </>
          ) : (
            <>
              <header className="topbar">
                <div>
                  <p className="eyebrow">Audit trail</p>
                  <h2>Decision history and system record</h2>
                </div>
                <div className="topbar-meta">
                  <StatusPill tone="neutral">Immutable log</StatusPill>
                  <StatusPill tone="safe">3 entries recorded</StatusPill>
                </div>
              </header>

              <section className="dashboard-grid dashboard-grid--app reveal reveal-delay-2">
                <article className="card card--wide">
                  <div className="card-heading">
                    <span className="card-kicker">Recorded actions</span>
                    <StatusPill tone="neutral">Most recent first</StatusPill>
                  </div>
                  <div className="audit-log-list">
                    {auditTrail.map((entry) => {
                      const [time, detail] = entry.split(" — ");
                      return (
                        <div className="audit-log-item" key={entry}>
                          <div className="audit-log-marker" />
                          <div className="audit-log-content">
                            <strong>{time}</strong>
                            <p>{detail}</p>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </article>
              </section>
            </>
          )}

          {showDebug ? (
            <section className="debug-panel">
              <article className="card card--wide">
                <div className="card-heading">
                  <span className="card-kicker">Debug payloads</span>
                  <StatusPill tone="neutral">Developer view</StatusPill>
                </div>
                <div className="debug-grid">
                  <div className="debug-block">
                    <strong>Queue payload</strong>
                    <pre>{JSON.stringify(queue, null, 2)}</pre>
                  </div>
                  <div className="debug-block">
                    <strong>Selected incident ID</strong>
                    <pre>{JSON.stringify(selectedIncidentId, null, 2)}</pre>
                  </div>
                  <div className="debug-block">
                    <strong>Incident payload</strong>
                    <pre>{JSON.stringify(incident, null, 2)}</pre>
                  </div>
                  <div className="debug-block">
                    <strong>Decision support payload</strong>
                    <pre>{JSON.stringify(decisionSupport, null, 2)}</pre>
                  </div>
                  <div className="debug-block">
                    <strong>Coverage review payload</strong>
                    <pre>{JSON.stringify(coverageReview, null, 2)}</pre>
                  </div>
                  <div className="debug-block">
                    <strong>Errors and loading</strong>
                    <pre>
                      {JSON.stringify(
                        {
                          queueError,
                          incidentError,
                          incidentLoading,
                        },
                        null,
                        2,
                      )}
                    </pre>
                  </div>
                </div>
              </article>
            </section>
          ) : null}
        </section>
      </div>
    </main>
  );
}
