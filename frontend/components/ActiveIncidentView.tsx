import { useState } from "react";
import type { IncidentViewModel } from "@/lib/view-model";
import { toneForCoverageStatus, toneForSeverity } from "@/lib/view-model";
import { AgentPanel } from "./AgentPanel";
import { StatusPill } from "./StatusPill";
import type { RecordShape } from "@/types/api";

export function ActiveIncidentView({
  viewModel,
  rawLogs,
  viewMode,
  incidentLoading,
  incidentError,
  actionMessage,
  selectedAlternativeId,
  rationale,
  actionLoading,
  agentAuth,
  agentQuestion,
  agentAnswer,
  agentLoading,
  agentError,
  onSelectAlternative,
  onRationaleChange,
  onApprove,
  onAlternative,
  onDoubleCheck,
  onEscalate,
  onAgentQuestionChange,
  onAgentAsk,
}: {
  viewModel: IncidentViewModel;
  rawLogs: RecordShape[];
  viewMode: "simple" | "expert";
  incidentLoading: boolean;
  incidentError: string | null;
  actionMessage: string | null;
  selectedAlternativeId: string | null;
  rationale: string;
  actionLoading: boolean;
  agentAuth: RecordShape | null;
  agentQuestion: string;
  agentAnswer: RecordShape | null;
  agentLoading: boolean;
  agentError: string | null;
  onSelectAlternative: (actionId: string) => void;
  onRationaleChange: (value: string) => void;
  onApprove: () => void;
  onAlternative: () => void;
  onDoubleCheck: () => void;
  onEscalate: () => void;
  onAgentQuestionChange: (value: string) => void;
  onAgentAsk: () => void;
}) {
  const [openSignal, setOpenSignal] = useState<string | null>(null);
  const [openRawLog, setOpenRawLog] = useState<string | null>(null);
  const isExpert = viewMode === "expert";

  if (!isExpert) {
    return (
      <>
        {viewModel.recommendationMayBeIncomplete ? (
          <div className="warning-banner warning-banner--critical">
            <strong>Recommendation may be incomplete.</strong>
            <span>{viewModel.incompletenessWarning ?? viewModel.decisionRiskNote}</span>
          </div>
        ) : null}
        {incidentError ? <div className="warning-banner">{incidentError}</div> : null}
        {actionMessage ? <div className="success-banner">{actionMessage}</div> : null}

        <section className="simple-workflow reveal reveal-delay-2">
          <article className="card simple-card">
            <div className="card-heading">
              <span className="card-kicker">A. What happened?</span>
              <StatusPill tone="critical">Incident</StatusPill>
            </div>
            <h3>{viewModel.title}</h3>
            <p>{viewModel.summary}</p>
            <div className="timeline-inline">
              {viewModel.timeline.map((item) => (
                <span className="timeline-chip" key={item.step + item.title}>
                  {item.step}: {item.title}
                </span>
              ))}
            </div>
          </article>

          <article className="card simple-card">
            <div className="card-heading">
              <span className="card-kicker">B. What should I do?</span>
              <StatusPill tone="warning">
                {viewModel.recommendedAction.requiresHumanApproval ? "Human decision needed" : "Suggested"}
              </StatusPill>
            </div>
            <h3>{viewModel.recommendedAction.label}</h3>
            <p>{viewModel.recommendedAction.reason}</p>
            <p className="muted">{viewModel.decisionRiskNote}</p>
            {viewModel.latestDecision ? (
              <div className="latest-decision">
                <strong>{viewModel.latestDecision.title}</strong>
                <p>{viewModel.latestDecision.detail}</p>
                {viewModel.latestDecision.rationale ? <p className="latest-decision-rationale">Rationale: {viewModel.latestDecision.rationale}</p> : null}
              </div>
            ) : null}
          </article>

          <article className="card simple-card">
            <div className="card-heading">
              <span className="card-kicker">C. What else could I do?</span>
              <StatusPill tone="neutral">{viewModel.alternatives.length} alternatives</StatusPill>
            </div>
            <div className="decision-list">
              {viewModel.alternatives.map((action) => (
                <button
                  className={`decision-item decision-item--selectable${
                    selectedAlternativeId === action.actionId ? " decision-item--selected" : ""
                  }`}
                  key={action.actionId}
                  onClick={() => onSelectAlternative(action.actionId)}
                  type="button"
                >
                  <div>
                    <div className="decision-label-row">
                      <strong>{action.label}</strong>
                    </div>
                    <p>{action.reason}</p>
                    <small>{action.tradeoff}</small>
                  </div>
                </button>
              ))}
            </div>
          </article>

        <article className="card simple-card">
          <div className="card-heading">
            <span className="card-kicker">D. Did we check everything?</span>
            <StatusPill tone={viewModel.recommendationMayBeIncomplete ? "warning" : "safe"}>
              {viewModel.recommendationMayBeIncomplete ? "Incomplete" : "Sufficient"}
            </StatusPill>
          </div>
          <p className="muted">
            Model: {viewModel.modelType}
            {viewModel.modelVersion ? ` (${viewModel.modelVersion})` : ""}
          </p>
          <div className="check-grid">
            {viewModel.coverage.map((check) => (
              <div className="check-card" key={check.category}>
                  <div className="check-header">
                    <strong>{check.category}</strong>
                    <StatusPill tone={toneForCoverageStatus(check.rawStatus)}>{check.status}</StatusPill>
                  </div>
                  <p>{check.note}</p>
                </div>
              ))}
            </div>
            {viewModel.whatCouldChange.length ? (
              <div className="detail-list">
                <strong>What could change the decision</strong>
                <ul>
                  {viewModel.whatCouldChange.map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              </div>
            ) : null}
            <div className="detail-list">
              <strong>Why the system is concerned</strong>
              <ul>
                {viewModel.signals.map((signal) => (
                  <li key={signal.label}>
                    {signal.label}: {signal.detail}
                  </li>
                ))}
              </ul>
            </div>
          </article>

          <article className="card simple-card">
            <div className="card-heading">
              <span className="card-kicker">Record the human decision</span>
              <StatusPill tone="safe">Audit recorded</StatusPill>
            </div>
            <label className="field-label" htmlFor="operator-rationale-simple">
              Why are you taking this action?
            </label>
            <textarea
              className="text-input"
              id="operator-rationale-simple"
              value={rationale}
              onChange={(event) => onRationaleChange(event.target.value)}
              placeholder="Record the human reasoning in plain language."
            />
            <div className="action-grid">
              <button className="cta cta--primary" disabled={actionLoading} onClick={onApprove} type="button">
                Approve recommendation
              </button>
              <button className="cta cta--secondary" disabled={actionLoading || !selectedAlternativeId} onClick={onAlternative} type="button">
                Choose selected alternative
              </button>
              <button className="cta cta--secondary" disabled={actionLoading} onClick={onDoubleCheck} type="button">
                Double check
              </button>
              <button className="cta cta--secondary" disabled={actionLoading} onClick={onEscalate} type="button">
                Escalate
              </button>
            </div>
          </article>
        </section>
      </>
    );
  }

  return (
    <>
      {viewModel.recommendationMayBeIncomplete ? (
        <div className="warning-banner warning-banner--critical">
          <strong>Recommendation may be incomplete.</strong>
          <span>{viewModel.incompletenessWarning ?? viewModel.decisionRiskNote}</span>
        </div>
      ) : null}
      {incidentError ? <div className="warning-banner">{incidentError}</div> : null}
      {actionMessage ? <div className="success-banner">{actionMessage}</div> : null}

      <section className="hero-strip reveal reveal-delay-2">
        <article className="card card--hero-main">
          <div className="card-heading">
            <span className="card-kicker">Incident summary</span>
            <StatusPill tone="critical">What happened</StatusPill>
          </div>
          <h3>{viewModel.title}</h3>
          <p>{viewModel.summary}</p>
          <div className="timeline-inline">
            {viewModel.timeline.map((item) => (
              <span className="timeline-chip" key={item.step + item.title}>
                {item.step}: {item.title}
              </span>
            ))}
          </div>
        </article>

        <article className="card card--hero-side">
          <div className="card-heading">
            <span className="card-kicker">Recommended action</span>
            <StatusPill tone="warning">
              {viewModel.recommendedAction.requiresHumanApproval ? "Approval required" : "Suggested"}
            </StatusPill>
          </div>
          <h3>{viewModel.recommendedAction.label}</h3>
          <p>{viewModel.recommendedAction.reason}</p>
          <p className="muted">{viewModel.decisionRiskNote}</p>
        </article>
      </section>

      <section className="dashboard-grid dashboard-grid--app">
        {isExpert ? (
          <article className="card card--primary reveal reveal-delay-2">
            <div className="card-heading">
              <span className="card-kicker">Why Sentinel is concerned</span>
              <StatusPill tone="warning">{viewModel.signals.length} signals</StatusPill>
            </div>
            <ul className="signal-list">
              {viewModel.signals.map((signal) => (
                <li key={signal.label}>
                  <div className="signal-header">
                    <strong>{signal.label}</strong>
                    <button
                      aria-expanded={openSignal === signal.label}
                      aria-label={`Explain ${signal.label}`}
                      className="info-button"
                      onClick={() => setOpenSignal(openSignal === signal.label ? null : signal.label)}
                      type="button"
                    >
                      i
                    </button>
                  </div>
                  <p>{signal.detail}</p>
                  {openSignal === signal.label ? <div className="signal-explanation">{signal.explanation}</div> : null}
                </li>
              ))}
            </ul>
          </article>
        ) : null}

        {isExpert ? (
          <article className="card card--confidence reveal reveal-delay-3">
            <div className="card-heading">
              <span className="card-kicker">Confidence</span>
              <strong className="metric-value">{viewModel.confidence}%</strong>
            </div>
            <p className="muted">
              Model: {viewModel.modelType}
              {viewModel.modelVersion ? ` (${viewModel.modelVersion})` : ""}
            </p>
            <p className="muted">Use this as triage guidance, not autonomous authority.</p>
            <div className="meter">
              <div className="meter-track" aria-hidden="true">
                <span className="meter-fill" style={{ width: `${viewModel.confidence}%` }} />
              </div>
            </div>
            <div className="topbar-meta">
              <StatusPill tone={toneForSeverity(viewModel.severity)}>{viewModel.severity}</StatusPill>
              <StatusPill tone="warning">{incidentLoading ? "Loading" : "Live data"}</StatusPill>
            </div>
          </article>
        ) : null}

        <article className="card card--coverage reveal reveal-delay-3">
          <div className="card-heading">
            <span className="card-kicker">Coverage and blind spots</span>
            <StatusPill tone={viewModel.recommendationMayBeIncomplete ? "warning" : "safe"}>
              {viewModel.recommendationMayBeIncomplete ? "Incomplete" : "Sufficient"}
            </StatusPill>
          </div>
          <div className="check-grid">
            {viewModel.coverage.map((check) => (
              <div className="check-card" key={check.category}>
                <div className="check-header">
                  <strong>{check.category}</strong>
                  <StatusPill tone={toneForCoverageStatus(check.rawStatus)}>{check.status}</StatusPill>
                </div>
                <p>{check.note}</p>
              </div>
            ))}
          </div>
          {viewModel.whatCouldChange.length ? (
            <div className="detail-list">
              <strong>What could change the decision</strong>
              <ul>
                {viewModel.whatCouldChange.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </div>
          ) : null}
        </article>

        <article className="card card--model-explanation reveal reveal-delay-3">
          <div className="card-heading">
            <span className="card-kicker">Why the model flagged this</span>
            <StatusPill tone="neutral">{viewModel.modelType ? viewModel.modelType.toUpperCase() : "Model"}</StatusPill>
          </div>
          {viewModel.modelContributions.length ? (
            <div className="detail-list detail-list--compact">
              <ul>
                {viewModel.modelContributions.map((item) => (
                  <li key={`${item.feature}-${item.direction}`}>
                    <strong>{item.feature}</strong>: {item.plainLanguage}
                  </li>
                ))}
              </ul>
            </div>
          ) : (
            <p className="muted">No model-specific explanation was recorded for this detector result.</p>
          )}
        </article>

        <article className="card card--raw-logs reveal reveal-delay-3">
          <div className="card-heading">
            <span className="card-kicker">Raw logs for expert review</span>
            <StatusPill tone="neutral">{rawLogs.length} events</StatusPill>
          </div>
          {rawLogs.length ? (
            <div className="raw-log-list">
              {rawLogs.map((event) => (
                <details
                  className="raw-log-entry"
                  key={`${String(event.event_id)}-${String(event.event_index)}`}
                  open={openRawLog === String(event.event_id)}
                  onToggle={(toggleEvent) => {
                    const isOpen = (toggleEvent.currentTarget as HTMLDetailsElement).open;
                    setOpenRawLog(isOpen ? String(event.event_id) : null);
                  }}
                >
                  <summary className="raw-log-summary">
                    <div className="raw-log-meta">
                      <strong>{String(event.event_name ?? "Event")}</strong>
                      <small>{String(event.event_source ?? "unknown source")}</small>
                    </div>
                    <span className="raw-log-toggle">{openRawLog === String(event.event_id) ? "Hide payload" : "View payload"}</span>
                  </summary>
                  <pre className="raw-log-pre">{JSON.stringify(event.event_payload ?? event, null, 2)}</pre>
                </details>
              ))}
            </div>
          ) : (
            <p className="muted">No raw event payloads were recorded for this incident.</p>
          )}
        </article>

        <article className="card card--alternatives reveal reveal-delay-4">
          <div className="card-heading">
            <span className="card-kicker">Alternatives</span>
            <StatusPill tone="neutral">{viewModel.alternatives.length} options</StatusPill>
          </div>
          <div className="decision-list">
            {viewModel.alternatives.map((action) => (
              <button
                className={`decision-item decision-item--selectable${
                  selectedAlternativeId === action.actionId ? " decision-item--selected" : ""
                }`}
                key={action.actionId}
                onClick={() => onSelectAlternative(action.actionId)}
                type="button"
              >
                <div>
                  <div className="decision-label-row">
                    <strong>{action.label}</strong>
                    <span>{action.actionId}</span>
                  </div>
                  <p>{action.reason}</p>
                  <small>{action.tradeoff}</small>
                </div>
              </button>
            ))}
          </div>
        </article>

        <article className="card card--human-decision reveal reveal-delay-4">
          <div className="card-heading">
            <span className="card-kicker">Human decision and audit</span>
            <StatusPill tone="safe">Live workflow</StatusPill>
          </div>
          {viewModel.latestDecision ? (
            <div className="latest-decision">
              <strong>{viewModel.latestDecision.title}</strong>
              <p>{viewModel.latestDecision.detail}</p>
              {viewModel.latestDecision.rationale ? <p className="latest-decision-rationale">Rationale: {viewModel.latestDecision.rationale}</p> : null}
              {viewModel.latestDecision.recordedAt ? <small className="latest-decision-time">Recorded {viewModel.latestDecision.recordedAt}</small> : null}
            </div>
          ) : null}
          <label className="field-label" htmlFor="operator-rationale">
            Rationale
          </label>
          <textarea
            className="text-input"
            id="operator-rationale"
            value={rationale}
            onChange={(event) => onRationaleChange(event.target.value)}
            placeholder="Record why you are taking this action."
          />
          <div className="action-grid">
            <button className="cta cta--primary" disabled={actionLoading} onClick={onApprove} type="button">
              Approve recommendation
            </button>
            <button className="cta cta--secondary" disabled={actionLoading || !selectedAlternativeId} onClick={onAlternative} type="button">
              Choose selected alternative
            </button>
            <button className="cta cta--secondary" disabled={actionLoading} onClick={onDoubleCheck} type="button">
              Double check
            </button>
            <button className="cta cta--secondary" disabled={actionLoading} onClick={onEscalate} type="button">
              Escalate
            </button>
          </div>
          {viewModel.doubleCheckCandidates.length ? (
            <div className="detail-list">
              <strong>Double-check candidates</strong>
              <ul>
                {viewModel.doubleCheckCandidates.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </div>
          ) : null}
        </article>
      </section>

      <AgentPanel
        agentAuth={agentAuth}
        agentError={agentError}
        agentQuestion={agentQuestion}
        agentAnswer={agentAnswer}
        agentLoading={agentLoading}
        onQuestionChange={onAgentQuestionChange}
        onAsk={onAgentAsk}
      />
    </>
  );
}
