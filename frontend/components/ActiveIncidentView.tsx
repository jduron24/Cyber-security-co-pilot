import type { IncidentViewModel } from "@/lib/view-model";
import { toneForCoverageStatus, toneForSeverity } from "@/lib/view-model";
import { AgentPanel } from "./AgentPanel";
import { StatusPill } from "./StatusPill";
import type { RecordShape } from "@/types/api";

export function ActiveIncidentView({
  viewModel,
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
        <article className="card card--primary reveal reveal-delay-2">
          <div className="card-heading">
            <span className="card-kicker">Why Sentinel is concerned</span>
            <StatusPill tone="warning">{viewModel.signals.length} signals</StatusPill>
          </div>
          <ul className="signal-list">
            {viewModel.signals.map((signal) => (
              <li key={signal.label}>
                <strong>{signal.label}</strong>
                <p>{signal.detail}</p>
              </li>
            ))}
          </ul>
        </article>

        <article className="card reveal reveal-delay-3">
          <div className="card-heading">
            <span className="card-kicker">Confidence</span>
            <strong className="metric-value">{viewModel.confidence}%</strong>
          </div>
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

        <article className="card reveal reveal-delay-3">
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

        <article className="card reveal reveal-delay-4">
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

        <article className="card reveal reveal-delay-4">
          <div className="card-heading">
            <span className="card-kicker">Human decision and audit</span>
            <StatusPill tone="safe">Live workflow</StatusPill>
          </div>
          {viewModel.latestDecision ? (
            <div className="latest-decision">
              <strong>{viewModel.latestDecision.title}</strong>
              <p>{viewModel.latestDecision.detail}</p>
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
