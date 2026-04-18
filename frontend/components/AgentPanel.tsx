import { asRecord, asString } from "@/lib/view-model";
import type { RecordShape } from "@/types/api";
import { StatusPill } from "./StatusPill";

export function AgentPanel({
  agentAuth,
  agentError,
  agentQuestion,
  agentAnswer,
  agentLoading,
  onQuestionChange,
  onAsk,
}: {
  agentAuth: RecordShape | null;
  agentError: string | null;
  agentQuestion: string;
  agentAnswer: RecordShape | null;
  agentLoading: boolean;
  onQuestionChange: (value: string) => void;
  onAsk: () => void;
}) {
  return (
    <section className="dashboard-grid reveal reveal-delay-5">
      <article className="card card--wide">
        <div className="card-heading">
          <span className="card-kicker">Agent</span>
          <StatusPill tone="neutral">
            {asString(
              agentAuth?.labels ? asRecord(agentAuth.labels)[asString(agentAuth.auth_mode, "api_key")] : agentAuth?.auth_mode,
              "Unavailable",
            )}
          </StatusPill>
        </div>
        <p className="muted">Secondary tool only. The decision workflow above remains the canonical path.</p>
        {agentError ? <div className="warning-banner">{agentError}</div> : null}
        <label className="field-label" htmlFor="agent-question">
          Ask the agent
        </label>
        <div className="agent-row">
          <input
            className="text-input"
            id="agent-question"
            value={agentQuestion}
            onChange={(event) => onQuestionChange(event.target.value)}
          />
          <button className="cta cta--secondary" disabled={agentLoading} onClick={onAsk} type="button">
            {agentLoading ? "Thinking…" : "Ask"}
          </button>
        </div>
        {agentAnswer ? (
          <div className="agent-answer">
            <strong>Agent response</strong>
            <p>{asString(agentAnswer.answer, "No answer returned.")}</p>
          </div>
        ) : null}
      </article>
    </section>
  );
}
