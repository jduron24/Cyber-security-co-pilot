import type { AuditEntry, CyberAuditEntry } from "@/lib/view-model";
import { StatusPill } from "./StatusPill";

export function AuditTrailView({
  operatorAuditEntries,
  cyberAuditEntries,
}: {
  operatorAuditEntries: AuditEntry[];
  cyberAuditEntries: CyberAuditEntry[];
}) {
  return (
    <section className="dashboard-grid dashboard-grid--app reveal reveal-delay-2">
      <article className="card card--wide">
        <div className="card-heading">
          <span className="card-kicker">Human decision audit trail</span>
          <StatusPill tone="neutral">{operatorAuditEntries.length} entries</StatusPill>
        </div>
        <div className="audit-log-list">
          {operatorAuditEntries.length ? (
            operatorAuditEntries.map((entry) => (
              <div className="audit-log-item" key={`${entry.time}-${entry.title}-${entry.detail}`}>
                <div className="audit-log-marker" />
                <div className="audit-log-content">
                  <strong>{entry.title}</strong>
                  <small>{entry.time}</small>
                  <p>{entry.detail}</p>
                </div>
              </div>
            ))
          ) : (
            <div className="audit-log-item">
              <div className="audit-log-marker" />
              <div className="audit-log-content">
                <strong>No recorded operator decisions yet</strong>
                <p>Approve, escalate, choose an alternative, or request a double check to build the audit trail.</p>
              </div>
            </div>
          )}
        </div>
      </article>

      <article className="card card--wide">
        <div className="card-heading">
          <span className="card-kicker">Cyber data used for the decision</span>
          <StatusPill tone="neutral">{cyberAuditEntries.length} entries</StatusPill>
        </div>
        <div className="audit-log-list">
          {cyberAuditEntries.length ? (
            cyberAuditEntries.map((entry) => (
              <div className="audit-log-item" key={`${entry.source}-${entry.title}-${entry.detail}`}>
                <div className="audit-log-marker" />
                <div className="audit-log-content">
                  <strong>{entry.title}</strong>
                  <small>{entry.source}</small>
                  <p>{entry.detail}</p>
                </div>
              </div>
            ))
          ) : (
            <div className="audit-log-item">
              <div className="audit-log-marker" />
              <div className="audit-log-content">
                <strong>No cyber context trail available yet</strong>
                <p>Load an incident to see the evidence, detector, coverage, and decision-support context used to frame the recommendation.</p>
              </div>
            </div>
          )}
        </div>
      </article>
    </section>
  );
}
