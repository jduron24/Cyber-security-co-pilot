import type { AuditEntry } from "@/lib/view-model";
import { StatusPill } from "./StatusPill";

export function AuditTrailView({ auditEntries }: { auditEntries: AuditEntry[] }) {
  return (
    <section className="dashboard-grid dashboard-grid--app reveal reveal-delay-2">
      <article className="card card--wide">
        <div className="card-heading">
          <span className="card-kicker">Recorded decisions and review events</span>
          <StatusPill tone="neutral">{auditEntries.length} entries</StatusPill>
        </div>
        <div className="audit-log-list">
          {auditEntries.length ? (
            auditEntries.map((entry) => (
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
    </section>
  );
}
