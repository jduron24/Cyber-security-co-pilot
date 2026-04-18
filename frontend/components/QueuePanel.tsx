import type { QueueItem } from "@/lib/view-model";

export function QueuePanel({
  queue,
  selectedIncidentId,
  queueError,
  onSelectIncident,
}: {
  queue: QueueItem[];
  selectedIncidentId: string;
  queueError: string | null;
  onSelectIncident: (incidentId: string) => void;
}) {
  return (
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
            onClick={() => onSelectIncident(item.id)}
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
  );
}
