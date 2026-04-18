"use client";

import { useEffect, useMemo, useState } from "react";

import { ActiveIncidentView } from "@/components/ActiveIncidentView";
import { AuditTrailView } from "@/components/AuditTrailView";
import { QueuePanel } from "@/components/QueuePanel";
import { ApiError, getAgentAuth, listIncidents, loadIncidentWorkspace, postAgentQuery, postAlternative, postApprove, postDoubleCheck, postEscalate } from "@/lib/api";
import { buildIncidentViewModel, mapQueueItem } from "@/lib/view-model";
import type { OperatorHistoryResponse, RecordShape } from "@/types/api";

const fallbackQueue = [
  { id: "INC-1042", site: "Water Plant East", severity: "High", state: "Needs review" },
  { id: "INC-1038", site: "County Records", severity: "Medium", state: "Monitoring" },
  { id: "INC-1033", site: "City Hospital Annex", severity: "Low", state: "Closed" },
];

export default function Home() {
  const [selectedView, setSelectedView] = useState<"active" | "audit">("active");
  const [queue, setQueue] = useState(fallbackQueue);
  const [queueError, setQueueError] = useState<string | null>(null);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string>(fallbackQueue[0].id);
  const [incident, setIncident] = useState<RecordShape | null>(null);
  const [decisionSupport, setDecisionSupport] = useState<RecordShape | null>(null);
  const [coverageReview, setCoverageReview] = useState<RecordShape | null>(null);
  const [operatorHistory, setOperatorHistory] = useState<OperatorHistoryResponse | null>(null);
  const [incidentLoading, setIncidentLoading] = useState(false);
  const [incidentError, setIncidentError] = useState<string | null>(null);
  const [selectedAlternativeId, setSelectedAlternativeId] = useState<string | null>(null);
  const [rationale, setRationale] = useState("");
  const [actionLoading, setActionLoading] = useState(false);
  const [actionMessage, setActionMessage] = useState<string | null>(null);
  const [agentAuth, setAgentAuth] = useState<RecordShape | null>(null);
  const [agentQuestion, setAgentQuestion] = useState("What should I do next?");
  const [agentAnswer, setAgentAnswer] = useState<RecordShape | null>(null);
  const [agentLoading, setAgentLoading] = useState(false);
  const [agentError, setAgentError] = useState<string | null>(null);

  async function refreshWorkspace(incidentId: string) {
    const result = await loadIncidentWorkspace(incidentId);
    setIncident(result.incident);
    setDecisionSupport(result.decisionSupport);
    setCoverageReview(result.coverageReview);
    setOperatorHistory(result.operatorHistory);
  }

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
      setActionMessage(null);
      setAgentAnswer(null);
      try {
        await refreshWorkspace(selectedIncidentId);
        if (cancelled) return;
      } catch (error) {
        if (cancelled) return;
        setIncidentError(error instanceof ApiError ? error.message : "Could not load incident details.");
        setIncident(null);
        setDecisionSupport(null);
        setCoverageReview(null);
        setOperatorHistory(null);
      } finally {
        if (!cancelled) {
          setIncidentLoading(false);
        }
      }
    }

    async function loadAgentAuthState() {
      if (!selectedIncidentId.startsWith("incident_")) return;
      try {
        const result = await getAgentAuth(selectedIncidentId);
        if (!cancelled) {
          setAgentAuth(result);
        }
      } catch (error) {
        if (!cancelled) {
          setAgentAuth(null);
          setAgentError(error instanceof ApiError ? error.message : "Could not load agent status.");
        }
      }
    }

    void loadDetails();
    void loadAgentAuthState();
    return () => {
      cancelled = true;
    };
  }, [selectedIncidentId]);

  const viewModel = useMemo(
    () => buildIncidentViewModel(incident, decisionSupport, coverageReview, operatorHistory, selectedIncidentId),
    [coverageReview, decisionSupport, incident, operatorHistory, selectedIncidentId],
  );

  async function runAction(action: "approve" | "alternative" | "escalate" | "double-check") {
    if (!selectedIncidentId.startsWith("incident_")) return;
    setActionLoading(true);
    setActionMessage(null);
    setIncidentError(null);
    try {
      let result: RecordShape;
      if (action === "approve") {
        result = await postApprove(selectedIncidentId, { rationale, used_double_check: false });
      } else if (action === "alternative") {
        if (!selectedAlternativeId) {
          throw new ApiError("Select an alternative before submitting.");
        }
        result = await postAlternative(selectedIncidentId, {
          action_id: selectedAlternativeId,
          rationale,
          used_double_check: false,
        });
      } else if (action === "escalate") {
        result = await postEscalate(selectedIncidentId, { rationale, used_double_check: false });
      } else {
        result = await postDoubleCheck(selectedIncidentId, { rationale, used_double_check: true });
      }
      const chosenAction = result.chosen_action && typeof result.chosen_action === "object"
        ? (result.chosen_action as RecordShape)
        : {};
      const chosenLabel =
        (typeof chosenAction.label === "string" && chosenAction.label) ||
        (typeof chosenAction.action_id === "string" && chosenAction.action_id) ||
        (action === "double-check" ? "Double check recorded" : "Action recorded");
      const decisionType = typeof result.decision_type === "string" ? result.decision_type : "decision recorded";
      setActionMessage(`${decisionType.replace(/_/g, " ")}: ${chosenLabel}`);
      await refreshWorkspace(selectedIncidentId);
    } catch (error) {
      setIncidentError(error instanceof ApiError ? error.message : "Could not record operator action.");
    } finally {
      setActionLoading(false);
    }
  }

  async function runAgentQuery() {
    if (!selectedIncidentId.startsWith("incident_") || !agentQuestion.trim()) return;
    setAgentLoading(true);
    setAgentError(null);
    try {
      const result = await postAgentQuery(selectedIncidentId, { user_query: agentQuestion.trim() });
      setAgentAnswer(result);
    } catch (error) {
      setAgentError(error instanceof ApiError ? error.message : "Could not query agent.");
    } finally {
      setAgentLoading(false);
    }
  }

  return (
    <main className="sentinel-shell">
      <div className="app-frame reveal reveal-delay-1">
        <aside className="left-rail">
          <div className="brand-block">
            <p className="eyebrow">Sentinel</p>
            <h1>Operator Console</h1>
            <p>Decision support with visible blind spots for non-expert operators.</p>
          </div>

          <nav className="nav-stack">
            <button
              className={`nav-item${selectedView === "active" ? " nav-item--active" : ""}`}
              onClick={() => setSelectedView("active")}
              type="button"
            >
              Active incident
            </button>
            <button
              className={`nav-item${selectedView === "audit" ? " nav-item--active" : ""}`}
              onClick={() => setSelectedView("audit")}
              type="button"
            >
              Audit trail
            </button>
          </nav>

          <QueuePanel
            queue={queue}
            selectedIncidentId={selectedIncidentId}
            queueError={queueError}
            onSelectIncident={setSelectedIncidentId}
          />
        </aside>

        <section className="workspace">
          {selectedView === "active" ? (
            <ActiveIncidentView
              viewModel={viewModel}
              incidentLoading={incidentLoading}
              incidentError={incidentError}
              actionMessage={actionMessage}
              selectedAlternativeId={selectedAlternativeId}
              rationale={rationale}
              actionLoading={actionLoading}
              agentAuth={agentAuth}
              agentQuestion={agentQuestion}
              agentAnswer={agentAnswer}
              agentLoading={agentLoading}
              agentError={agentError}
              onSelectAlternative={setSelectedAlternativeId}
              onRationaleChange={setRationale}
              onApprove={() => void runAction("approve")}
              onAlternative={() => void runAction("alternative")}
              onDoubleCheck={() => void runAction("double-check")}
              onEscalate={() => void runAction("escalate")}
              onAgentQuestionChange={setAgentQuestion}
              onAgentAsk={() => void runAgentQuery()}
            />
          ) : (
            <AuditTrailView auditEntries={viewModel.auditEntries} />
          )}
        </section>
      </div>
    </main>
  );
}
