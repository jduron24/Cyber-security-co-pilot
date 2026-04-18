"use client";

import { useEffect, useMemo, useState } from "react";

import { ActiveIncidentView } from "@/components/ActiveIncidentView";
import { AuditTrailView } from "@/components/AuditTrailView";
import { QueuePanel } from "@/components/QueuePanel";
import { ApiError, getAgentAuth, listIncidents, loadIncidentWorkspace, postAgentQuery, postAlternative, postApprove, postDoubleCheck, postEscalate } from "@/lib/api";
import { buildIncidentViewModel, mapQueueItem } from "@/lib/view-model";
import type { OperatorHistoryResponse, RecordShape } from "@/types/api";

const fallbackQueue = [
  { id: "INC-1042", label: "INC-1042", site: "Water Plant East", severity: "High", state: "Needs review" },
  { id: "INC-1038", label: "INC-1038", site: "County Records", severity: "Medium", state: "Monitoring" },
  { id: "INC-1033", label: "INC-1033", site: "City Hospital Annex", severity: "Low", state: "Closed" },
];

function logPage(event: string, payload?: unknown): void {
  console.info(`[frontend/page] ${event}`, payload ?? "");
}

export default function Home() {
  const [viewMode, setViewMode] = useState<"simple" | "expert">("simple");
  const [selectedView, setSelectedView] = useState<"active" | "audit">("active");
  const [queue, setQueue] = useState(fallbackQueue);
  const [queueError, setQueueError] = useState<string | null>(null);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string>(fallbackQueue[0].id);
  const [incident, setIncident] = useState<RecordShape | null>(null);
  const [incidentEvents, setIncidentEvents] = useState<RecordShape[]>([]);
  const [evidencePackage, setEvidencePackage] = useState<RecordShape | null>(null);
  const [detectorResult, setDetectorResult] = useState<RecordShape | null>(null);
  const [coverageAssessment, setCoverageAssessment] = useState<RecordShape | null>(null);
  const [decisionSupportResult, setDecisionSupportResult] = useState<RecordShape | null>(null);
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

  useEffect(() => {
    if (viewMode === "simple" && selectedView === "audit") {
      setSelectedView("active");
    }
  }, [selectedView, viewMode]);

  async function refreshWorkspace(incidentId: string) {
    logPage("refresh_workspace_start", { incidentId });
    const result = await loadIncidentWorkspace(incidentId);
    logPage("refresh_workspace_success", {
      incidentId,
      hasIncident: Boolean(result.incident),
      hasEvidencePackage: Boolean(result.evidencePackage),
      hasDetectorResult: Boolean(result.detectorResult),
      hasCoverageAssessment: Boolean(result.coverageAssessment),
      hasDecisionSupportResult: Boolean(result.decisionSupportResult),
      hasDecisionSupport: Boolean(result.decisionSupport),
      hasCoverageReview: Boolean(result.coverageReview),
      hasOperatorHistory: Boolean(result.operatorHistory),
    });
    setIncident(result.incident);
    setIncidentEvents(result.incidentEvents);
    setEvidencePackage(result.evidencePackage);
    setDetectorResult(result.detectorResult);
    setCoverageAssessment(result.coverageAssessment);
    setDecisionSupportResult(result.decisionSupportResult);
    setDecisionSupport(result.decisionSupport);
    setCoverageReview(result.coverageReview);
    setOperatorHistory(result.operatorHistory);
  }

  useEffect(() => {
    let cancelled = false;

    async function loadQueue() {
      try {
        logPage("load_queue_start");
        const result = await listIncidents();
        logPage("load_queue_result", { count: result.length, incidents: result });
        if (cancelled || result.length === 0) return;
        const mapped = result.map(mapQueueItem);
        logPage("load_queue_mapped", mapped);
        setQueue(mapped);
        setSelectedIncidentId(mapped[0].id);
        setQueueError(null);
      } catch (error) {
        if (cancelled) return;
        console.error("[frontend/page] load_queue_failed", error);
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
        logPage("skip_load_details_for_fallback_incident", { selectedIncidentId });
        return;
      }
      setIncidentLoading(true);
      setIncidentError(null);
      setActionMessage(null);
      setAgentAnswer(null);
      try {
        logPage("load_details_start", { selectedIncidentId });
        await refreshWorkspace(selectedIncidentId);
        if (cancelled) return;
      } catch (error) {
        if (cancelled) return;
        console.error("[frontend/page] load_details_failed", { selectedIncidentId, error });
        setIncidentError(error instanceof ApiError ? error.message : "Could not load incident details.");
        setIncident(null);
        setIncidentEvents([]);
        setEvidencePackage(null);
        setDetectorResult(null);
        setCoverageAssessment(null);
        setDecisionSupportResult(null);
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
        logPage("load_agent_auth_start", { selectedIncidentId });
        const result = await getAgentAuth(selectedIncidentId);
        if (!cancelled) {
          logPage("load_agent_auth_success", result);
          setAgentAuth(result);
        }
      } catch (error) {
        if (!cancelled) {
          console.error("[frontend/page] load_agent_auth_failed", { selectedIncidentId, error });
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
    () =>
      buildIncidentViewModel(
        incident,
        evidencePackage,
        detectorResult,
        coverageAssessment,
        decisionSupportResult,
        decisionSupport,
        coverageReview,
        operatorHistory,
        selectedIncidentId,
      ),
    [coverageAssessment, coverageReview, decisionSupport, decisionSupportResult, detectorResult, evidencePackage, incident, operatorHistory, selectedIncidentId],
  );

  async function runAction(action: "approve" | "alternative" | "escalate" | "double-check") {
    if (!selectedIncidentId.startsWith("incident_")) return;
    setActionLoading(true);
    setActionMessage(null);
    setIncidentError(null);
    try {
      logPage("run_action_start", { action, selectedIncidentId, selectedAlternativeId, rationale });
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
      const normalizedDecisionType = decisionType.replace(/_/g, " ");
      const normalizedRationale = rationale.trim();
      logPage("run_action_success", { action, result });
      setActionMessage(
        `Human decision recorded: ${normalizedDecisionType} -> ${chosenLabel}.${normalizedRationale ? ` Rationale saved: ${normalizedRationale}` : " No rationale recorded."}`,
      );
      await refreshWorkspace(selectedIncidentId);
    } catch (error) {
      console.error("[frontend/page] run_action_failed", { action, selectedIncidentId, error });
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
      logPage("run_agent_query_start", { selectedIncidentId, agentQuestion });
      const result = await postAgentQuery(selectedIncidentId, { user_query: agentQuestion.trim() });
      logPage("run_agent_query_success", result);
      setAgentAnswer(result);
    } catch (error) {
      console.error("[frontend/page] run_agent_query_failed", { selectedIncidentId, error });
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

          <section className="mode-panel">
            <div className="rail-heading">
              <span>Workspace view</span>
              <strong>{viewMode === "simple" ? "Simple" : "Expert"}</strong>
            </div>
            <div className="mode-toggle" role="tablist" aria-label="Workspace view mode">
              <button
                aria-selected={viewMode === "simple"}
                className={`mode-toggle__button${viewMode === "simple" ? " mode-toggle__button--active" : ""}`}
                onClick={() => setViewMode("simple")}
                type="button"
              >
                Simple
              </button>
              <button
                aria-selected={viewMode === "expert"}
                className={`mode-toggle__button${viewMode === "expert" ? " mode-toggle__button--active" : ""}`}
                onClick={() => setViewMode("expert")}
                type="button"
              >
                Expert
              </button>
            </div>
            <p className="mode-panel__copy">
              {viewMode === "simple"
                ? "Show the operator workflow only: what happened, what to do, alternatives, and blind spots."
                : "Show deeper audit history, cyber context, and agent support for analyst review."}
            </p>
          </section>

          {viewMode === "expert" ? (
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
          ) : null}

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
              rawLogs={incidentEvents}
              viewMode={viewMode}
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
            <AuditTrailView
              operatorAuditEntries={viewModel.operatorAuditEntries}
              cyberAuditEntries={viewModel.cyberAuditEntries}
            />
          )}
        </section>
      </div>
    </main>
  );
}
