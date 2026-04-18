import { fireEvent, render, screen } from "@testing-library/react";

import type { IncidentViewModel } from "@/lib/view-model";
import { ActiveIncidentView } from "./ActiveIncidentView";

const viewModel: IncidentViewModel = {
  title: "Suspicious access activity",
  incidentId: "incident_000000001",
  severity: "High",
  site: "203.0.113.10",
  summary: "Summary",
  confidence: 92,
  recommendationMayBeIncomplete: true,
  incompletenessWarning: "Network branch is missing.",
  decisionRiskNote: "Review network evidence before acting.",
  recommendedAction: {
    actionId: "reset_credentials",
    label: "Reset credentials",
    reason: "Fast containment step.",
    requiresHumanApproval: true,
  },
  alternatives: [
    {
      actionId: "temporary_access_lock",
      label: "Temporary access lock",
      reason: "Contain immediately.",
      tradeoff: "Can interrupt legitimate work.",
    },
  ],
  signals: [{ label: "Privilege change", detail: "Permissions changed.", explanation: "This means permissions or access levels changed." }],
  modelType: "ebm",
  modelContributions: [
    {
      feature: "Failure ratio",
      contribution: 0.34,
      direction: "increases suspicion",
      plainLanguage: "A high failure ratio increased suspicion.",
    },
  ],
  timeline: [{ step: "Step 1", title: "ConsoleLogin" }],
  coverage: [{ category: "Network", status: "Not Checked", rawStatus: "not_checked", note: "Missing: network_logs" }],
  whatCouldChange: ["If network_logs shows more activity, the recommendation may change."],
  doubleCheckCandidates: ["Review network logs"],
  latestDecision: {
    title: "Human decision recorded: Approve Recommendation",
    detail: "Reset credentials",
    rationale: "Contain the account before more changes happen.",
    recordedAt: "2025-01-01T00:05:00Z",
  },
  operatorAuditEntries: [],
  cyberAuditEntries: [],
};

describe("ActiveIncidentView", () => {
  it("renders the simple view without expert-only panels", () => {
    const onSelectAlternative = vi.fn();

    render(
      <ActiveIncidentView
        viewModel={viewModel}
        rawLogs={[]}
        viewMode="simple"
        incidentLoading={false}
        incidentError={null}
        actionMessage={null}
        selectedAlternativeId={null}
        rationale=""
        actionLoading={false}
        agentAuth={null}
        agentQuestion="What should I do?"
        agentAnswer={null}
        agentLoading={false}
        agentError={null}
        onSelectAlternative={onSelectAlternative}
        onRationaleChange={vi.fn()}
        onApprove={vi.fn()}
        onAlternative={vi.fn()}
        onDoubleCheck={vi.fn()}
        onEscalate={vi.fn()}
        onAgentQuestionChange={vi.fn()}
        onAgentAsk={vi.fn()}
      />,
    );

    expect(screen.getByText(/recommendation may be incomplete/i)).toBeInTheDocument();
    expect(screen.getByText(/a\. what happened\?/i)).toBeInTheDocument();
    expect(screen.getByText(/b\. what should i do\?/i)).toBeInTheDocument();
    expect(screen.getByText(/c\. what else could i do\?/i)).toBeInTheDocument();
    expect(screen.getByText(/d\. did we check everything\?/i)).toBeInTheDocument();
    expect(screen.getByText(/human decision recorded/i)).toBeInTheDocument();
    expect(screen.getByText(/rationale: contain the account before more changes happen\./i)).toBeInTheDocument();
    expect(screen.queryByText(/^agent$/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/confidence/i)).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /temporary access lock/i }));
    expect(onSelectAlternative).toHaveBeenCalledWith("temporary_access_lock");
  });

  it("renders expert-only signal details when expert mode is enabled", () => {
    render(
      <ActiveIncidentView
        viewModel={viewModel}
        rawLogs={[
          {
            event_id: "evt-1",
            event_name: "ConsoleLogin",
            event_source: "signin.amazonaws.com",
            event_index: 0,
            event_payload: { eventName: "ConsoleLogin", sourceIPAddress: "203.0.113.10" },
          },
        ]}
        viewMode="expert"
        incidentLoading={false}
        incidentError={null}
        actionMessage={null}
        selectedAlternativeId={null}
        rationale=""
        actionLoading={false}
        agentAuth={null}
        agentQuestion="What should I do?"
        agentAnswer={null}
        agentLoading={false}
        agentError={null}
        onSelectAlternative={vi.fn()}
        onRationaleChange={vi.fn()}
        onApprove={vi.fn()}
        onAlternative={vi.fn()}
        onDoubleCheck={vi.fn()}
        onEscalate={vi.fn()}
        onAgentQuestionChange={vi.fn()}
        onAgentAsk={vi.fn()}
      />,
    );

    expect(screen.getByText(/why sentinel is concerned/i)).toBeInTheDocument();
    expect(screen.getByText(/why the model flagged this/i)).toBeInTheDocument();
    expect(screen.getByText(/a high failure ratio increased suspicion\./i)).toBeInTheDocument();
    expect(screen.getByText(/raw logs for expert review/i)).toBeInTheDocument();
    expect(screen.getByText(/signin\.amazonaws\.com/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /explain privilege change/i }));
    expect(screen.getByText(/permissions or access levels changed/i)).toBeInTheDocument();
    expect(screen.getByText(/^agent$/i)).toBeInTheDocument();
  });
});
