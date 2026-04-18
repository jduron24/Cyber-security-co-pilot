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
  signals: [{ label: "privilege_change", detail: "Permissions changed." }],
  timeline: [{ step: "Step 1", title: "ConsoleLogin" }],
  coverage: [{ category: "Network", status: "Not Checked", rawStatus: "not_checked", note: "Missing: network_logs" }],
  whatCouldChange: ["If network_logs shows more activity, the recommendation may change."],
  doubleCheckCandidates: ["Review network logs"],
  latestDecision: null,
  auditEntries: [],
};

describe("ActiveIncidentView", () => {
  it("renders warning and enables alternative selection flow", () => {
    const onSelectAlternative = vi.fn();

    render(
      <ActiveIncidentView
        viewModel={viewModel}
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
    fireEvent.click(screen.getByRole("button", { name: /temporary access lock/i }));
    expect(onSelectAlternative).toHaveBeenCalledWith("temporary_access_lock");
  });
});
