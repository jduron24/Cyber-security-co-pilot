import { fireEvent, render, screen, waitFor } from "@testing-library/react";

import * as api from "@/lib/api";
import Home from "./page";

vi.mock("next/image", () => ({
  default: (props: Record<string, unknown>) => {
    const { alt, src, priority: _priority, ...rest } = props;
    return <img alt={String(alt ?? "")} src={String(src ?? "")} {...rest} />;
  },
}));

vi.mock("@/lib/api", () => ({
  ApiError: class ApiError extends Error {
    status?: number;
    constructor(message: string, status?: number) {
      super(message);
      this.name = "ApiError";
      this.status = status;
    }
  },
  listIncidents: vi.fn(async () => [
    {
      incident_id: "incident_000000001",
      title: "Unusual login with missing network branch",
      severity_hint: "medium",
      entities: { primary_source_ip_address: "203.0.113.10" },
      start_time: "2026-04-18T09:15:00Z",
      end_time: "2026-04-18T09:22:00Z",
    },
  ]),
  loadIncidentWorkspace: vi.fn(async () => ({
    incident: {
      incident_id: "incident_000000001",
      title: "Unusual login with missing network branch",
      summary: "Summary",
      severity_hint: "medium",
      primary_actor: { actor_key: "demo-user@example.com" },
      entities: { primary_source_ip_address: "203.0.113.10" },
      start_time: "2026-04-18T09:15:00Z",
      end_time: "2026-04-18T09:22:00Z",
      event_sequence: ["ConsoleLogin", "ListUsers", "CreateAccessKey"],
    },
    incidentEvents: [],
    evidencePackage: null,
    detectorResult: {
      risk_score: 0.72,
      risk_band: "medium",
      top_signals: [{ label: "console_login" }],
      model_type: "ebm",
      feature_contributions: [],
    },
    coverageAssessment: {
      completeness_level: "medium",
      checks: [{ category: "network_logs", status: "not_checked", note: "Missing: network logs" }],
      missing_sources: ["network_logs"],
    },
    decisionSupportResult: {
      recommended_action: {
        action_id: "reset_credentials",
        label: "Reset credentials",
        reason: "Contain the account.",
        requires_human_approval: true,
      },
      alternative_actions: [
        {
          action_id: "collect_more_evidence",
          label: "Collect more evidence",
          reason: "Important checks are missing.",
          tradeoff: "This may delay a stronger response.",
        },
      ],
      completeness_assessment: {
        level: "medium",
        warning: "This recommendation may be incomplete.",
        reasons: ["Network telemetry was not checked."],
      },
    },
    decisionSupport: {
      incident_summary: {
        title: "Unusual login with missing network branch",
        summary: "Summary",
        risk_band: "medium",
      },
      recommended_action: {
        action_id: "reset_credentials",
        label: "Reset credentials",
        reason: "Contain the account.",
        requires_human_approval: true,
      },
      alternative_actions: [
        {
          action_id: "collect_more_evidence",
          label: "Collect more evidence",
          reason: "Important checks are missing.",
          tradeoff: "This may delay a stronger response.",
        },
      ],
      completeness_assessment: {
        level: "medium",
        warning: "This recommendation may be incomplete.",
        reasons: ["Network telemetry was not checked."],
      },
    },
    coverageReview: {
      incident_summary: {
        title: "Unusual login with missing network branch",
        summary: "Summary",
        risk_band: "medium",
        top_signals: [{ label: "console_login", detail: "Someone signed in." }],
      },
      recommended_action: {
        action_id: "reset_credentials",
        label: "Reset credentials",
        reason: "Contain the account.",
        requires_human_approval: true,
      },
      alternative_actions: [
        {
          action_id: "collect_more_evidence",
          label: "Collect more evidence",
          reason: "Important checks are missing.",
          tradeoff: "This may delay a stronger response.",
        },
      ],
      recommendation_may_be_incomplete: true,
      decision_risk_note: "Review network evidence before acting.",
      coverage_status_by_category: [
        { category: "network_logs", status: "not_checked", note: "Missing: network logs" },
      ],
      what_could_change_the_decision: ["Network telemetry could change the decision."],
      double_check_candidates: ["Review network logs"],
    },
    operatorHistory: {
      latest_decision: null,
      recent_decisions: [],
      review_events: [],
    },
  })),
  postApprove: vi.fn(),
  getLatestReport: vi.fn(),
  downloadReportPdf: vi.fn(),
  postAlternative: vi.fn(),
  postEscalate: vi.fn(),
  postDoubleCheck: vi.fn(),
  getAgentAuth: vi.fn(async () => ({
    auth_mode: "api_key",
    model: "gpt-5.4",
    labels: { api_key: "Production mode" },
  })),
  postAgentQuery: vi.fn(),
}));

describe("Home page view switching", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  async function renderLoadedHome() {
    render(<Home />);
    await waitFor(() => {
      expect(screen.getByText(/a\. what happened\?/i)).toBeInTheDocument();
    });
    await waitFor(() => {
      expect(screen.getByText(/reset credentials/i)).toBeInTheDocument();
    });
  }

  it("switches between simple and expert views and exposes the audit tab only in expert mode", async () => {
    await renderLoadedHome();

    expect(screen.queryByRole("button", { name: /audit trail/i })).not.toBeInTheDocument();
    expect(screen.queryByText(/why this incident was flagged/i)).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /^expert$/i }));

    expect(screen.getByRole("button", { name: /active incident/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /audit trail/i })).toBeInTheDocument();
    expect(screen.getByText(/why this incident was flagged/i)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /audit trail/i }));
    expect(screen.getByText(/human decision audit trail/i)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /^simple$/i }));
    expect(screen.getByText(/a\. what happened\?/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /audit trail/i })).not.toBeInTheDocument();
  });

  it("submits approval and shows the generated report", async () => {
    vi.mocked(api.postApprove).mockResolvedValue({
      decision_type: "approve_recommendation",
      chosen_action: {
        action_id: "reset_credentials",
        label: "Reset credentials",
      },
      report: {
        incident_id: "incident_000000001",
        severity: "Medium",
        generated_at: "2026-04-18T09:30:00Z",
        title: "Approval report",
        summary: "The operator approved a credential reset after suspicious sign-in activity.",
        approved_action: {
          label: "Reset credentials",
          reason: "Contain the account.",
        },
        operator_rationale: "Contain the account before more changes happen.",
        why_sentinel_is_concerned: ["Someone signed in and then changed access."],
        blind_spots: ["Network logs are still missing."],
      },
    });

    await renderLoadedHome();

    fireEvent.change(screen.getByLabelText(/why are you taking this action/i), {
      target: { value: "Contain the account before more changes happen." },
    });
    fireEvent.click(screen.getByRole("button", { name: /approve recommendation/i }));

    await waitFor(() => {
      expect(api.postApprove).toHaveBeenCalledWith(
        "incident_000000001",
        expect.objectContaining({
          rationale: "Contain the account before more changes happen.",
          used_double_check: false,
        }),
      );
    });
    await waitFor(() => {
      expect(screen.getByText(/report drafted/i)).toBeInTheDocument();
      expect(screen.getByText(/the operator approved a credential reset/i)).toBeInTheDocument();
    });
  });

  it("loads the latest report from the workspace action", async () => {
    vi.mocked(api.getLatestReport).mockResolvedValue({
      incident_id: "incident_000000001",
      severity: "Medium",
      generated_at: "2026-04-18T09:35:00Z",
      title: "Latest report",
      summary: "Latest stored report summary.",
      approved_action: {
        label: "Reset credentials",
        reason: "Contain the account.",
      },
      operator_rationale: "Review completed.",
      why_sentinel_is_concerned: ["The account showed suspicious behavior."],
      blind_spots: ["Network logs are still missing."],
    });

    await renderLoadedHome();

    fireEvent.click(screen.getByRole("button", { name: /view latest report/i }));

    await waitFor(() => {
      expect(api.getLatestReport).toHaveBeenCalledWith("incident_000000001");
      expect(screen.getByText(/latest stored report summary/i)).toBeInTheDocument();
    });
  });

  it("submits an alternative action selection", async () => {
    vi.mocked(api.postAlternative).mockResolvedValue({
      decision_type: "choose_alternative",
      chosen_action: {
        action_id: "collect_more_evidence",
        label: "Collect more evidence",
      },
    });

    await renderLoadedHome();

    fireEvent.click(screen.getByRole("button", { name: /collect more evidence/i }));
    fireEvent.click(screen.getByRole("button", { name: /choose selected alternative/i }));

    await waitFor(() => {
      expect(api.postAlternative).toHaveBeenCalledWith(
        "incident_000000001",
        expect.objectContaining({
          action_id: "collect_more_evidence",
          used_double_check: false,
        }),
      );
    });
  });

  it("asks the agent in expert view and renders the answer", async () => {
    vi.mocked(api.postAgentQuery).mockResolvedValue({
      answer: "Reset the credentials first, then review the missing network evidence.",
    });

    await renderLoadedHome();

    fireEvent.click(screen.getByRole("button", { name: /^expert$/i }));
    fireEvent.change(screen.getByLabelText(/ask the agent/i), {
      target: { value: "What should I do next?" },
    });
    fireEvent.click(screen.getByRole("button", { name: /^ask$/i }));

    await waitFor(() => {
      expect(api.postAgentQuery).toHaveBeenCalledWith("incident_000000001", {
        user_query: "What should I do next?",
      });
      expect(screen.getByText(/reset the credentials first/i)).toBeInTheDocument();
    });
  });
});
