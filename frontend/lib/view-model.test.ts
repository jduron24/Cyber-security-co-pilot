import { buildAuditEntries, buildIncidentViewModel, displayLabel, mapQueueItem } from "./view-model";
import type { OperatorHistoryResponse } from "@/types/api";

describe("view-model helpers", () => {
  it("maps queue items from incident payloads", () => {
    const item = mapQueueItem({
      incident_id: "incident_1",
      title: "Unusual login with missing network branch",
      severity_hint: "high",
      entities: { primary_source_ip_address: "198.51.100.10" },
    });

    expect(item.id).toBe("incident_1");
    expect(item.label).toBe("INC-1042");
    expect(item.site).toBe("198.51.100.10");
    expect(item.severity).toBe("High");
  });

  it("builds audit entries from operator history", () => {
    const history: OperatorHistoryResponse = {
      latest_decision: null,
      recent_decisions: [
        {
          created_at: "2025-01-01T00:00:00Z",
          decision_type: "approve_recommendation",
          chosen_action_label: "Reset credentials",
          rationale: "Suspicious login followed by access-key creation.",
        },
      ],
      review_events: [{ created_at: "2025-01-01T00:01:00Z", event_type: "double_check_requested", payload_json: { decision_risk_note: "Need network review." } }],
    };

    const entries = buildAuditEntries(history);
    expect(entries).toHaveLength(2);
    expect(entries[0].title).toBe("Approve Recommendation");
    expect(entries[0].detail).toContain("Rationale: Suspicious login followed by access-key creation.");
    expect(entries[1].detail).toBe("Need network review.");
  });

  it("builds the incident view model from backend payloads", () => {
    const model = buildIncidentViewModel(
      {
        incident_id: "incident_1",
        title: "Incident title",
        severity_hint: "high",
        entities: { primary_source_ip_address: "203.0.113.10" },
      },
      {
        provenance_json: { source: "demo_runner" },
        raw_refs_json: { coverage_categories: ["login", "network"] },
      },
      {
        risk_band: "high",
        detector_labels_json: ["privilege_change"],
        data_sources_used_json: ["demo_stream", "network_logs"],
      },
      {
        completeness_level: "medium",
        checks_json: [{ name: "network_logs", status: "not_checked" }],
        missing_sources_json: ["network_logs"],
      },
      {
        recommended_action: { action_id: "reset_credentials", label: "Reset credentials", reason: "Reason" },
        alternative_actions: [{ action_id: "escalate_to_expert", label: "Escalate", reason: "Reason", tradeoff: "Tradeoff" }],
      },
      null,
      {
        incident_summary: {
          title: "Incident title",
          summary: "Summary",
          risk_score: 0.88,
          risk_band: "high",
          event_sequence: ["ConsoleLogin"],
          top_signals: [{ label: "privilege_change" }],
        },
        recommended_action: {
          action_id: "reset_credentials",
          label: "Reset credentials",
          reason: "Reason",
          requires_human_approval: true,
        },
        alternative_actions: [{ action_id: "escalate_to_expert", label: "Escalate", reason: "Reason", tradeoff: "Tradeoff" }],
        coverage_status_by_category: [{ category: "network", status: "not_checked", missing_sources: ["network_logs"] }],
        completeness: { warning: "Warning" },
        recommendation_may_be_incomplete: true,
        decision_risk_note: "Risk note",
        what_could_change_the_decision: ["A"],
        double_check: { candidates: ["Review network logs"] },
      },
      {
        latest_decision: {
          decision_type: "approve_recommendation",
          chosen_action_label: "Reset credentials",
          rationale: "The credential reset is the fastest containment step.",
          created_at: "2025-01-01T00:05:00Z",
        },
        recent_decisions: [],
        review_events: [],
      },
      "incident_1",
    );

    expect(model.recommendedAction.label).toBe("Reset credentials");
    expect(model.signals[0].label).toBe("Privilege change");
    expect(model.signals[0].explanation).toContain("permissions or access levels changed");
    expect(model.coverage[0].status).toBe("Not checked");
    expect(model.coverage[0].note).toContain("network_logs");
    expect(model.recommendationMayBeIncomplete).toBe(true);
    expect(model.cyberAuditEntries[0].title).toContain("Evidence package");
    expect(model.cyberAuditEntries[1].title).toContain("Detector scored high risk");
    expect(model.latestDecision?.title).toContain("Human decision recorded");
    expect(model.latestDecision?.rationale).toBe("The credential reset is the fastest containment step.");
    expect(model.latestDecision?.recordedAt).toBe("2025-01-01T00:05:00Z");
  });

  it("maps known backend keys to operator-facing labels", () => {
    expect(displayLabel("recon_plus_privilege")).toBe("Reconnaissance and privilege change pattern");
    expect(displayLabel("checked_signal_found")).toBe("Checked, signal found");
    expect(displayLabel("temporary_access_lock")).toBe("Temporarily lock access");
  });
});
