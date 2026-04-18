import type { OperatorHistoryResponse, RecordShape } from "@/types/api";

export interface QueueItem {
  id: string;
  label: string;
  site: string;
  severity: string;
  state: string;
}

export interface SignalItem {
  label: string;
  detail: string;
}

export interface TimelineItem {
  step: string;
  title: string;
}

export interface CoverageItem {
  category: string;
  status: string;
  rawStatus: string;
  note: string;
}

export interface AlternativeItem {
  actionId: string;
  label: string;
  reason: string;
  tradeoff: string;
}

export interface LatestDecisionItem {
  title: string;
  detail: string;
}

export interface AuditEntry {
  time: string;
  title: string;
  detail: string;
}

export interface IncidentViewModel {
  title: string;
  incidentId: string;
  severity: string;
  site: string;
  summary: string;
  confidence: number;
  recommendationMayBeIncomplete: boolean;
  incompletenessWarning: string | null;
  decisionRiskNote: string;
  recommendedAction: {
    actionId: string;
    label: string;
    reason: string;
    requiresHumanApproval: boolean;
  };
  alternatives: AlternativeItem[];
  signals: SignalItem[];
  timeline: TimelineItem[];
  coverage: CoverageItem[];
  whatCouldChange: string[];
  doubleCheckCandidates: string[];
  latestDecision: LatestDecisionItem | null;
  auditEntries: AuditEntry[];
}

const DISPLAY_LABELS: Record<string, string> = {
  reset_credentials: "Reset credentials",
  temporary_access_lock: "Temporarily lock access",
  collect_more_evidence: "Collect more evidence",
  escalate_to_expert: "Escalate to expert",
  checked_signal_found: "Checked, signal found",
  checked_no_signal: "Checked, no signal",
  not_checked: "Not checked",
  unavailable: "Could not check",
  no_signal: "No signal found",
  recon_activity: "Reconnaissance activity",
  privilege_change: "Privilege change",
  console_login: "Console login",
  assumed_role_actor: "Assumed role actor",
  iam_sequence: "IAM activity sequence",
  sts_sequence: "STS activity sequence",
  recon_plus_privilege: "Reconnaissance and privilege change pattern",
  compromised_identity: "Compromised identity",
  misconfigured_automation: "Misconfigured automation",
  login: "Login",
  identity: "Identity",
  network: "Network",
};

const INCIDENT_QUEUE_LABELS: Record<string, string> = {
  "Unusual login with missing network branch": "INC-1042",
  "Complete high-confidence credential misuse case": "INC-1038",
  "Resource launch with unavailable device context": "INC-1033",
};

export function asRecord(value: unknown): RecordShape {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as RecordShape) : {};
}

export function asArray<T = unknown>(value: unknown): T[] {
  return Array.isArray(value) ? (value as T[]) : [];
}

export function asString(value: unknown, fallback = "Unavailable"): string {
  return typeof value === "string" && value.trim() ? value : fallback;
}

export function asOptionalString(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value : null;
}

export function asBoolean(value: unknown, fallback = false): boolean {
  return typeof value === "boolean" ? value : fallback;
}

export function asNumber(value: unknown, fallback = 0): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

export function toSentenceCase(value: string): string {
  if (!value) return "Unavailable";
  return value
    .split(/[_-]/g)
    .map((part) => (part ? part[0].toUpperCase() + part.slice(1) : part))
    .join(" ");
}

export function displayLabel(value: unknown, fallback = "Unavailable"): string {
  const raw = asOptionalString(value);
  if (!raw) return fallback;
  return DISPLAY_LABELS[raw] ?? toSentenceCase(raw);
}

export function toneForSeverity(value: string): "critical" | "warning" | "safe" | "neutral" {
  const normalized = value.toLowerCase();
  if (normalized.includes("high")) return "critical";
  if (normalized.includes("medium")) return "warning";
  if (normalized.includes("low")) return "safe";
  return "neutral";
}

export function toneForCoverageStatus(value: string): "critical" | "warning" | "safe" | "neutral" {
  const normalized = value.toLowerCase();
  if (normalized.includes("signal_found")) return "critical";
  if (normalized.includes("not_checked") || normalized.includes("unavailable")) return "warning";
  if (normalized.includes("no_signal")) return "safe";
  return "neutral";
}

export function summarizeCoverageNote(row: RecordShape): string {
  const checks = asArray<RecordShape>(row.checks);
  const missingSources = asArray<string>(row.missing_sources).filter(Boolean);
  if (missingSources.length) {
    return `Missing: ${missingSources.join(", ")}`;
  }
  if (checks.length) {
    const first = checks[0];
    return asString(first.detail, `${checks.length} checks available`);
  }
  return "No additional detail available.";
}

export function mapQueueItem(item: RecordShape): QueueItem {
  const entities = asRecord(item.entities);
  const title = asString(item.title, "Incident");
  return {
    id: asString(item.incident_id, "incident"),
    label: INCIDENT_QUEUE_LABELS[title] ?? asString(item.incident_id, "incident"),
    site: asString(entities.primary_source_ip_address ?? item.title, "Unknown site"),
    severity: toSentenceCase(asString(item.severity_hint, "unknown")),
    state: "Needs review",
  };
}

export function buildAuditEntries(operatorHistory: OperatorHistoryResponse | null): AuditEntry[] {
  if (!operatorHistory) return [];
  const decisions = operatorHistory.recent_decisions.map((item) => {
    const row = asRecord(item);
    const chosenAction = asOptionalString(row.chosen_action_label) ?? asOptionalString(row.chosen_action_id) ?? "Decision recorded";
    return {
      time: asString(row.created_at, "Recently"),
      title: toSentenceCase(asString(row.decision_type, "operator update")),
      detail: `${chosenAction}${asBoolean(row.used_double_check) ? " after double check" : ""}`,
    };
  });
  const reviewEvents = operatorHistory.review_events.map((item) => {
    const row = asRecord(item);
    return {
      time: asString(row.created_at, "Recently"),
      title: toSentenceCase(asString(row.event_type, "review event")),
      detail: asString(asRecord(row.payload_json).decision_risk_note, "Additional review context recorded."),
    };
  });
  return [...decisions, ...reviewEvents].slice(0, 8);
}

export function buildIncidentViewModel(
  incident: RecordShape | null,
  decisionSupport: RecordShape | null,
  coverageReview: RecordShape | null,
  operatorHistory: OperatorHistoryResponse | null,
  selectedIncidentId: string,
): IncidentViewModel {
  const incidentRecord = asRecord(incident);
  const coverageReviewRecord = asRecord(coverageReview);
  const incidentSummary = asRecord(coverageReviewRecord.incident_summary);
  const decisionSupportRecord = asRecord(decisionSupport);
  const decisionSupportResult = asRecord(decisionSupportRecord.decision_support_result);
  const recommendedAction = asRecord(coverageReviewRecord.recommended_action ?? decisionSupportResult.recommended_action);
  const alternativeActions = asArray<RecordShape>(coverageReviewRecord.alternative_actions);
  const eventSequence = asArray<string>(incidentSummary.event_sequence);
  const topSignals = asArray<RecordShape>(incidentSummary.top_signals);
  const coverageItems = asArray<RecordShape>(coverageReviewRecord.coverage_status_by_category);
  const completeness = asRecord(coverageReviewRecord.completeness);
  const latestDecision = asRecord(operatorHistory?.latest_decision ?? null);

  return {
    title: asString(incidentSummary.title ?? incidentRecord.title, "Suspicious access activity"),
    incidentId: asString(incidentRecord.incident_id, selectedIncidentId),
    severity: toSentenceCase(asString(incidentSummary.risk_band ?? incidentRecord.severity_hint, "high")),
    site: asString(asRecord(incidentRecord.entities).primary_source_ip_address ?? incidentRecord.title, "Unknown site"),
    summary: asString(incidentSummary.summary ?? incidentRecord.summary, "Incident summary unavailable."),
    confidence: Math.round(asNumber(incidentSummary.risk_score, 0.84) * 100),
    recommendationMayBeIncomplete: asBoolean(coverageReviewRecord.recommendation_may_be_incomplete),
    incompletenessWarning: asOptionalString(completeness.warning),
    decisionRiskNote: asString(coverageReviewRecord.decision_risk_note, "Review available evidence before acting."),
    recommendedAction: {
      actionId: asString(recommendedAction.action_id, "recommended_action"),
      label: asString(recommendedAction.label ?? recommendedAction.action_id, "Recommended action"),
      reason: asString(recommendedAction.reason, "No recommendation reason available."),
      requiresHumanApproval: asBoolean(recommendedAction.requires_human_approval, true),
    },
    alternatives: alternativeActions.map((item) => ({
      actionId: asString(item.action_id, "alternative"),
      label: displayLabel(item.label ?? item.action_id, "Alternative"),
      reason: asString(item.reason, "No reason available."),
      tradeoff: asString(item.tradeoff, "No tradeoff available."),
    })),
    signals: topSignals.map((item) => ({
      label: displayLabel(item.label ?? item.feature, "Signal"),
      detail: asString(item.detail, displayLabel(item.label ?? item.feature, "Suspicious activity detected.")),
    })),
    timeline: eventSequence.slice(0, 6).map((item, index) => ({
      step: `Step ${index + 1}`,
      title: asString(item, "Activity"),
    })),
    coverage: coverageItems.map((item) => ({
      category: displayLabel(item.category, "Coverage"),
      status: displayLabel(item.status, "Unknown"),
      rawStatus: asString(item.status, "unknown"),
      note: summarizeCoverageNote(item),
    })),
    whatCouldChange: asArray<string>(coverageReviewRecord.what_could_change_the_decision).filter(Boolean),
    doubleCheckCandidates: asArray<string>(asRecord(coverageReviewRecord.double_check).candidates).filter(Boolean),
    latestDecision: Object.keys(latestDecision).length
      ? {
          title: toSentenceCase(asString(latestDecision.decision_type, "decision recorded")),
          detail: asString(
            displayLabel(latestDecision.chosen_action_label ?? latestDecision.chosen_action_id, "Action recorded"),
            "Action recorded",
          ),
        }
      : null,
    auditEntries: buildAuditEntries(operatorHistory),
  };
}
