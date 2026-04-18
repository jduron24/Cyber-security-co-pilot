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
  explanation: string;
}

export interface ModelContributionItem {
  feature: string;
  contribution: number;
  direction: string;
  plainLanguage: string;
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
  rationale: string | null;
  recordedAt: string | null;
}

export interface AuditEntry {
  time: string;
  title: string;
  detail: string;
}

export interface CyberAuditEntry {
  title: string;
  detail: string;
  source: string;
}

export interface IncidentViewModel {
  title: string;
  incidentId: string;
  severity: string;
  site: string;
  summary: string;
  confidence: number;
  modelType: string;
  modelVersion: string | null;
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
  modelContributions: ModelContributionItem[];
  timeline: TimelineItem[];
  coverage: CoverageItem[];
  whatCouldChange: string[];
  doubleCheckCandidates: string[];
  latestDecision: LatestDecisionItem | null;
  operatorAuditEntries: AuditEntry[];
  cyberAuditEntries: CyberAuditEntry[];
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

const SIGNAL_EXPLANATIONS: Record<string, string> = {
  recon_activity: "This means the account or session was looking around the environment, which often happens before a bigger change or attack.",
  privilege_change: "This means permissions or access levels changed. That can increase what the account is able to do and usually deserves attention.",
  console_login: "This means someone used the web console to access the environment. It matters because interactive logins can indicate hands-on activity.",
  assumed_role_actor: "This means the activity came from a temporary role session instead of a long-lived user. That can make tracing the true source more important.",
  iam_sequence: "This means several identity and access management actions happened close together, which can signal account misuse.",
  sts_sequence: "This means token or identity-verification actions happened in sequence, which can be part of session setup or credential validation.",
  recon_plus_privilege: "This means the same incident shows both reconnaissance and permission changes, which is a stronger sign of risky activity.",
  root_actor: "This means the root account was involved. Root activity is high impact because it has very broad access.",
  ec2_sequence: "This means compute infrastructure actions happened in sequence. It can indicate someone is exploring or changing live resources.",
  resource_creation: "This means new resources were created. That matters because attackers often create new infrastructure to keep access or expand activity.",
  recon_plus_resource_creation: "This means the same incident shows both exploration and new resource creation, which raises concern that the activity is deliberate.",
  suspicious_console_login: "This means the console login itself looked abnormal based on the surrounding signals and context.",
  active_network_beaconing: "This means network activity suggests the session or host may still be communicating regularly, which can indicate ongoing compromise.",
  resource_creation_after_login: "This means new resources appeared shortly after login, which can be a sign of fast post-login action.",
  ongoing_session_activity: "This means the suspicious session may still be active rather than already finished.",
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

export function explainSignal(value: unknown): string {
  const raw = asOptionalString(value);
  if (!raw) return "This signal marks activity that contributed to the recommendation.";
  return SIGNAL_EXPLANATIONS[raw] ?? "This signal marks activity that contributed to the recommendation.";
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
    const rationale = asOptionalString(row.rationale);
    return {
      time: asString(row.created_at, "Recently"),
      title: toSentenceCase(asString(row.decision_type, "operator update")),
      detail: `${chosenAction}${asBoolean(row.used_double_check) ? " after double check" : ""}${rationale ? `. Rationale: ${rationale}` : ""}`,
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

export function buildCyberAuditEntries(
  evidencePackage: RecordShape | null,
  detectorResult: RecordShape | null,
  coverageAssessment: RecordShape | null,
  decisionSupportResult: RecordShape | null,
  coverageReview: RecordShape | null,
): CyberAuditEntry[] {
  const entries: CyberAuditEntry[] = [];
  const evidence = asRecord(evidencePackage);
  const detector = asRecord(detectorResult);
  const coverage = asRecord(coverageAssessment);
  const decisionSupport = asRecord(decisionSupportResult);
  const review = asRecord(coverageReview);

  if (Object.keys(evidence).length) {
    const provenance = asRecord(evidence.provenance_json);
    const rawRefs = asRecord(evidence.raw_refs_json);
    const categories = asArray<string>(rawRefs.coverage_categories).map((item) => displayLabel(item, item)).join(", ");
    entries.push({
      title: "Evidence package loaded",
      detail: `${asString(provenance.source, "system")} supplied the evidence package${categories ? ` across ${categories}` : ""}.`,
      source: "Evidence package",
    });
  }

  if (Object.keys(detector).length) {
    const labels = asArray<string>(detector.detector_labels_json).slice(0, 3).map((item) => displayLabel(item, item));
    const sources = asArray<string>(detector.data_sources_used_json).join(", ");
    entries.push({
      title: `Detector scored ${asString(detector.risk_band, "unknown")} risk`,
      detail: `${labels.length ? `Top detector labels: ${labels.join(", ")}.` : "Detector output available."}${sources ? ` Data sources: ${sources}.` : ""}`,
      source: "Detector",
    });
    const contributions = asArray<RecordShape>(detector.feature_contributions_json).slice(0, 3);
    if (contributions.length) {
      entries.push({
        title: `Model explanation from ${asString(detector.model_type, "detector model").toUpperCase()}`,
        detail: contributions
          .map((item) => asString(item.plain_language, `${displayLabel(item.feature, "Signal")} ${asString(item.direction, "affected the score")}.`))
          .join(" "),
        source: "Detector explanation",
      });
    }
  }

  if (Object.keys(coverage).length) {
    const checks = asArray<RecordShape>(coverage.checks_json).map((item) => `${displayLabel(item.name, "Check")}: ${displayLabel(item.status, "Unknown")}`);
    const missing = asArray<string>(coverage.missing_sources_json);
    entries.push({
      title: `Coverage assessed ${asString(coverage.completeness_level, "unknown")} completeness`,
      detail: `${checks.length ? `Checks: ${checks.join("; ")}.` : ""}${missing.length ? ` Missing sources: ${missing.join(", ")}.` : ""}`.trim(),
      source: "Coverage",
    });
  }

  if (Object.keys(decisionSupport).length) {
    const recommended = asRecord(decisionSupport.recommended_action);
    const alternatives = asArray<RecordShape>(decisionSupport.alternative_actions)
      .slice(0, 3)
      .map((item) => displayLabel(item.label ?? item.action_id, "Alternative"));
    entries.push({
      title: `Decision support recommended ${displayLabel(recommended.label ?? recommended.action_id, "an action")}`,
      detail: `${asString(recommended.reason, "No recommendation reason recorded.")}${alternatives.length ? ` Alternatives considered: ${alternatives.join(", ")}.` : ""}`,
      source: "Decision support",
    });
  }

  if (Object.keys(review).length) {
    const decisionChanges = asArray<string>(review.what_could_change_the_decision);
    const candidates = asArray<string>(asRecord(review.double_check).candidates);
    entries.push({
      title: "Coverage review framed decision risk",
      detail: `${asString(review.decision_risk_note, "Coverage review available.")}${decisionChanges.length ? ` Decision changers: ${decisionChanges.slice(0, 2).join(" ")}` : ""}${candidates.length ? ` Double-check candidates: ${candidates.join(", ")}.` : ""}`,
      source: "Coverage review",
    });
  }

  return entries;
}

export function buildIncidentViewModel(
  incident: RecordShape | null,
  evidencePackage: RecordShape | null,
  detectorResult: RecordShape | null,
  coverageAssessment: RecordShape | null,
  decisionSupportResultRecord: RecordShape | null,
  decisionSupport: RecordShape | null,
  coverageReview: RecordShape | null,
  operatorHistory: OperatorHistoryResponse | null,
  selectedIncidentId: string,
): IncidentViewModel {
  const incidentRecord = asRecord(incident);
  const coverageReviewRecord = asRecord(coverageReview);
  const incidentSummary = asRecord(coverageReviewRecord.incident_summary);
  const decisionSupportRecord = asRecord(decisionSupport);
  const decisionSupportResult = asRecord(
    Object.keys(asRecord(decisionSupportResultRecord)).length ? decisionSupportResultRecord : decisionSupportRecord.decision_support_result,
  );
  const recommendedAction = asRecord(coverageReviewRecord.recommended_action ?? decisionSupportResult.recommended_action);
  const alternativeActions = asArray<RecordShape>(coverageReviewRecord.alternative_actions);
  const eventSequence = asArray<string>(incidentSummary.event_sequence);
  const topSignals = asArray<RecordShape>(incidentSummary.top_signals);
  const detectorTopSignals = asArray<RecordShape>(detectorRecord.top_signals_json ?? detectorRecord.top_signals);
  const featureContributions = asArray<RecordShape>(detectorRecord.feature_contributions_json ?? detectorRecord.feature_contributions);
  const coverageItems = asArray<RecordShape>(coverageReviewRecord.coverage_status_by_category);
  const completeness = asRecord(coverageReviewRecord.completeness);
  const latestDecision = asRecord(operatorHistory?.latest_decision ?? null);
  const modelContributions = featureContributions.slice(0, 5).map((item) => ({
    feature: displayLabel(item.feature, "Signal"),
    contribution: asNumber(item.contribution),
    direction: asString(item.direction, "affected the score"),
    plainLanguage: asString(item.plain_language, "This factor affected the model score."),
  }));
  const detectorExplanation = asRecord(detectorRecord.explanation_json ?? detectorRecord.explanation);
  const scoreFromIncidentSummary = typeof incidentSummary.risk_score === "number" ? incidentSummary.risk_score : null;
  const scoreFromDetector = typeof detectorRecord.risk_score === "number" ? detectorRecord.risk_score : null;
  const scoreFromExplanation = typeof detectorExplanation.prediction_probability === "number" ? detectorExplanation.prediction_probability : null;
  const riskScore = scoreFromIncidentSummary ?? scoreFromDetector ?? scoreFromExplanation ?? 0.84;
  const hasIncidentSummarySignals = topSignals.length > 0;
  const fallbackSignals = hasIncidentSummarySignals ? detectorTopSignals : featureContributions;
  const signalsSource = hasIncidentSummarySignals ? topSignals : fallbackSignals;

  return {
    title: asString(incidentSummary.title ?? incidentRecord.title, "Suspicious access activity"),
    incidentId: asString(incidentRecord.incident_id, selectedIncidentId),
    severity: toSentenceCase(asString(incidentSummary.risk_band ?? incidentRecord.severity_hint, "high")),
    site: asString(asRecord(incidentRecord.entities).primary_source_ip_address ?? incidentRecord.title, "Unknown site"),
    summary: asString(incidentSummary.summary ?? incidentRecord.summary, "Incident summary unavailable."),
    confidence: Math.round(asNumber(riskScore, 0.84) * 100),
    modelType: asString(detectorRecord.model_type, "unknown"),
    modelVersion: asOptionalString(detectorRecord.model_version),
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
    signals: signalsSource.map((item) => ({
      label: displayLabel(item.label ?? item.feature, "Signal"),
      detail: asString(
        item.detail,
        typeof item.contribution === "number"
          ? `${item.contribution >= 0 ? "Increases" : "Decreases"} suspicion (contribution ${item.contribution.toFixed(3)}).`
          : displayLabel(item.label ?? item.feature, "Suspicious activity detected."),
      ),
      explanation: explainSignal(item.label ?? item.feature),
    })),
    modelContributions,
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
          title: `Human decision recorded: ${toSentenceCase(asString(latestDecision.decision_type, "decision recorded"))}`,
          detail: asString(displayLabel(latestDecision.chosen_action_label ?? latestDecision.chosen_action_id, "Action recorded"), "Action recorded"),
          rationale: asOptionalString(latestDecision.rationale),
          recordedAt: asOptionalString(latestDecision.created_at),
        }
      : null,
    operatorAuditEntries: buildAuditEntries(operatorHistory),
    cyberAuditEntries: buildCyberAuditEntries(evidencePackage, detectorResult, coverageAssessment, decisionSupportResult, coverageReviewRecord),
  };
}
