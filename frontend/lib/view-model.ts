import type { OperatorHistoryResponse, RecordShape } from "@/types/api";

export interface QueueItem {
  id: string;
  label: string;
  site: string;
  severity: string;
  timestamp: string | null;
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
  incidentLabel: string;
  severity: string;
  site: string;
  incidentWindow: string | null;
  timelineSubject: string;
  plainLanguageWhatHappened: string;
  summary: string;
  confidence: number;
  recommendationMayBeIncomplete: boolean;
  incompletenessWarning: string | null;
  decisionRiskNote: string;
  plainLanguageConcernSummary: string;
  recommendedAction: {
    actionId: string;
    label: string;
    reason: string;
    requiresHumanApproval: boolean;
  };
  alternatives: AlternativeItem[];
  signals: SignalItem[];
  modelType: string | null;
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
    timestamp: formatIncidentWindow(item.start_time, item.end_time),
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
    const categories = asArray<string>(rawRefs.coverage_categories).map((item) => displayLabel(item, item));
    entries.push({
      title: "What evidence was available",
      detail: `${toSentenceStart(asString(provenance.source, "system"))} provided the incident evidence${categories.length ? ` across ${joinHumanList(categories)}` : ""}.`,
      source: "Available evidence",
    });
  }

  if (Object.keys(detector).length) {
    const labels = asArray<string>(detector.detector_labels_json).slice(0, 3).map((item) => displayLabel(item, item));
    const sources = asArray<string>(detector.data_sources_used_json).join(", ");
    entries.push({
      title: `What the detector found`,
      detail: `${labels.length ? `The strongest signals were ${joinHumanList(labels)}.` : "The detector found suspicious activity."}${sources ? ` It relied on ${humanizeSourceList(sources)}.` : ""}`,
      source: "Detector finding",
    });
    const contributions = asArray<RecordShape>(detector.feature_contributions_json).slice(0, 3);
    if (contributions.length) {
      entries.push({
        title: `Why the model leaned suspicious`,
        detail: contributions
          .map((item) => asString(item.plain_language, `${displayLabel(item.feature, "Signal")} ${asString(item.direction, "affected the score")}.`))
          .join(" "),
        source: `${asString(detector.model_type, "detector model").toUpperCase()} model`,
      });
    }
  }

  if (Object.keys(coverage).length) {
    const checks = asArray<RecordShape>(coverage.checks_json).map((item) => `${displayLabel(item.name, "Check")} was ${displayLabel(item.status, "Unknown").toLowerCase()}`);
    const missing = asArray<string>(coverage.missing_sources_json);
    entries.push({
      title: `What was checked and what was missing`,
      detail: `${checks.length ? `${toSentenceStart(joinHumanList(checks))}.` : ""}${missing.length ? ` Missing sources: ${joinHumanList(missing.map((item) => displayLabel(item, item)))}.` : ""}`.trim(),
      source: "Coverage review",
    });
  }

  if (Object.keys(decisionSupport).length) {
    const recommended = asRecord(decisionSupport.recommended_action);
    const alternatives = asArray<RecordShape>(decisionSupport.alternative_actions)
      .slice(0, 3)
      .map((item) => displayLabel(item.label ?? item.action_id, "Alternative"));
    entries.push({
      title: `What the system recommended`,
      detail: `${displayLabel(recommended.label ?? recommended.action_id, "An action")} was recommended because ${lowercaseFirst(asString(recommended.reason, "no recommendation reason was recorded."))}${alternatives.length ? ` Other options considered were ${joinHumanList(alternatives)}.` : ""}`,
      source: "Decision support",
    });
  }

  if (Object.keys(review).length) {
    const decisionChanges = asArray<string>(review.what_could_change_the_decision);
    const candidates = asArray<string>(asRecord(review.double_check).candidates);
    entries.push({
      title: "Why the recommendation may still change",
      detail: `${asString(review.decision_risk_note, "Coverage review is available.")}${decisionChanges.length ? ` The decision could change if ${joinHumanList(decisionChanges.slice(0, 2).map((item) => lowercaseFirst(item)))}.` : ""}${candidates.length ? ` The next best review steps are ${joinHumanList(candidates.map((item) => lowercaseFirst(item)))}.` : ""}`,
      source: "Decision risk",
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
  const coverageItems = asArray<RecordShape>(coverageReviewRecord.coverage_status_by_category);
  const completeness = asRecord(coverageReviewRecord.completeness);
  const latestDecision = asRecord(operatorHistory?.latest_decision ?? null);
  const detectorRecord = asRecord(detectorResult);
  const modelContributions = asArray<RecordShape>(detectorRecord.feature_contributions_json).slice(0, 5).map((item) => ({
    feature: displayLabel(item.feature, "Signal"),
    contribution: asNumber(item.contribution),
    direction: asString(item.direction, "affected the score"),
    plainLanguage: asString(item.plain_language, "This factor affected the model score."),
  }));
  const confidence = deriveConfidencePercent(detectorRecord, coverageReviewRecord, incidentSummary);

  return {
    title: asString(incidentSummary.title ?? incidentRecord.title, "Suspicious access activity"),
    incidentId: asString(incidentRecord.incident_id, selectedIncidentId),
    incidentLabel:
      INCIDENT_QUEUE_LABELS[asString(incidentSummary.title ?? incidentRecord.title, "Suspicious access activity")] ??
      asString(incidentRecord.incident_id, selectedIncidentId),
    severity: toSentenceCase(asString(incidentSummary.risk_band ?? incidentRecord.severity_hint, "high")),
    site: asString(asRecord(incidentRecord.entities).primary_source_ip_address ?? incidentRecord.title, "Unknown site"),
    incidentWindow: formatIncidentWindow(incidentRecord.start_time, incidentRecord.end_time),
    timelineSubject: buildTimelineSubject(incidentRecord),
    plainLanguageWhatHappened: buildPlainLanguageWhatHappened(
      asString(incidentSummary.title ?? incidentRecord.title, "Suspicious access activity"),
      asString(incidentSummary.summary ?? incidentRecord.summary, "Incident summary unavailable."),
      topSignals.map((item) => displayLabel(item.label ?? item.feature, "Signal")),
      asString(asRecord(incidentRecord.entities).primary_source_ip_address ?? incidentRecord.title, "Unknown site"),
    ),
    summary: asString(incidentSummary.summary ?? incidentRecord.summary, "Incident summary unavailable."),
    confidence,
    recommendationMayBeIncomplete: asBoolean(coverageReviewRecord.recommendation_may_be_incomplete),
    incompletenessWarning: asOptionalString(completeness.warning),
    decisionRiskNote: asString(coverageReviewRecord.decision_risk_note, "Review available evidence before acting."),
    plainLanguageConcernSummary: buildPlainLanguageConcernSummary(topSignals.map((item) => asString(item.label ?? item.feature, "signal")), eventSequence),
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
      explanation: explainSignal(item.label ?? item.feature),
    })),
    modelType: asOptionalString(detectorRecord.model_type),
    modelContributions,
    timeline: eventSequence.slice(0, 6).map((item, index) => ({
      step: `${index + 1}`,
      title: humanizeTimelineEvent(asString(item, "Activity")),
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

function deriveConfidencePercent(
  detectorRecord: RecordShape,
  coverageReviewRecord: RecordShape,
  incidentSummary: RecordShape,
): number {
  const explanation = asRecord(detectorRecord.explanation_json);
  const modelConfidence = asNumber(explanation.confidence, Number.NaN);
  const fallbackRiskScore = asNumber(incidentSummary.risk_score, 0.72);
  const completeness = asRecord(coverageReviewRecord.completeness);
  const completenessLevel = asString(
    completeness.level ?? coverageReviewRecord.completeness_level,
    "medium",
  ).toLowerCase();

  let cap = 85;
  if (completenessLevel.includes("high")) cap = 92;
  else if (completenessLevel.includes("medium")) cap = 78;
  else if (completenessLevel.includes("low")) cap = 68;

  if (asBoolean(coverageReviewRecord.recommendation_may_be_incomplete) && cap > 78) {
    cap = 78;
  }

  const rawPercent = Number.isFinite(modelConfidence) ? Math.round(modelConfidence * 100) : Math.round(fallbackRiskScore * 100);
  return Math.max(55, Math.min(rawPercent, cap));
}

export function formatIncidentWindow(startTime: unknown, endTime: unknown): string | null {
  const start = formatTimestamp(startTime);
  const end = formatTimestamp(endTime);
  if (start && end) {
    return `${start} - ${end}`;
  }
  return start ?? end;
}

export function formatTimestamp(value: unknown): string | null {
  const raw = asOptionalString(value);
  if (!raw) return null;
  const date = new Date(raw);
  if (Number.isNaN(date.getTime())) return raw;
  return new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
    timeZoneName: "short",
  }).format(date);
}

function joinHumanList(items: string[]): string {
  const cleaned = items.map((item) => item.trim()).filter(Boolean);
  if (cleaned.length === 0) return "";
  if (cleaned.length === 1) return cleaned[0];
  if (cleaned.length === 2) return `${cleaned[0]} and ${cleaned[1]}`;
  return `${cleaned.slice(0, -1).join(", ")}, and ${cleaned[cleaned.length - 1]}`;
}

function toSentenceStart(value: string): string {
  if (!value) return value;
  return value[0].toUpperCase() + value.slice(1);
}

function lowercaseFirst(value: string): string {
  if (!value) return value;
  return value[0].toLowerCase() + value.slice(1);
}

function humanizeSourceList(value: string): string {
  return joinHumanList(value.split(",").map((item) => displayLabel(item.trim(), item.trim())));
}

function buildPlainLanguageWhatHappened(
  title: string,
  summary: string,
  signals: string[],
  site: string,
): string {
  const normalizedTitle = title.toLowerCase();
  if (normalizedTitle.includes("unusual login")) {
    return "Someone appears to have signed in and then performed suspicious account activity. The current review suggests possible credential misuse, but some evidence is still missing.";
  }
  if (normalizedTitle.includes("credential misuse")) {
    return "The activity looks like a strong case of account misuse. The pattern is consistent enough that the system is treating it as a high-confidence security incident.";
  }
  if (normalizedTitle.includes("resource launch")) {
    return "Someone created or changed resources after signing in, which can indicate risky hands-on activity. Some surrounding device context is unavailable, so the picture is not complete.";
  }

  const signalSummary = signals.length ? ` The main reasons are ${joinHumanList(signals.slice(0, 3).map((item) => item.toLowerCase()))}.` : "";
  const cleanedSummary = summary && summary !== "Incident summary unavailable." ? ` ${toSentenceStart(summary)}` : "";
  return `Sentinel found suspicious activity affecting ${site}.${signalSummary}${cleanedSummary}`;
}

function buildPlainLanguageConcernSummary(signals: string[], eventSequence: string[]): string {
  const normalizedSignals = new Set(
    signals
      .map((item) => item.trim().toLowerCase())
      .filter(Boolean),
  );
  const normalizedEvents = new Set(
    eventSequence
      .map((item) => item.trim().toLowerCase())
      .filter(Boolean),
  );

  const statements: string[] = [];

  if (normalizedSignals.has("console_login") || normalizedEvents.has("consolelogin")) {
    statements.push("Someone signed in interactively through the AWS console");
  }
  if (
    normalizedSignals.has("recon_activity") ||
    normalizedSignals.has("ec2_sequence") ||
    normalizedEvents.has("describeinstances") ||
    normalizedEvents.has("describenetworkinterfaces")
  ) {
    statements.push("the account then looked around existing cloud resources");
  }
  if (
    normalizedSignals.has("resource_creation") ||
    normalizedSignals.has("recon_plus_resource_creation") ||
    normalizedSignals.has("resource_creation_after_login") ||
    normalizedEvents.has("runinstances") ||
    normalizedEvents.has("createaccesskey") ||
    normalizedEvents.has("createuser")
  ) {
    statements.push("new resources or access changes followed soon after");
  }
  if (normalizedSignals.has("privilege_change") || normalizedSignals.has("recon_plus_privilege")) {
    statements.push("permissions or access appear to have changed during the same sequence");
  }
  if (normalizedSignals.has("active_network_beaconing") || normalizedSignals.has("ongoing_session_activity")) {
    statements.push("the activity may still be ongoing");
  }

  if (statements.length >= 3) {
    return `${toSentenceStart(statements[0])}, ${statements[1]}, and ${statements[2]}. This sequence is concerning because it looks like hands-on activity after access was gained.`;
  }
  if (statements.length === 2) {
    return `${toSentenceStart(statements[0])}, and ${statements[1]}. Together, that pattern is more concerning than any one event on its own.`;
  }
  if (statements.length === 1) {
    return `${toSentenceStart(statements[0])}. The system flagged it because this kind of activity often appears in suspicious hands-on sessions.`;
  }

  const humanSignals = signals.map((item) => displayLabel(item, item).toLowerCase()).slice(0, 3);
  if (humanSignals.length) {
    return `The system is concerned because it saw signs of ${joinHumanList(humanSignals)} in the same incident. That combination can indicate suspicious account activity.`;
  }

  return "The system is concerned because several actions in this incident, taken together, look less like routine work and more like suspicious hands-on activity.";
}

function buildTimelineSubject(incidentRecord: RecordShape): string {
  const primaryActor = asRecord(incidentRecord.primary_actor);
  const actorKey = asOptionalString(primaryActor.actor_key);
  if (actorKey) {
    return actorKey;
  }

  const entities = asRecord(incidentRecord.entities);
  const sourceIp = asOptionalString(entities.primary_source_ip_address);
  if (sourceIp) {
    return `the activity from ${sourceIp}`;
  }

  return "this incident";
}

function humanizeTimelineEvent(value: string): string {
  const normalized = value.trim().toLowerCase();
  const directMap: Record<string, string> = {
    consolelogin: "Signed in to the AWS console",
    describeinstances: "Looked up existing virtual machines",
    runinstances: "Launched a new virtual machine",
    getcalleridentity: "Checked which account or role was active",
    assumrole: "Switched into a temporary role",
    creteaccesskey: "Created a new access key",
    createaccesskey: "Created a new access key",
    attachuserpolicy: "Attached a new permission policy to a user",
    putuserpolicy: "Changed a user's permissions",
    putrolepolicy: "Changed a role's permissions",
    createuser: "Created a new user account",
    createpolicy: "Created a new permission policy",
    listbuckets: "Viewed the list of storage buckets",
    getbucketpolicy: "Viewed a storage bucket policy",
    describenetworkinterfaces: "Looked up network interface details",
    startinstances: "Started an existing virtual machine",
    stopinstances: "Stopped a virtual machine",
    terminateinstances: "Terminated a virtual machine",
    createinstanceprofile: "Created a new instance profile",
    addroletoinstanceprofile: "Attached a role to an instance profile",
  };

  if (directMap[normalized]) {
    return directMap[normalized];
  }

  const spaced = value.replace(/([a-z])([A-Z])/g, "$1 $2").replace(/[_-]+/g, " ").trim();
  return toSentenceStart(spaced);
}
