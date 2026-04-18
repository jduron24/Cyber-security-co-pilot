export type RecordShape = Record<string, unknown>;

export interface IncidentListResponse {
  incidents: RecordShape[];
}

export interface IncidentContextResponse {
  incident: RecordShape;
  incident_events?: RecordShape[];
  evidence_package?: RecordShape | null;
  detector_result?: RecordShape | null;
  coverage_assessment?: RecordShape | null;
  decision_support_result?: RecordShape | null;
}

export interface DecisionSupportResponse {
  result: RecordShape;
}

export interface CoverageReviewResponse {
  review: RecordShape;
}

export interface OperatorActionResponse {
  result: RecordShape;
}

export interface OperatorHistoryResponse {
  latest_decision: RecordShape | null;
  recent_decisions: RecordShape[];
  review_events: RecordShape[];
}

export interface AgentAuthResponse {
  result: RecordShape;
}

export interface AgentQueryResponse {
  result: RecordShape;
}

export interface IncidentWorkspaceResponse {
  incident: RecordShape;
  incidentEvents: RecordShape[];
  evidencePackage: RecordShape | null;
  detectorResult: RecordShape | null;
  coverageAssessment: RecordShape | null;
  decisionSupportResult: RecordShape | null;
  decisionSupport: RecordShape | null;
  coverageReview: RecordShape | null;
  operatorHistory: OperatorHistoryResponse | null;
}
