import type {
  AgentAuthResponse,
  AgentQueryResponse,
  CoverageReviewResponse,
  DecisionSupportResponse,
  IncidentContextResponse,
  IncidentReportResponse,
  IncidentListResponse,
  IncidentWorkspaceResponse,
  OperatorActionResponse,
  OperatorHistoryResponse,
  RecordShape,
} from "@/types/api";

function normalizeBaseUrl(value: string | undefined, fallback: string): string {
  return (value ?? fallback).trim().replace(/\s+/g, "").replace(/\/$/, "");
}

const API_BASE_URL = normalizeBaseUrl(process.env.NEXT_PUBLIC_API_BASE_URL, "/api/core");
const AGENT_BASE_URL = normalizeBaseUrl(process.env.NEXT_PUBLIC_AGENT_API_BASE_URL, "/api/agent");

function logApi(event: string, payload?: unknown): void {
  console.info(`[frontend/api] ${event}`, payload ?? "");
}

export class ApiError extends Error {
  status?: number;

  constructor(message: string, status?: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

async function fetchJson<T>(baseUrl: string, path: string, init?: RequestInit): Promise<T> {
  const url = `${baseUrl}${path}`;
  logApi("request", {
    url,
    method: init?.method ?? "GET",
    hasBody: Boolean(init?.body),
  });

  const response = await fetch(url, {
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
    cache: "no-store",
    ...init,
  });

  logApi("response", {
    url,
    method: init?.method ?? "GET",
    status: response.status,
    ok: response.ok,
    redirected: response.redirected,
  });

  if (!response.ok) {
    let detail = response.statusText;
    try {
      const payload = (await response.json()) as { detail?: string };
      detail = payload.detail ?? detail;
      logApi("response_error_payload", { url, payload });
    } catch {}
    console.error("[frontend/api] request_failed", { url, status: response.status, detail });
    throw new ApiError(detail || "Request failed", response.status);
  }

  const payload = (await response.json()) as T;
  logApi("response_payload", { url, payload });
  return payload;
}

export async function listIncidents(limit = 25): Promise<RecordShape[]> {
  const response = await fetchJson<IncidentListResponse>(API_BASE_URL, `/incidents/?limit=${limit}`);
  return response.incidents;
}

export async function loadOperatorHistory(incidentId: string): Promise<OperatorHistoryResponse> {
  return fetchJson<OperatorHistoryResponse>(API_BASE_URL, `/incidents/${incidentId}/operator-history`);
}

export async function loadIncidentWorkspace(incidentId: string): Promise<IncidentWorkspaceResponse> {
  const incidentContext = await fetchJson<IncidentContextResponse>(API_BASE_URL, `/incidents/${incidentId}`);

  const [decisionSupportResult, coverageReviewResult, operatorHistoryResult] = await Promise.allSettled([
    fetchJson<DecisionSupportResponse>(API_BASE_URL, `/incidents/${incidentId}/decision-support`),
    fetchJson<CoverageReviewResponse>(API_BASE_URL, `/incidents/${incidentId}/coverage-review`),
    loadOperatorHistory(incidentId),
  ]);

  return {
    incident: incidentContext.incident,
    incidentEvents: incidentContext.incident_events ?? [],
    evidencePackage: incidentContext.evidence_package ?? null,
    detectorResult: incidentContext.detector_result ?? null,
    coverageAssessment: incidentContext.coverage_assessment ?? null,
    decisionSupportResult: incidentContext.decision_support_result ?? null,
    decisionSupport: decisionSupportResult.status === "fulfilled" ? decisionSupportResult.value.result : null,
    coverageReview: coverageReviewResult.status === "fulfilled" ? coverageReviewResult.value.review : null,
    operatorHistory: operatorHistoryResult.status === "fulfilled" ? operatorHistoryResult.value : null,
  };
}

export async function postApprove(
  incidentId: string,
  payload: { rationale?: string; used_double_check?: boolean; actor?: RecordShape; policy_version?: string },
): Promise<RecordShape> {
  const response = await fetchJson<OperatorActionResponse>(API_BASE_URL, `/incidents/${incidentId}/approve`, {
    method: "POST",
    body: JSON.stringify(payload),
  });
  return response.result;
}

export async function getLatestReport(incidentId: string): Promise<RecordShape | null> {
  const response = await fetchJson<IncidentReportResponse>(API_BASE_URL, `/incidents/${incidentId}/report/latest`);
  return response.report ?? null;
}

export function buildReportPrintUrl(incidentId: string): string {
  return `${API_BASE_URL}/incidents/${incidentId}/report/latest/print`;
}

export async function downloadReportPdf(incidentId: string): Promise<void> {
  const url = `${API_BASE_URL}/incidents/${incidentId}/report/latest/pdf`;
  logApi("download_pdf_start", { url });
  const response = await fetch(url, {
    headers: { Accept: "application/pdf" },
    cache: "no-store",
  });
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const payload = (await response.json()) as { detail?: string };
      detail = payload.detail ?? detail;
    } catch {}
    throw new ApiError(detail || "Could not download PDF.", response.status);
  }
  const blob = await response.blob();
  const objectUrl = window.URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = objectUrl;
  anchor.download = `sentinel-report-${incidentId}.pdf`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.URL.revokeObjectURL(objectUrl);
  logApi("download_pdf_success", { url });
}

export async function postAlternative(
  incidentId: string,
  payload: { action_id: string; rationale?: string; used_double_check?: boolean; actor?: RecordShape; policy_version?: string },
): Promise<RecordShape> {
  const response = await fetchJson<OperatorActionResponse>(API_BASE_URL, `/incidents/${incidentId}/alternative`, {
    method: "POST",
    body: JSON.stringify(payload),
  });
  return response.result;
}

export async function postEscalate(
  incidentId: string,
  payload: { rationale?: string; used_double_check?: boolean; actor?: RecordShape; policy_version?: string },
): Promise<RecordShape> {
  const response = await fetchJson<OperatorActionResponse>(API_BASE_URL, `/incidents/${incidentId}/escalate`, {
    method: "POST",
    body: JSON.stringify(payload),
  });
  return response.result;
}

export async function postDoubleCheck(
  incidentId: string,
  payload: { rationale?: string; used_double_check?: boolean; actor?: RecordShape; policy_version?: string },
): Promise<RecordShape> {
  const response = await fetchJson<OperatorActionResponse>(API_BASE_URL, `/incidents/${incidentId}/double-check`, {
    method: "POST",
    body: JSON.stringify(payload),
  });
  return response.result;
}

export async function getAgentAuth(incidentId: string): Promise<RecordShape> {
  const response = await fetchJson<AgentAuthResponse>(AGENT_BASE_URL, `/incidents/${incidentId}/agent-auth`);
  return response.result;
}

export async function postAgentQuery(
  incidentId: string,
  payload: { user_query: string; policy_version?: string },
): Promise<RecordShape> {
  const response = await fetchJson<AgentQueryResponse>(AGENT_BASE_URL, `/incidents/${incidentId}/agent-query`, {
    method: "POST",
    body: JSON.stringify(payload),
  });
  return response.result;
}
