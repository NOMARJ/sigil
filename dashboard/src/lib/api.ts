// ---------------------------------------------------------------------------
// Sigil Dashboard — API client
// Typed fetch wrappers for the FastAPI backend.
// ---------------------------------------------------------------------------

import type {
  AlertChannel,
  AlertConfig,
  AuthTokens,
  BillingPlan,
  DashboardStats,
  Finding,
  LoginRequest,
  PaginatedResponse,
  Policy,
  PortalSession,
  Publisher,
  RegisterRequest,
  ReportThreatRequest,
  Scan,
  Signature,
  SubmitScanRequest,
  Subscription,
  ThreatEntry,
  ThreatReport,
  User,
  Team,
  Verdict,
  VerifyPackageResponse,
  ScanSource,
} from "./types";

const API_URL =
  typeof window !== "undefined"
    ? process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000"
    : process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem("sigil_access_token");
}

/** Parse an API error response into a human-readable message. */
function parseErrorMessage(status: number, body: string): string {
  try {
    const parsed = JSON.parse(body);
    if (parsed.detail) {
      if (typeof parsed.detail === "string") return parsed.detail;
      if (Array.isArray(parsed.detail)) {
        return parsed.detail.map((d: { msg?: string }) => d.msg ?? String(d)).join(", ");
      }
    }
  } catch {
    // body is not JSON
  }

  switch (status) {
    case 401:
      return "Authentication required. Please sign in again.";
    case 403:
      return "You do not have permission to perform this action.";
    case 404:
      return "The requested resource was not found.";
    case 422:
      return "Invalid request data. Please check your input.";
    case 429:
      return "Too many requests. Please wait a moment and try again.";
    case 500:
      return "An internal server error occurred. Please try again later.";
    default:
      return `Request failed (${status}): ${body}`;
  }
}

async function request<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const token = getToken();

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options.headers as Record<string, string>),
  };

  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const res = await fetch(`${API_URL}${path}`, {
    ...options,
    headers,
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(parseErrorMessage(res.status, body));
  }

  // Handle 204 No Content
  if (res.status === 204) {
    return undefined as T;
  }

  return res.json() as Promise<T>;
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

export async function login(payload: LoginRequest): Promise<AuthTokens> {
  return request<AuthTokens>("/auth/login", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function register(payload: RegisterRequest): Promise<AuthTokens> {
  return request<AuthTokens>("/auth/register", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function refreshToken(refresh: string): Promise<AuthTokens> {
  return request<AuthTokens>("/auth/refresh", {
    method: "POST",
    body: JSON.stringify({ refresh_token: refresh }),
  });
}

export async function getCurrentUser(): Promise<User> {
  return request<User>("/auth/me");
}

export async function logout(): Promise<void> {
  try {
    await request<void>("/auth/logout", { method: "POST" });
  } catch {
    // Even if the server-side logout fails, we still clear local tokens
  }
}

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

export async function getDashboardStats(): Promise<DashboardStats> {
  return request<DashboardStats>("/dashboard/stats");
}

// ---------------------------------------------------------------------------
// Scans
// ---------------------------------------------------------------------------

export async function listScans(params?: {
  page?: number;
  per_page?: number;
  verdict?: Verdict;
  source?: string;
  search?: string;
}): Promise<PaginatedResponse<Scan>> {
  const query = new URLSearchParams();
  if (params?.page) query.set("page", String(params.page));
  if (params?.per_page) query.set("per_page", String(params.per_page));
  if (params?.verdict) query.set("verdict", params.verdict);
  if (params?.source) query.set("source", params.source);
  if (params?.search) query.set("search", params.search);
  const qs = query.toString();
  return request<PaginatedResponse<Scan>>(`/scans${qs ? `?${qs}` : ""}`);
}

/** @deprecated Use listScans instead */
export const getScans = listScans;

export async function getScan(id: string): Promise<Scan> {
  return request<Scan>(`/scans/${id}`);
}

/** @deprecated Use getScan instead */
export const getScanById = getScan;

export async function getScanFindings(id: string): Promise<Finding[]> {
  return request<Finding[]>(`/scans/${id}/findings`);
}

export async function submitScan(payload: SubmitScanRequest): Promise<Scan> {
  return request<Scan>("/scans", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function approveScan(id: string): Promise<Scan> {
  return request<Scan>(`/scans/${id}/approve`, { method: "POST" });
}

export async function rejectScan(id: string): Promise<Scan> {
  return request<Scan>(`/scans/${id}/reject`, { method: "POST" });
}

// ---------------------------------------------------------------------------
// Threats
// ---------------------------------------------------------------------------

export async function searchThreats(params?: {
  page?: number;
  per_page?: number;
  severity?: Verdict;
  search?: string;
  source?: ScanSource;
}): Promise<PaginatedResponse<ThreatEntry>> {
  const query = new URLSearchParams();
  if (params?.page) query.set("page", String(params.page));
  if (params?.per_page) query.set("per_page", String(params.per_page));
  if (params?.severity) query.set("severity", params.severity);
  if (params?.search) query.set("search", params.search);
  if (params?.source) query.set("source", params.source);
  const qs = query.toString();
  return request<PaginatedResponse<ThreatEntry>>(
    `/threats${qs ? `?${qs}` : ""}`,
  );
}

/** @deprecated Use searchThreats instead */
export const getThreats = searchThreats;

export async function getThreat(id: string): Promise<ThreatEntry> {
  return request<ThreatEntry>(`/threats/${id}`);
}

/** @deprecated Use getThreat instead */
export const getThreatById = getThreat;

export async function submitReport(payload: ReportThreatRequest): Promise<ThreatEntry> {
  return request<ThreatEntry>("/threats/report", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

// ---------------------------------------------------------------------------
// Publishers
// ---------------------------------------------------------------------------

export async function getPublisher(name: string, source: ScanSource): Promise<Publisher> {
  const query = new URLSearchParams({ name, source });
  return request<Publisher>(`/publishers?${query.toString()}`);
}

// ---------------------------------------------------------------------------
// Signatures
// ---------------------------------------------------------------------------

export async function getSignatures(): Promise<Signature[]> {
  return request<Signature[]>("/signatures");
}

// ---------------------------------------------------------------------------
// Threat Reports (review workflow)
// ---------------------------------------------------------------------------

export async function listThreatReports(params?: {
  status?: string;
  page?: number;
  per_page?: number;
}): Promise<PaginatedResponse<ThreatReport>> {
  const query = new URLSearchParams();
  if (params?.status && params.status !== "all") query.set("status", params.status);
  if (params?.page) query.set("page", String(params.page));
  if (params?.per_page) query.set("per_page", String(params.per_page));
  const qs = query.toString();
  return request<PaginatedResponse<ThreatReport>>(
    `/threat-reports${qs ? `?${qs}` : ""}`,
  );
}

export async function getThreatReport(id: string): Promise<ThreatReport> {
  return request<ThreatReport>(`/threat-reports/${id}`);
}

export async function updateThreatReportStatus(
  id: string,
  status: string,
  notes?: string,
): Promise<ThreatReport> {
  return request<ThreatReport>(`/threat-reports/${id}`, {
    method: "PATCH",
    body: JSON.stringify({ status, notes: notes ?? "" }),
  });
}

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------

export async function verifyPackage(
  packageName: string,
  source: ScanSource,
): Promise<VerifyPackageResponse> {
  const query = new URLSearchParams({ package_name: packageName, source });
  return request<VerifyPackageResponse>(`/verify?${query.toString()}`);
}

// ---------------------------------------------------------------------------
// Team
// ---------------------------------------------------------------------------

export async function getTeam(): Promise<Team> {
  return request<Team>("/team");
}

export async function inviteMember(email: string, role: string): Promise<User> {
  return request<User>("/team/invite", {
    method: "POST",
    body: JSON.stringify({ email, role }),
  });
}

export async function removeMember(userId: string): Promise<void> {
  await request<void>(`/team/members/${userId}`, { method: "DELETE" });
}

export async function updateMemberRole(
  userId: string,
  role: string,
): Promise<User> {
  return request<User>(`/team/members/${userId}/role`, {
    method: "PATCH",
    body: JSON.stringify({ role }),
  });
}

// ---------------------------------------------------------------------------
// Settings / Policies
// ---------------------------------------------------------------------------

export async function listPolicies(): Promise<Policy> {
  return request<Policy>("/settings/policy");
}

/** @deprecated Use listPolicies instead */
export const getPolicy = listPolicies;

export async function createPolicy(policy: Partial<Policy>): Promise<Policy> {
  return request<Policy>("/settings/policy", {
    method: "POST",
    body: JSON.stringify(policy),
  });
}

export async function updatePolicy(policy: Partial<Policy>): Promise<Policy> {
  return request<Policy>("/settings/policy", {
    method: "PATCH",
    body: JSON.stringify(policy),
  });
}

export async function deletePolicy(id: string): Promise<void> {
  await request<void>(`/settings/policy/${id}`, { method: "DELETE" });
}

// ---------------------------------------------------------------------------
// Settings / Alert Channels
// ---------------------------------------------------------------------------

export async function listAlerts(): Promise<AlertChannel[]> {
  return request<AlertChannel[]>("/settings/alerts");
}

/** @deprecated Use listAlerts instead */
export const getAlertChannels = listAlerts;

export async function createAlert(
  channel: AlertConfig,
): Promise<AlertChannel> {
  return request<AlertChannel>("/settings/alerts", {
    method: "POST",
    body: JSON.stringify(channel),
  });
}

/** @deprecated Use createAlert instead */
export const createAlertChannel = createAlert;

export async function updateAlert(
  id: string,
  updates: Partial<AlertConfig>,
): Promise<AlertChannel> {
  return request<AlertChannel>(`/settings/alerts/${id}`, {
    method: "PATCH",
    body: JSON.stringify(updates),
  });
}

export async function deleteAlert(id: string): Promise<void> {
  await request<void>(`/settings/alerts/${id}`, { method: "DELETE" });
}

/** @deprecated Use deleteAlert instead */
export const deleteAlertChannel = deleteAlert;

export async function testAlert(id: string): Promise<void> {
  await request<void>(`/settings/alerts/${id}/test`, { method: "POST" });
}

// ---------------------------------------------------------------------------
// Billing
// ---------------------------------------------------------------------------

export async function getPlans(): Promise<BillingPlan[]> {
  return request<BillingPlan[]>("/billing/plans");
}

export async function subscribe(planId: string): Promise<Subscription> {
  return request<Subscription>("/billing/subscribe", {
    method: "POST",
    body: JSON.stringify({ plan_id: planId }),
  });
}

export async function getSubscription(): Promise<Subscription> {
  return request<Subscription>("/billing/subscription");
}

export async function createPortalSession(): Promise<PortalSession> {
  return request<PortalSession>("/billing/portal", { method: "POST" });
}
