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
  PolicyRecord,
  PortalSession,
  Publisher,
  RegisterRequest,
  ReportThreatRequest,
  ReportThreatResponse,
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
  InvestigationDepth,
  InvestigationResult,
  FalsePositiveAnalysis,
  RemediationResult,
  CreditInfo,
  ChatSession,
  ChatMessage,
} from "./types";

const API_URL = process.env.NEXT_PUBLIC_API_URL;

function getApiUrl(): string {
  if (!API_URL) {
    throw new Error("NEXT_PUBLIC_API_URL is not configured");
  }
  return API_URL;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function getToken(): Promise<string | null> {
  if (typeof window === "undefined") return null;

  // Only Auth0 tokens now
  try {
    const res = await fetch("/api/auth/token", {
      credentials: 'include',
      cache: 'no-store',
    });
    if (res.ok) {
      const { accessToken, token } = await res.json();
      return accessToken || token || null;
    }
  } catch {
    // Not authenticated
  }

  return null;
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
  const token = await getToken();

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options.headers as Record<string, string>),
  };

  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const res = await fetch(`${getApiUrl()}${path}`, {
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

// DEPRECATED: Auth0 handles registration now via Universal Login
// export async function register(payload: RegisterRequest): Promise<AuthTokens> {
//   return request<AuthTokens>("/auth/register", {
//     method: "POST",
//     body: JSON.stringify(payload),
//   });
// }

// DEPRECATED: Auth0 handles login now via Universal Login
// export async function login(payload: LoginRequest): Promise<AuthTokens> {
//   return request<AuthTokens>("/auth/login", {
//     method: "POST",
//     body: JSON.stringify(payload),
//   });
// }

// DEPRECATED: Auth0 handles token refresh
// export async function refreshToken(refresh: string): Promise<AuthTokens> {
//   return request<AuthTokens>("/auth/refresh", {
//     method: "POST",
//     body: JSON.stringify({ refresh_token: refresh }),
//   });
// }

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
  scope?: "own" | "public" | "community" | "all";
}): Promise<PaginatedResponse<Scan>> {
  const query = new URLSearchParams();
  if (params?.page) query.set("page", String(params.page));
  if (params?.per_page) query.set("per_page", String(params.per_page));
  if (params?.verdict) query.set("verdict", params.verdict);
  if (params?.source) query.set("source", params.source);
  if (params?.search) query.set("search", params.search);
  if (params?.scope) query.set("scope", params.scope);
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

export async function submitReport(payload: ReportThreatRequest): Promise<ReportThreatResponse> {
  const evidence = [
    `Threat type: ${payload.threat_type}`,
    `Severity: ${payload.severity}`,
    ...payload.indicators.map((indicator) => `Indicator: ${indicator}`),
    ...payload.references.map((reference) => `Reference: ${reference}`),
  ].join("\n");

  return request<ReportThreatResponse>("/report", {
    method: "POST",
    body: JSON.stringify({
      package_name: payload.package_name,
      ecosystem: payload.source,
      reason: payload.description,
      evidence,
    }),
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
  const res = await request<{ signatures: Signature[] } | Signature[]>("/signatures");
  // API returns { signatures: [...], total, last_updated } or bare array
  if (Array.isArray(res)) return res;
  return (res as { signatures: Signature[] }).signatures ?? [];
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
  const records = await request<PolicyRecord[]>("/settings/policy");
  const byType = new Map(records.map((record) => [record.type, record]));

  return {
    auto_approve_threshold:
      (byType.get("auto_approve_threshold")?.config.verdict as Verdict | undefined) ??
      "LOW_RISK",
    allowlisted_packages:
      (byType.get("allowlist")?.config.packages as string[] | undefined) ?? [],
    blocklisted_packages:
      (byType.get("blocklist")?.config.packages as string[] | undefined) ?? [],
    require_approval_for:
      (byType.get("required_phases")?.config.verdicts as Verdict[] | undefined) ?? [],
  };
}

/** @deprecated Use listPolicies instead */
export const getPolicy = listPolicies;

export async function createPolicy(policy: Partial<Policy>): Promise<Policy> {
  return updatePolicy(policy);
}

export async function updatePolicy(policy: Partial<Policy>): Promise<Policy> {
  const existing = await request<PolicyRecord[]>("/settings/policy");
  const byType = new Map(existing.map((record) => [record.type, record]));

  const desired: Array<{
    type: PolicyRecord["type"];
    name: string;
    config: Record<string, unknown>;
    enabled: boolean;
  }> = [
    {
      type: "auto_approve_threshold",
      name: "Auto-Approve Threshold",
      config: { verdict: policy.auto_approve_threshold ?? "LOW_RISK" },
      enabled: true,
    },
    {
      type: "allowlist",
      name: "Allowlisted Packages",
      config: { packages: policy.allowlisted_packages ?? [] },
      enabled: true,
    },
    {
      type: "blocklist",
      name: "Blocklisted Packages",
      config: { packages: policy.blocklisted_packages ?? [] },
      enabled: true,
    },
    {
      type: "required_phases",
      name: "Require Manual Approval",
      config: { verdicts: policy.require_approval_for ?? [] },
      enabled: true,
    },
  ];

  await Promise.all(
    desired.map((record) => {
      const current = byType.get(record.type);
      const body = JSON.stringify(record);
      if (current) {
        return request<PolicyRecord>(`/settings/policy/${current.id}`, {
          method: "PATCH",
          body,
        });
      }
      return request<PolicyRecord>("/settings/policy", {
        method: "POST",
        body,
      });
    }),
  );

  return listPolicies();
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
  const channel = await request<AlertChannel[]>(`/settings/alerts`).then((channels) =>
    channels.find((item) => item.id === id),
  );
  if (!channel) {
    throw new Error("Alert channel not found");
  }
  await request<void>("/settings/alerts/test", {
    method: "POST",
    body: JSON.stringify({
      channel_type: channel.channel_type,
      channel_config: channel.channel_config,
    }),
  });
}

// ---------------------------------------------------------------------------
// Billing
// ---------------------------------------------------------------------------

export async function getPlans(): Promise<BillingPlan[]> {
  return request<BillingPlan[]>("/billing/plans");
}

export async function subscribe(planTier: string, interval: "monthly" | "annual" = "monthly"): Promise<Subscription> {
  return request<Subscription>("/billing/subscribe", {
    method: "POST",
    body: JSON.stringify({ plan: planTier, interval }),
  });
}

export async function getSubscription(): Promise<Subscription> {
  return request<Subscription>("/billing/subscription");
}

export async function createPortalSession(): Promise<PortalSession> {
  return request<PortalSession>("/billing/portal", { method: "POST" });
}

export type CreditUsage = {
  current_balance: number;
  monthly_allocation: number;
  used_this_month: number;
  reset_date?: string | null;
  days_until_reset: number;
  transactions: Array<{
    id: string;
    amount: number;
    feature: string;
    timestamp: string;
    description: string;
  }>;
};

export type CreditPurchaseSession = {
  success: boolean;
  checkout_url?: string | null;
  credits_purchased?: number | null;
  new_balance?: number | null;
};

function daysUntil(resetDate?: string | null): number {
  if (!resetDate) return 0;

  const timestamp = Date.parse(resetDate);
  if (Number.isNaN(timestamp)) return 0;

  const dayMs = 24 * 60 * 60 * 1000;
  return Math.max(0, Math.ceil((timestamp - Date.now()) / dayMs));
}

export async function getCreditUsage(): Promise<CreditUsage> {
  const usage = await request<{
    current_balance: number;
    monthly_allocation: number;
    used_this_month: number;
    reset_date?: string | null;
  }>("/v1/interactive/credits");

  return {
    ...usage,
    days_until_reset: daysUntil(usage.reset_date),
    transactions: [],
  };
}

const INTERACTIVE_CREDIT_COSTS: CreditInfo["costs"] = {
  quick_investigation: 4,
  thorough_investigation: 8,
  exhaustive_investigation: 16,
  false_positive_check: 4,
  remediation: 6,
  chat_message: 2,
};

export async function getInteractiveCreditInfo(): Promise<CreditInfo> {
  const usage = await request<{
    current_balance: number;
    monthly_allocation: number;
    used_this_month: number;
  }>("/v1/interactive/credits");

  return {
    balance: usage.current_balance,
    monthly_limit: usage.monthly_allocation,
    used_this_month: usage.used_this_month,
    costs: INTERACTIVE_CREDIT_COSTS,
  };
}

export async function investigateFinding(payload: {
  scanId: string;
  findingId: string;
  depth: InvestigationDepth;
}): Promise<InvestigationResult> {
  return request<InvestigationResult>("/v1/interactive/investigate", {
    method: "POST",
    body: JSON.stringify({
      scan_id: payload.scanId,
      finding_id: payload.findingId,
      depth: payload.depth,
    }),
  });
}

export async function analyzeFalsePositive(payload: {
  scanId: string;
  findingId: string;
}): Promise<FalsePositiveAnalysis> {
  return request<FalsePositiveAnalysis>("/v1/interactive/false-positive", {
    method: "POST",
    body: JSON.stringify({
      scan_id: payload.scanId,
      finding_id: payload.findingId,
    }),
  });
}

export async function generateRemediation(payload: {
  scanId: string;
  findingId: string;
}): Promise<RemediationResult> {
  return request<RemediationResult>("/v1/interactive/remediate", {
    method: "POST",
    body: JSON.stringify({
      scan_id: payload.scanId,
      finding_id: payload.findingId,
    }),
  });
}

type InteractiveSessionResponse = {
  session_id: string;
  scan_id: string;
  status: string;
  started_at?: string;
  last_activity?: string;
  conversation_history?: ChatMessage[];
};

function toChatSession(session: InteractiveSessionResponse): ChatSession {
  const createdAt = session.started_at ?? new Date().toISOString();
  return {
    id: session.session_id,
    scan_id: session.scan_id,
    messages: session.conversation_history ?? [],
    created_at: createdAt,
    updated_at: session.last_activity ?? createdAt,
  };
}

export async function createInteractiveSession(scanId: string): Promise<ChatSession> {
  const session = await request<InteractiveSessionResponse>("/v1/interactive/sessions", {
    method: "POST",
    body: JSON.stringify({ scan_id: scanId }),
  });
  return toChatSession(session);
}

export async function continueInteractiveSession(sessionId: string): Promise<ChatSession> {
  const session = await request<InteractiveSessionResponse>(
    `/v1/interactive/sessions/${sessionId}/continue`,
    { method: "POST" },
  );
  return toChatSession(session);
}

export async function getSharedInteractiveSession<T>(token: string): Promise<T> {
  return request<T>(`/v1/interactive/sessions/shared/${token}`);
}

export async function exportInteractiveSession(payload: {
  session_id?: string;
  share_token?: string;
}): Promise<string> {
  return request<string>("/v1/interactive/sessions/export", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function getUserUsageStats<T>(days: string): Promise<T> {
  const query = new URLSearchParams({ days });
  return request<T>(`/v1/analytics/my/usage?${query.toString()}`);
}

export async function getUserChurnRisk<T>(): Promise<T> {
  return request<T>("/v1/analytics/my/churn-risk");
}

export async function purchaseCredits(
  packageId: number,
): Promise<CreditPurchaseSession> {
  return request<CreditPurchaseSession>("/v1/billing/purchase-credits", {
    method: "POST",
    body: JSON.stringify({ package_id: packageId }),
  });
}
