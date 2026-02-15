// ---------------------------------------------------------------------------
// Sigil Dashboard — API client
// Typed fetch wrappers for the FastAPI backend.
// ---------------------------------------------------------------------------

import type {
  AuthTokens,
  DashboardStats,
  Finding,
  LoginRequest,
  PaginatedResponse,
  Policy,
  AlertChannel,
  RegisterRequest,
  Scan,
  ThreatEntry,
  User,
  Team,
  Verdict,
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
    throw new Error(`API ${res.status}: ${body}`);
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

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

export async function getDashboardStats(): Promise<DashboardStats> {
  return request<DashboardStats>("/dashboard/stats");
}

// ---------------------------------------------------------------------------
// Scans
// ---------------------------------------------------------------------------

export async function getScans(params?: {
  page?: number;
  per_page?: number;
  verdict?: Verdict;
  source?: string;
}): Promise<PaginatedResponse<Scan>> {
  const query = new URLSearchParams();
  if (params?.page) query.set("page", String(params.page));
  if (params?.per_page) query.set("per_page", String(params.per_page));
  if (params?.verdict) query.set("verdict", params.verdict);
  if (params?.source) query.set("source", params.source);
  const qs = query.toString();
  return request<PaginatedResponse<Scan>>(`/scans${qs ? `?${qs}` : ""}`);
}

export async function getScanById(id: string): Promise<Scan> {
  return request<Scan>(`/scans/${id}`);
}

export async function getScanFindings(id: string): Promise<Finding[]> {
  return request<Finding[]>(`/scans/${id}/findings`);
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

export async function getThreats(params?: {
  page?: number;
  per_page?: number;
  severity?: Verdict;
}): Promise<PaginatedResponse<ThreatEntry>> {
  const query = new URLSearchParams();
  if (params?.page) query.set("page", String(params.page));
  if (params?.per_page) query.set("per_page", String(params.per_page));
  if (params?.severity) query.set("severity", params.severity);
  const qs = query.toString();
  return request<PaginatedResponse<ThreatEntry>>(
    `/threats${qs ? `?${qs}` : ""}`,
  );
}

export async function getThreatById(id: string): Promise<ThreatEntry> {
  return request<ThreatEntry>(`/threats/${id}`);
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

export async function getPolicy(): Promise<Policy> {
  return request<Policy>("/settings/policy");
}

export async function updatePolicy(policy: Partial<Policy>): Promise<Policy> {
  return request<Policy>("/settings/policy", {
    method: "PATCH",
    body: JSON.stringify(policy),
  });
}

export async function getAlertChannels(): Promise<AlertChannel[]> {
  return request<AlertChannel[]>("/settings/alerts");
}

export async function createAlertChannel(
  channel: Omit<AlertChannel, "id">,
): Promise<AlertChannel> {
  return request<AlertChannel>("/settings/alerts", {
    method: "POST",
    body: JSON.stringify(channel),
  });
}

export async function deleteAlertChannel(id: string): Promise<void> {
  await request<void>(`/settings/alerts/${id}`, { method: "DELETE" });
}
