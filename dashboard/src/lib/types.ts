// ---------------------------------------------------------------------------
// Sigil Dashboard — Shared TypeScript types
// These mirror the models exposed by the FastAPI backend.
// ---------------------------------------------------------------------------

/** Verdict levels returned by the scan engine. */
export type Verdict = "CLEAN" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

/** Scan phases as defined by the Sigil scanner. */
export type ScanPhase =
  | "install_hooks"
  | "code_patterns"
  | "network_exfil"
  | "credentials"
  | "obfuscation"
  | "provenance";

/** Source from which a package was scanned. */
export type ScanSource = "pip" | "npm" | "git" | "local";

/** An individual finding produced during a scan phase. */
export interface Finding {
  id: string;
  scan_id: string;
  phase: ScanPhase;
  severity: Verdict;
  title: string;
  description: string;
  file_path: string;
  line_number: number | null;
  pattern_matched: string;
  weight: number;
}

/** A completed (or in-progress) scan record. */
export interface Scan {
  id: string;
  package_name: string;
  package_version: string;
  source: ScanSource;
  verdict: Verdict;
  score: number;
  findings_count: number;
  findings: Finding[];
  quarantine_path: string | null;
  status: "pending" | "scanning" | "completed" | "failed";
  created_at: string;
  completed_at: string | null;
  approved_by: string | null;
  approved_at: string | null;
}

/** Known-malicious package entry from the threat intelligence feed. */
export interface ThreatEntry {
  id: string;
  package_name: string;
  source: ScanSource;
  threat_type: string;
  description: string;
  reporter: string;
  reported_at: string;
  severity: Verdict;
  indicators: string[];
  references: string[];
}

/** Publisher / maintainer metadata for a package. */
export interface Publisher {
  name: string;
  email: string;
  url: string | null;
  verified: boolean;
  first_seen: string;
  package_count: number;
}

/** Signature entry for pattern matching rules. */
export interface Signature {
  id: string;
  name: string;
  pattern: string;
  phase: ScanPhase;
  severity: Verdict;
  description: string;
  enabled: boolean;
  created_at: string;
}

/** User roles within a Sigil team. */
export type UserRole = "owner" | "admin" | "member" | "viewer";

/** A user account in the Sigil dashboard. */
export interface User {
  id: string;
  email: string;
  name: string;
  avatar_url: string | null;
  role: UserRole;
  created_at: string;
  last_login: string | null;
}

/** A team (organisation) in the Sigil dashboard. */
export interface Team {
  id: string;
  name: string;
  slug: string;
  members: User[];
  created_at: string;
  scan_count: number;
  threat_count: number;
}

/** Team invitation record. */
export interface TeamInvite {
  id: string;
  email: string;
  role: UserRole;
  invited_by: string;
  created_at: string;
  expires_at: string;
  accepted: boolean;
}

/** Policy type for automated scan decisions. */
export type PolicyType = "auto_approve" | "require_approval" | "auto_reject";

/** Policy configuration for automated decisions. */
export interface Policy {
  id?: string;
  auto_approve_threshold: Verdict;
  allowlisted_packages: string[];
  blocklisted_packages: string[];
  require_approval_for: Verdict[];
}

/** Alert channel types. */
export type AlertChannelType = "slack" | "email" | "webhook";

/** Alert channel configuration. */
export interface AlertChannel {
  id: string;
  type: AlertChannelType;
  target: string;
  enabled: boolean;
  min_severity: Verdict;
}

/** Alert configuration for creating/updating. */
export interface AlertConfig {
  type: AlertChannelType;
  target: string;
  enabled: boolean;
  min_severity: Verdict;
}

/** Billing plan definition. */
export interface BillingPlan {
  id: string;
  name: string;
  description: string;
  price_monthly: number;
  price_yearly: number;
  scan_limit: number;
  team_member_limit: number;
  features: string[];
  is_current?: boolean;
}

/** Active subscription record. */
export interface Subscription {
  id: string;
  plan_id: string;
  plan_name: string;
  status: "active" | "canceled" | "past_due" | "trialing";
  current_period_start: string;
  current_period_end: string;
  cancel_at_period_end: boolean;
  scan_usage: number;
  scan_limit: number;
}

/** Dashboard overview statistics. */
export interface DashboardStats {
  total_scans: number;
  threats_blocked: number;
  packages_approved: number;
  critical_findings: number;
  scans_today: number;
  trend_scans: number;
  trend_threats: number;
}

/** Generic paginated API response. */
export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  per_page: number;
  has_more: boolean;
}

/** Auth tokens returned after login / refresh. */
export interface AuthTokens {
  access_token: string;
  refresh_token: string;
  expires_at: number;
}

/** Login request payload. */
export interface LoginRequest {
  email: string;
  password: string;
}

/** Registration request payload. */
export interface RegisterRequest {
  email: string;
  password: string;
  name: string;
}

/** Submit scan request payload. */
export interface SubmitScanRequest {
  package_name: string;
  package_version?: string;
  source: ScanSource;
  target_url?: string;
  target_path?: string;
}

/** Report threat request payload. */
export interface ReportThreatRequest {
  package_name: string;
  source: ScanSource;
  threat_type: string;
  description: string;
  severity: Verdict;
  indicators: string[];
  references: string[];
}

/** Package verification response. */
export interface VerifyPackageResponse {
  package_name: string;
  source: ScanSource;
  is_known_threat: boolean;
  threat_entries: ThreatEntry[];
  publisher: Publisher | null;
  last_scan: Scan | null;
}

/** Billing portal session. */
export interface PortalSession {
  url: string;
}

/** API error response. */
export interface ApiError {
  detail: string;
  status: number;
}
