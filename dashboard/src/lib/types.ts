// ---------------------------------------------------------------------------
// Sigil Dashboard — Shared TypeScript types
// These mirror the models exposed by the FastAPI backend.
// ---------------------------------------------------------------------------

/** Risk classification levels returned by the scan engine. */
export type Verdict =
  | "LOW_RISK"
  | "MEDIUM_RISK"
  | "HIGH_RISK"
  | "CRITICAL_RISK";

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

/** An individual finding produced during during a scan phase. */
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
  confidence?: "HIGH" | "MEDIUM" | "LOW";
}

/** A completed (or in-progress) scan record.
 *  Aligned with API ScanListItem / ScanDetail models.
 */
export interface Scan {
  id: string;
  target: string;
  target_type: string;
  files_scanned: number;
  findings_count: number;
  risk_score: number;
  verdict: Verdict | string;
  threat_hits: number;
  metadata: Record<string, unknown>;
  created_at: string;
  scanner_version?: string;
  confidence_summary?: {
    high: number;
    medium: number;
    low: number;
  };
  original_score?: number;
  rescanned_at?: string;
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

/** Community-submitted threat report with review workflow tracking. */
export interface ThreatReport {
  id: string;
  package_name: string;
  package_version: string;
  ecosystem: string;
  reason: string;
  evidence: string;
  reporter_email: string | null;
  status: "received" | "under_review" | "confirmed" | "rejected";
  reviewer_id: string | null;
  review_notes: string;
  reviewed_at: string | null;
  created_at: string;
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
  plan: PlanTier;
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

/** Billing plan definition (matches API PlanInfo). */
export interface BillingPlan {
  tier: string;
  name: string;
  price_monthly: number;
  price_yearly: number;
  scans_per_month: number;
  features: string[];
}

/** Active subscription record (matches API SubscriptionResponse). */
export interface Subscription {
  plan: string;
  status: "active" | "canceled" | "past_due" | "trialing" | "incomplete";
  billing_interval: "monthly" | "annual";
  current_period_start: string | null;
  current_period_end: string | null;
  cancel_at_period_end: boolean;
  stripe_subscription_id: string | null;
  checkout_url: string | null;
}

/** Dashboard overview statistics.
 *  Aligned with API DashboardStats model.
 */
export interface DashboardStats {
  total_scans: number;
  threats_blocked: number;
  packages_approved: number;
  critical_findings: number;
  scans_trend: number;
  threats_trend: number;
  approved_trend: number;
  critical_trend: number;
}

/** Generic paginated API response.
 *  Aligned with API ScanListResponse model.
 */
export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  per_page: number;
  has_more?: boolean;
  upgrade_message?: string | null;
}

/** Auth tokens returned after login / refresh. */
export interface AuthTokens {
  access_token: string;
  refresh_token?: string;
  expires_at?: number;
  expires_in?: number;
  token_type?: string;
  user?: User;
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

// ---------------------------------------------------------------------------
// Forge Types (Premium Features) - DEPRECATED/ARCHIVED
// ---------------------------------------------------------------------------

/** User subscription plan tiers. */
export type PlanTier = "free" | "pro" | "team" | "enterprise";

/** @deprecated A tracked tool in Forge - Forge functionality archived */
export interface ForgeTool {
  id: string;
  name: string;
  description: string;
  category: string;
  repository_url: string;
  documentation_url?: string;
  version: string;
  risk_score?: number;
  last_scan_id?: string;
  tracked_at: string;
  created_by: string;
}

/** @deprecated Forge settings/preferences - Forge functionality archived */
export interface ForgeSettings {
  notifications: {
    security_alerts: boolean;
    version_updates: boolean;
    weekly_digest: boolean;
  };
  privacy: {
    public_profile: boolean;
    share_anonymized_data: boolean;
  };
  tracking: {
    auto_track_dependencies: boolean;
    scan_frequency: "manual" | "daily" | "weekly";
  };
}

/** @deprecated Tool tracking request - Forge functionality archived */
export interface TrackToolRequest {
  name: string;
  repository_url: string;
  description?: string;
  category?: string;
}

// ---------------------------------------------------------------------------
// LLM Insights Types (Pro Features)
// ---------------------------------------------------------------------------

/** Types of LLM analysis available. */
export type LLMAnalysisType =
  | "zero_day_detection"
  | "obfuscation_analysis"
  | "behavioral_pattern"
  | "supply_chain_risk"
  | "ai_attack_vector"
  | "contextual_correlation";

/** Confidence levels for LLM analysis. */
export type LLMConfidenceLevel = "low" | "medium" | "high" | "very_high";

/** Categories of threats that LLM can detect. */
export type LLMThreatCategory =
  | "code_injection"
  | "data_exfiltration"
  | "credential_theft"
  | "supply_chain_attack"
  | "prompt_injection"
  | "privilege_escalation"
  | "obfuscated_malware"
  | "time_bomb"
  | "backdoor"
  | "unknown_pattern";

/** A single insight from LLM analysis. */
export interface LLMInsight {
  analysis_type: LLMAnalysisType;
  threat_category: LLMThreatCategory;
  confidence: number;
  confidence_level: LLMConfidenceLevel;
  title: string;
  description: string;
  reasoning: string;
  evidence_snippets: string[];
  affected_files: string[];
  severity_adjustment: number;
  false_positive_likelihood: number;
  remediation_suggestions: string[];
  mitigation_steps: string[];
}

/** Contextual analysis across multiple files/findings. */
export interface LLMContextAnalysis {
  attack_chain_detected: boolean;
  coordinated_threat: boolean;
  attack_chain_steps: string[];
  correlation_insights: string[];
  overall_intent: string;
  sophistication_level: "basic" | "intermediate" | "advanced";
}

/** Response model for LLM analysis. */
export interface LLMAnalysisResponse {
  insights: LLMInsight[];
  context_analysis: LLMContextAnalysis | null;
  analysis_id: string;
  model_used: string;
  tokens_used: number;
  processing_time_ms: number;
  cache_hit: boolean;
  confidence_summary: Record<string, number>;
  threat_summary: Record<string, number>;
  success: boolean;
  error_message: string | null;
  fallback_used: boolean;
  created_at: string;
}

// ---------------------------------------------------------------------------
// Interactive LLM Analysis Types (New Features)
// ---------------------------------------------------------------------------

/** Investigation depth levels for findings analysis. */
export type InvestigationDepth = "quick" | "thorough" | "exhaustive";

/** Investigation analysis response. */
export interface InvestigationResult {
  finding_id: string;
  depth: InvestigationDepth;
  confidence_score: number;
  threat_assessment: string;
  evidence: string[];
  code_flow_analysis: string;
  false_positive_likelihood: number;
  credits_used: number;
  model_used: string;
  created_at: string;
}

/** False positive analysis response. */
export interface FalsePositiveAnalysis {
  finding_id: string;
  is_safe: boolean;
  confidence_percentage: number;
  explanation: string;
  context_analysis: string;
  defense_suggestions: string[];
  credits_used: number;
  created_at: string;
}

/** Remediation code fix response. */
export interface RemediationResult {
  finding_id: string;
  fixes: Array<{
    id: string;
    title: string;
    description: string;
    code: string;
    language: string;
    explanation: string;
  }>;
  unit_test?: string;
  credits_used: number;
  created_at: string;
}

/** Interactive chat message. */
export interface ChatMessage {
  id: string;
  role: "user" | "assistant";
  content: string;
  timestamp: string;
  credits_used?: number;
  model_used?: string;
}

/** Interactive chat session. */
export interface ChatSession {
  id: string;
  scan_id: string;
  messages: ChatMessage[];
  created_at: string;
  updated_at: string;
}

/** Credit balance and usage. */
export interface CreditInfo {
  balance: number;
  monthly_limit: number;
  used_this_month: number;
  costs: {
    quick_investigation: number;
    thorough_investigation: number;
    exhaustive_investigation: number;
    false_positive_check: number;
    remediation: number;
    chat_message: number;
  };
}
