"""
Sigil API — Pydantic Models

Defines all request/response schemas, domain models, and enumerations used
throughout the API.
"""

from __future__ import annotations

import enum
import re
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Verdict(str, enum.Enum):
    """Overall risk classification derived from the aggregate score."""

    LOW_RISK = "LOW_RISK"
    MEDIUM_RISK = "MEDIUM_RISK"
    HIGH_RISK = "HIGH_RISK"
    CRITICAL_RISK = "CRITICAL_RISK"


class Severity(str, enum.Enum):
    """Individual finding severity level."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ScanPhase(str, enum.Enum):
    """The eight scan phases: original six + AI security extensions."""

    INSTALL_HOOKS = "install_hooks"
    CODE_PATTERNS = "code_patterns"
    NETWORK_EXFIL = "network_exfil"
    CREDENTIALS = "credentials"
    OBFUSCATION = "obfuscation"
    PROVENANCE = "provenance"
    PROMPT_INJECTION = "prompt_injection"  # Phase 7: Prompt injection attacks
    SKILL_SECURITY = "skill_security"  # Phase 8: AI skill/tool abuse


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------


class Finding(BaseModel):
    """A single security finding discovered during a scan phase."""

    phase: ScanPhase = Field(..., description="Scan phase that produced this finding")
    rule: str = Field(..., description="Rule identifier (e.g. 'npm-postinstall')")
    severity: Severity = Field(..., description="Severity of the finding")
    file: str = Field(..., description="Relative path to the file")
    line: int = Field(0, description="Line number where the finding occurs")
    snippet: str = Field("", description="Code snippet around the finding")
    weight: float = Field(1.0, description="Weight multiplier for scoring")
    description: str = Field(
        "", description="Short human-readable label for the finding"
    )
    explanation: str = Field(
        "", description="Detailed reasoning for why this was flagged and its severity"
    )


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    """Payload submitted to POST /v1/scan."""

    target: str = Field(..., description="Path, URL, or package name that was scanned")
    target_type: str = Field(
        "directory",
        description="One of: directory, git, pip, npm",
    )
    files_scanned: int = Field(0, description="Total files examined")
    findings: list[Finding] = Field(
        default_factory=list, description="Raw findings list"
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict, description="Arbitrary scan metadata"
    )


class ScanResponse(BaseModel):
    """Response returned from POST /v1/scan after enrichment."""

    disclaimer: str = Field(
        default="Automated static analysis result. Not a security certification. "
        "Provided as-is without warranty. See sigilsec.ai/terms for full terms.",
        description="Legal disclaimer — always included in responses",
    )
    scan_id: str = Field(..., description="Unique identifier for this scan")
    target: str
    target_type: str
    files_scanned: int = 0
    findings: list[Finding] = Field(default_factory=list)
    risk_score: float = Field(0.0, description="Aggregate weighted risk score")
    verdict: Verdict = Field(
        Verdict.LOW_RISK, description="Overall risk classification"
    )
    threat_intel_hits: list[ThreatEntry] = Field(
        default_factory=list,
        description="Known threat entries matching this scan",
    )
    created_at: datetime = Field(default_factory=datetime.utcnow)


# ---------------------------------------------------------------------------
# Threat Intelligence
# ---------------------------------------------------------------------------


class ThreatEntry(BaseModel):
    """A known-malicious package record in the threat database."""

    hash: str = Field(..., description="SHA-256 hash of the package artifact")
    package_name: str = Field(..., description="Package name (e.g. 'evil-pkg')")
    version: str = Field("", description="Affected version or range")
    severity: Severity = Field(Severity.HIGH)
    source: str = Field(
        "community", description="Intel source (community, nvd, internal)"
    )
    confirmed_at: datetime | None = Field(
        None, description="When the threat was confirmed"
    )
    description: str = Field("", description="Human-readable description of the threat")


class SignatureEntry(BaseModel):
    """A pattern signature used by the scanner for detection."""

    id: str = Field(..., description="Unique signature identifier")
    phase: ScanPhase = Field(..., description="Scan phase this signature applies to")
    pattern: str = Field(..., description="Regex or literal pattern")
    severity: Severity = Field(Severity.MEDIUM)
    description: str = Field("")
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class SignatureResponse(BaseModel):
    """Response for GET /v1/signatures (delta sync)."""

    signatures: list[SignatureEntry] = Field(default_factory=list)
    total: int = 0
    last_updated: datetime | None = None


# ---------------------------------------------------------------------------
# Publisher Reputation
# ---------------------------------------------------------------------------


class PublisherReputation(BaseModel):
    """Trust profile for a package publisher."""

    publisher_id: str = Field(
        ..., description="Publisher identifier (npm username, PyPI user, etc.)"
    )
    trust_score: float = Field(
        100.0,
        ge=0.0,
        le=100.0,
        description="Trust score from 0 (untrusted) to 100 (fully trusted)",
    )
    total_packages: int = Field(0, description="Total packages published")
    flagged_count: int = Field(
        0, description="Number of packages flagged as suspicious"
    )
    first_seen: datetime | None = None
    last_active: datetime | None = None
    notes: str = Field("", description="Additional reputation notes")


# ---------------------------------------------------------------------------
# Threat Report
# ---------------------------------------------------------------------------


class ThreatReport(BaseModel):
    """User-submitted threat report for a package."""

    package_name: str = Field(..., description="Name of the suspicious package")
    package_version: str = Field("", description="Specific version if known")
    ecosystem: str = Field("unknown", description="Ecosystem: npm, pip, cargo, etc.")
    reason: str = Field(..., description="Why the reporter believes this is malicious")
    evidence: str = Field("", description="Supporting evidence (URLs, snippets, etc.)")
    reporter_email: str | None = Field(None, description="Optional contact email")


class ThreatReportResponse(BaseModel):
    """Acknowledgement returned after submitting a threat report."""

    report_id: str
    status: str = Field("received", description="Processing status")
    message: str = Field("Thank you for your report. Our team will review it.")


# ---------------------------------------------------------------------------
# Marketplace Verification
# ---------------------------------------------------------------------------


class VerifyRequest(BaseModel):
    """Request to verify a package for a marketplace badge."""

    package_name: str = Field(..., description="Fully-qualified package name")
    package_version: str = Field(..., description="Exact version to verify")
    ecosystem: str = Field(..., description="Ecosystem: npm, pip, cargo, etc.")
    publisher_id: str = Field("", description="Publisher identifier")
    artifact_hash: str = Field(
        "", description="SHA-256 hash of the distribution artifact"
    )


class VerifyResponse(BaseModel):
    """Verification result for a marketplace badge request."""

    package_name: str
    package_version: str
    verified: bool = Field(False, description="Whether the package passed verification")
    verdict: Verdict = Field(Verdict.LOW_RISK)
    risk_score: float = 0.0
    badge_url: str | None = Field(
        None, description="URL to the Sigil-verified badge if approved"
    )
    findings_summary: str = Field("", description="Brief summary of any findings")
    verified_at: datetime = Field(default_factory=datetime.utcnow)


# ---------------------------------------------------------------------------
# Auth / User
# ---------------------------------------------------------------------------


class PolicyType(str, enum.Enum):
    """Types of scan policies that can be applied to a team."""

    ALLOWLIST = "allowlist"
    BLOCKLIST = "blocklist"
    AUTO_APPROVE_THRESHOLD = "auto_approve_threshold"
    REQUIRED_PHASES = "required_phases"


class ChannelType(str, enum.Enum):
    """Notification channel types."""

    SLACK = "slack"
    EMAIL = "email"
    WEBHOOK = "webhook"


class PlanTier(str, enum.Enum):
    """Available billing plan tiers."""

    FREE = "free"
    PRO = "pro"
    TEAM = "team"
    ENTERPRISE = "enterprise"


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------


class PolicyCreate(BaseModel):
    """Request to create a new team policy."""

    name: str = Field(..., description="Human-readable policy name")
    type: PolicyType = Field(..., description="Policy type")
    config: dict[str, Any] = Field(
        default_factory=dict,
        description="Policy configuration (contents depend on type)",
    )
    enabled: bool = Field(True, description="Whether the policy is active")


class PolicyUpdate(BaseModel):
    """Request to update an existing policy."""

    name: str | None = Field(None, description="Updated policy name")
    type: PolicyType | None = Field(None, description="Updated policy type")
    config: dict[str, Any] | None = Field(None, description="Updated configuration")
    enabled: bool | None = Field(None, description="Updated enabled state")


class PolicyResponse(BaseModel):
    """A team policy record."""

    id: str
    team_id: str
    name: str
    type: PolicyType
    config: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class PolicyEvaluateRequest(BaseModel):
    """Request to evaluate a scan result against team policies."""

    risk_score: float = Field(..., description="Scan risk score to evaluate")
    verdict: Verdict = Field(..., description="Scan verdict")
    findings: list[Finding] = Field(default_factory=list, description="Scan findings")
    target: str = Field("", description="Scan target name")
    target_type: str = Field("directory", description="Scan target type")


class PolicyEvaluateResponse(BaseModel):
    """Result of evaluating a scan against team policies."""

    allowed: bool = Field(True, description="Whether the scan passes all policies")
    violations: list[str] = Field(default_factory=list, description="Policy violations")
    auto_approved: bool = Field(False, description="Whether the scan was auto-approved")
    evaluated_policies: int = Field(0, description="Number of policies evaluated")


# ---------------------------------------------------------------------------
# Alerts / Notifications
# ---------------------------------------------------------------------------


class AlertCreate(BaseModel):
    """Request to create a notification channel."""

    channel_type: ChannelType = Field(..., description="Notification channel type")
    channel_config: dict[str, Any] = Field(
        ...,
        description="Channel configuration (webhook_url for slack/webhook, recipients for email)",
    )
    enabled: bool = Field(True, description="Whether the channel is active")


class AlertUpdate(BaseModel):
    """Request to update an alert channel."""

    channel_type: ChannelType | None = Field(None, description="Updated channel type")
    channel_config: dict[str, Any] | None = Field(
        None, description="Updated configuration"
    )
    enabled: bool | None = Field(None, description="Updated enabled state")


class AlertResponse(BaseModel):
    """An alert channel record."""

    id: str
    team_id: str
    channel_type: ChannelType
    channel_config: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)


class AlertTestRequest(BaseModel):
    """Request to send a test notification."""

    channel_type: ChannelType = Field(..., description="Channel type to test")
    channel_config: dict[str, Any] = Field(..., description="Channel config to test")


class AlertTestResponse(BaseModel):
    """Result of a test notification."""

    success: bool
    message: str


# ---------------------------------------------------------------------------
# Billing
# ---------------------------------------------------------------------------


class PlanInfo(BaseModel):
    """A billing plan description."""

    tier: PlanTier
    name: str
    price_monthly: float = Field(0.0, description="Monthly price in USD")
    price_yearly: float = Field(
        0.0, description="Annual price in USD (billed once per year)"
    )
    scans_per_month: int = Field(
        0, description="Included scans per month (0 = unlimited)"
    )
    features: list[str] = Field(default_factory=list, description="Feature list")


class SubscribeRequest(BaseModel):
    """Request to create or change a subscription."""

    plan: PlanTier = Field(..., description="Plan tier to subscribe to")
    interval: Literal["monthly", "annual"] = Field(
        "monthly", description="Billing interval"
    )
    payment_method_id: str | None = Field(None, description="Stripe payment method ID")


class SubscriptionResponse(BaseModel):
    """Current subscription details."""

    plan: PlanTier
    status: str = Field("active", description="Subscription status")
    billing_interval: str = Field(
        "monthly", description="Billing interval: monthly or annual"
    )
    current_period_start: datetime | None = None
    current_period_end: datetime | None = None
    cancel_at_period_end: bool = False
    stripe_subscription_id: str | None = None
    checkout_url: str | None = Field(
        None,
        description="Stripe Checkout URL — redirect the user here to complete payment",
    )


class PortalResponse(BaseModel):
    """Stripe customer portal session URL."""

    url: str = Field(..., description="URL to redirect the user to")


class WebhookResponse(BaseModel):
    """Acknowledgement for Stripe webhook events."""

    received: bool = True
    event_type: str = ""


# ---------------------------------------------------------------------------
# Auth / User
# ---------------------------------------------------------------------------


class UserCreate(BaseModel):
    """Registration request payload."""

    email: str = Field(..., description="User email address")
    password: str = Field(..., min_length=8, description="Password (min 8 characters)")
    name: str = Field("", description="Display name")

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        email = value or ""
        if email != email.strip():
            raise ValueError("Invalid email format")
        # Simple robust email validation without external dependency
        if not re.match(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", email):
            raise ValueError("Invalid email format")
        if ".." in email:
            raise ValueError("Invalid email format")
        return email

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, value: str) -> str:
        password = value or ""
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters")
        if not re.search(r"[A-Z]", password):
            raise ValueError("Password must include an uppercase letter")
        if not re.search(r"[a-z]", password):
            raise ValueError("Password must include a lowercase letter")
        if not re.search(r"\d", password):
            raise ValueError("Password must include a number")
        return password

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        name = value or ""
        lowered = name.lower()
        if any(
            token in lowered
            for token in [
                "<script",
                "javascript:",
                "onerror",
                "onload",
                "<img",
                "<svg",
                "<iframe",
            ]
        ):
            raise ValueError("Invalid display name")
        if name and not re.match(r"^[A-Za-z0-9 _.-]{1,100}$", name):
            raise ValueError("Invalid display name")
        return name


class UserLogin(BaseModel):
    """Login request payload."""

    email: str
    password: str


class UserResponse(BaseModel):
    """Public-facing user representation (no secrets)."""

    id: str
    email: str
    name: str = ""
    created_at: datetime = Field(default_factory=datetime.utcnow)


class TokenResponse(BaseModel):
    """JWT token pair returned on successful auth."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int = Field(..., description="Token lifetime in seconds")
    user: UserResponse


# ---------------------------------------------------------------------------
# Scan — Dashboard list / detail models
# ---------------------------------------------------------------------------


class ScanListItem(BaseModel):
    """Summary of a scan for list views."""

    id: str
    target: str
    target_type: str = "directory"
    files_scanned: int = 0
    findings_count: int = 0
    risk_score: float = 0.0
    verdict: str = "LOW_RISK"
    threat_hits: int = 0
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class ScanListResponse(BaseModel):
    """Paginated list of scans."""

    items: list[ScanListItem] = Field(default_factory=list)
    total: int = 0
    page: int = 1
    per_page: int = 20
    upgrade_message: str | None = Field(
        None, description="Set when the user's plan restricts scan history access"
    )


class ScanDetail(BaseModel):
    """Full scan record returned by GET /scans/{id}."""

    id: str
    target: str
    target_type: str = "directory"
    files_scanned: int = 0
    findings_count: int = 0
    risk_score: float = 0.0
    verdict: str = "LOW_RISK"
    threat_hits: int = 0
    findings_json: list[Any] = Field(default_factory=list)
    metadata_json: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class DashboardStats(BaseModel):
    """Aggregate statistics for the dashboard overview."""

    total_scans: int = 0
    threats_blocked: int = 0
    packages_approved: int = 0
    critical_findings: int = 0
    scans_trend: float = 0.0
    threats_trend: float = 0.0
    approved_trend: float = 0.0
    critical_trend: float = 0.0


# ---------------------------------------------------------------------------
# Team management
# ---------------------------------------------------------------------------


class TeamMember(BaseModel):
    """A team member record."""

    id: str
    email: str
    name: str = ""
    role: str = "member"
    created_at: datetime = Field(default_factory=datetime.utcnow)


class TeamResponse(BaseModel):
    """Team details with members list."""

    id: str
    name: str
    owner_id: str | None = None
    plan: str = "free"
    members: list[TeamMember] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class TeamInviteRequest(BaseModel):
    """Request to invite a member to a team."""

    email: str = Field(..., description="Email of the user to invite")
    role: str = Field("member", description="Role to assign: member, admin, or owner")


class TeamInviteResponse(BaseModel):
    """Response after sending a team invite."""

    success: bool = True
    message: str = "Invitation sent"
    email: str = ""
    role: str = "member"


class RoleUpdateRequest(BaseModel):
    """Request to update a team member's role."""

    role: str = Field(..., description="New role: member, admin, or owner")


class ForgotPasswordRequest(BaseModel):
    """Request to initiate a password reset."""

    email: str = Field(..., description="Email address of the account to reset")


class ResetPasswordRequest(BaseModel):
    """Request to complete a password reset using a token."""

    token: str = Field(..., description="Reset token received via email")
    new_password: str = Field(
        ..., min_length=8, description="New password (min 8 characters)"
    )


class ForgotPasswordResponse(BaseModel):
    """Response after requesting a password reset."""

    message: str


class ResetPasswordResponse(BaseModel):
    """Response after successfully resetting a password."""

    message: str


class RefreshTokenRequest(BaseModel):
    """Request to refresh an access token."""

    refresh_token: str = Field(..., description="The refresh token")


class AuthTokens(BaseModel):
    """Token pair returned on refresh."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int = Field(..., description="Token lifetime in seconds")


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------


class ErrorResponse(BaseModel):
    """Standard error body."""

    detail: str


class GateError(BaseModel):
    """Structured error body returned when a plan tier gate blocks a request."""

    detail: str
    required_plan: str
    current_plan: str
    upgrade_url: str = "https://app.sigilsec.ai/upgrade"


# ---------------------------------------------------------------------------
# Email Newsletter (Forge Weekly)
# ---------------------------------------------------------------------------


class EmailSubscriptionRequest(BaseModel):
    """Request to subscribe to Forge Weekly newsletter."""

    email: str = Field(..., description="Subscriber email address")
    preferences: dict[str, bool] = Field(
        default_factory=lambda: {
            "security_alerts": True,
            "tool_discoveries": True,
            "weekly_digest": True,
            "product_updates": True,
        },
        description="Email preferences for different content types",
    )
    source: str = Field(
        "forge", description="Subscription source (forge, api, dashboard)"
    )


class EmailSubscriptionResponse(BaseModel):
    """Response after email subscription."""

    success: bool = True
    message: str = "Successfully subscribed to Forge Weekly"
    email: str = ""
    preferences: dict[str, bool] = Field(default_factory=dict)
    unsubscribe_token: str = Field("", description="Token for unsubscribe links")


class EmailPreferencesUpdate(BaseModel):
    """Request to update email preferences."""

    preferences: dict[str, bool] = Field(..., description="Updated email preferences")


class WeeklyDigestContent(BaseModel):
    """Content structure for weekly digest generation."""

    week_ending: datetime = Field(..., description="Week ending date")
    new_tools: list[dict[str, Any]] = Field(
        default_factory=list, description="New tool discoveries"
    )
    security_alerts: list[dict[str, Any]] = Field(
        default_factory=list, description="Security alerts and threats"
    )
    trending_categories: list[dict[str, Any]] = Field(
        default_factory=list, description="Trending tool categories"
    )
    trust_score_changes: list[dict[str, Any]] = Field(
        default_factory=list, description="Notable trust score changes"
    )
    community_highlights: list[dict[str, str]] = Field(
        default_factory=list, description="Community submissions and highlights"
    )
    metrics: dict[str, int] = Field(
        default_factory=dict, description="Weekly metrics (scans, discoveries, etc.)"
    )


class EmailCampaignRequest(BaseModel):
    """Request to send an email campaign."""

    subject: str = Field(..., description="Email subject line")
    content: WeeklyDigestContent = Field(..., description="Email content")
    send_at: datetime | None = Field(None, description="Scheduled send time")
    test_mode: bool = Field(False, description="Send to test recipients only")


class EmailCampaignResponse(BaseModel):
    """Response after creating email campaign."""

    campaign_id: str = Field(..., description="Unique campaign identifier")
    scheduled_for: datetime = Field(..., description="Scheduled send time")
    recipient_count: int = Field(0, description="Number of recipients")
    status: str = Field("scheduled", description="Campaign status")


class UnsubscribeRequest(BaseModel):
    """Request to unsubscribe from emails."""

    token: str = Field(..., description="Unsubscribe token from email")
    reason: str = Field("", description="Optional unsubscribe reason")


class UnsubscribeResponse(BaseModel):
    """Response after unsubscribing."""

    success: bool = True
    message: str = "Successfully unsubscribed from all emails"


# ---------------------------------------------------------------------------
# Forge Analytics and Event Tracking
# ---------------------------------------------------------------------------


class ForgeEventType(str, enum.Enum):
    """Event types for Forge analytics tracking."""

    # Tool interactions
    TOOL_VIEWED = "tool_viewed"
    TOOL_TRACKED = "tool_tracked"
    TOOL_UNTRACKED = "tool_untracked"
    TOOL_STARRED = "tool_starred"
    TOOL_DETAIL_VIEWED = "tool_detail_viewed"

    # Stack management
    STACK_CREATED = "stack_created"
    STACK_SHARED = "stack_shared"
    STACK_DEPLOYED = "stack_deployed"
    STACK_FAVORITED = "stack_favorited"

    # Search and discovery
    SEARCH_PERFORMED = "search_performed"
    CATEGORY_BROWSED = "category_browsed"
    ECOSYSTEM_FILTERED = "ecosystem_filtered"
    FORGE_API_USED = "forge_api_used"

    # Alerts and monitoring
    ALERT_CONFIGURED = "alert_configured"
    ALERT_RECEIVED = "alert_received"
    ALERT_CLICKED = "alert_clicked"
    NOTIFICATION_SENT = "notification_sent"

    # Feature usage
    ANALYTICS_VIEWED = "analytics_viewed"
    EXPORT_PERFORMED = "export_performed"
    SETTINGS_UPDATED = "settings_updated"
    DASHBOARD_ACCESSED = "dashboard_accessed"

    # Security events
    TRUST_SCORE_CHANGED = "trust_score_changed"
    SECURITY_FINDING = "security_finding"
    SCAN_COMPLETED = "scan_completed"


class ForgeAnalyticsEvent(BaseModel):
    """Forge analytics event for tracking user behavior."""

    user_id: str = Field(..., description="User who performed the action")
    event_type: ForgeEventType = Field(..., description="Type of event")
    event_data: dict[str, Any] = Field(
        default_factory=dict, description="Event-specific data payload"
    )
    session_id: str | None = Field(None, description="User session identifier")
    ip_address: str | None = Field(None, description="Source IP address")
    user_agent: str | None = Field(None, description="User agent string")
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class PersonalAnalyticsRequest(BaseModel):
    """Request for personal analytics (Pro+ plan)."""

    days_back: int = Field(30, ge=1, le=365, description="Days to look back")
    categories: list[str] | None = Field(None, description="Filter by categories")
    ecosystems: list[str] | None = Field(None, description="Filter by ecosystems")


class PersonalAnalyticsResponse(BaseModel):
    """Personal analytics response for Pro+ users."""

    period_days: int
    total_tool_views: int
    total_tools_tracked: int
    total_searches: int
    total_stacks_created: int

    # Top tools by interaction
    most_viewed_tools: list[dict[str, Any]] = Field(default_factory=list)
    most_tracked_tools: list[dict[str, Any]] = Field(default_factory=list)

    # Usage patterns
    discovery_sources: dict[str, int] = Field(
        default_factory=dict, description="How user finds tools (search, browse, etc.)"
    )
    category_preferences: dict[str, int] = Field(
        default_factory=dict, description="Category interaction counts"
    )
    ecosystem_usage: dict[str, int] = Field(
        default_factory=dict, description="Ecosystem interaction counts"
    )

    # Security trends
    trust_score_trends: list[dict[str, Any]] = Field(
        default_factory=list, description="Trust score changes over time"
    )
    security_findings_timeline: list[dict[str, Any]] = Field(
        default_factory=list, description="Security findings for tracked tools"
    )

    # Activity patterns
    daily_activity: dict[str, int] = Field(
        default_factory=dict, description="Activity by day of week"
    )
    hourly_activity: dict[str, int] = Field(
        default_factory=dict, description="Activity by hour of day"
    )


class TeamAnalyticsResponse(BaseModel):
    """Team analytics response for Team+ users."""

    period_days: int
    team_id: str

    # Team overview
    active_members: int
    total_tools_tracked: int
    total_stacks_shared: int
    total_scans_performed: int

    # Collaboration metrics
    most_popular_tools: list[dict[str, Any]] = Field(default_factory=list)
    shared_tool_stacks: list[dict[str, Any]] = Field(default_factory=list)
    member_activity: list[dict[str, Any]] = Field(default_factory=list)

    # Team tool adoption
    tool_adoption_timeline: list[dict[str, Any]] = Field(default_factory=list)
    category_distribution: dict[str, int] = Field(default_factory=dict)
    ecosystem_distribution: dict[str, int] = Field(default_factory=dict)

    # Security compliance
    security_compliance_score: float = Field(
        0.0, description="Team security compliance percentage"
    )
    security_findings_summary: dict[str, int] = Field(default_factory=dict)
    tools_needing_review: list[dict[str, Any]] = Field(default_factory=list)


class OrganizationAnalyticsResponse(BaseModel):
    """Organization analytics response for Enterprise users."""

    organization_id: str

    # Department breakdown
    departments: list[dict[str, Any]] = Field(
        default_factory=list, description="Department-level analytics"
    )

    # Cost analysis
    total_tools_in_use: int
    estimated_monthly_costs: dict[str, float] = Field(
        default_factory=dict, description="Cost estimates by category"
    )
    cost_optimization_opportunities: list[dict[str, Any]] = Field(default_factory=list)

    # Risk dashboard
    organization_risk_score: float = Field(
        0.0, description="Overall organization security risk"
    )
    high_risk_tools: list[dict[str, Any]] = Field(default_factory=list)
    compliance_metrics: dict[str, float] = Field(default_factory=dict)
    security_trends: list[dict[str, Any]] = Field(default_factory=list)


class AnalyticsEventCreateRequest(BaseModel):
    """Request to track an analytics event."""

    event_type: ForgeEventType
    event_data: dict[str, Any] = Field(default_factory=dict)
    session_id: str | None = None


class AnalyticsEventBatchRequest(BaseModel):
    """Request to track multiple analytics events in batch."""

    events: list[AnalyticsEventCreateRequest]


# ---------------------------------------------------------------------------
# Forge Premium Features - Tool Tracking, Stacks, Alerts, Settings
# ---------------------------------------------------------------------------


class TrackedTool(BaseModel):
    """A tool tracked by a user with metadata."""

    id: str = Field(..., description="Tracking record ID")
    tool_id: str = Field(..., description="Tool package name")
    ecosystem: str = Field(..., description="Tool ecosystem (pip, npm, etc.)")
    tracked_at: datetime = Field(..., description="When tool was tracked")
    is_starred: bool = Field(False, description="User has starred this tool")
    custom_tags: list[str] = Field(
        default_factory=list, description="User-defined tags"
    )
    notes: str = Field("", description="User notes about this tool")
    trust_score: float = Field(0.0, description="Current trust score")


class TrackToolRequest(BaseModel):
    """Request to track a tool."""

    tool_id: str = Field(..., description="Package name to track")
    ecosystem: str = Field(..., description="Tool ecosystem")
    is_starred: bool = Field(False, description="Star the tool immediately")
    custom_tags: list[str] = Field(default_factory=list, description="Initial tags")
    notes: str = Field("", description="Initial notes")


class UpdateTrackedToolRequest(BaseModel):
    """Request to update tracked tool metadata."""

    is_starred: bool | None = None
    custom_tags: list[str] | None = None
    notes: str | None = None


class ForgeStack(BaseModel):
    """A custom tool stack created by a user."""

    id: str = Field(..., description="Stack ID")
    name: str = Field(..., description="Stack name")
    description: str = Field("", description="Stack description")
    tools: list[dict[str, Any]] = Field(
        default_factory=list, description="Tools in stack"
    )
    is_public: bool = Field(False, description="Stack is publicly visible")
    user_id: str = Field(..., description="Creator user ID")
    team_id: str | None = Field(None, description="Associated team ID")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")


class CreateStackRequest(BaseModel):
    """Request to create a new tool stack."""

    name: str = Field(..., max_length=255, description="Stack name")
    description: str = Field("", description="Stack description")
    tools: list[dict[str, Any]] = Field(..., description="Tools in the stack")
    is_public: bool = Field(False, description="Make stack publicly visible")


class UpdateStackRequest(BaseModel):
    """Request to update an existing stack."""

    name: str | None = None
    description: str | None = None
    tools: list[dict[str, Any]] | None = None
    is_public: bool | None = None


class AlertSubscription(BaseModel):
    """A user's alert subscription configuration."""

    id: str = Field(..., description="Subscription ID")
    tool_id: str | None = Field(None, description="Specific tool (None = all tools)")
    ecosystem: str | None = Field(None, description="Specific ecosystem (None = all)")
    alert_types: list[str] = Field(..., description="Types of alerts to receive")
    channels: dict[str, bool] = Field(
        default_factory=dict, description="Notification channels"
    )
    is_active: bool = Field(True, description="Subscription is active")
    created_at: datetime = Field(..., description="Creation timestamp")


class CreateAlertSubscriptionRequest(BaseModel):
    """Request to create an alert subscription."""

    tool_id: str | None = Field(None, description="Specific tool (optional)")
    ecosystem: str | None = Field(None, description="Specific ecosystem (optional)")
    alert_types: list[str] = Field(..., description="Alert types to subscribe to")
    channels: dict[str, bool] = Field(
        default_factory=dict, description="Notification channels"
    )


class UpdateAlertSubscriptionRequest(BaseModel):
    """Request to update an alert subscription."""

    alert_types: list[str] | None = None
    channels: dict[str, bool] | None = None
    is_active: bool | None = None


class ForgeUserSettings(BaseModel):
    """User's Forge preferences and settings."""

    alert_frequency: str = Field("daily", description="How often to receive alerts")
    alert_types: list[str] = Field(
        default_factory=lambda: ["security", "updates"],
        description="Default alert types",
    )
    delivery_channels: list[str] = Field(
        default_factory=lambda: ["email"], description="Default delivery channels"
    )
    quiet_hours: dict[str, str] | None = Field(
        None, description="Quiet hours configuration"
    )
    email_notifications: bool = Field(True, description="Enable email notifications")
    slack_notifications: bool = Field(False, description="Enable Slack notifications")
    weekly_digest: bool = Field(True, description="Send weekly digest email")
    created_at: datetime = Field(..., description="Settings creation time")
    updated_at: datetime = Field(..., description="Settings last update")


class UpdateForgeSettingsRequest(BaseModel):
    """Request to update Forge user settings."""

    alert_frequency: str | None = Field(None, pattern="^(instant|daily|weekly)$")
    alert_types: list[str] | None = None
    delivery_channels: list[str] | None = None
    quiet_hours: dict[str, str] | None = None
    email_notifications: bool | None = None
    slack_notifications: bool | None = None
    weekly_digest: bool | None = None


# Forward-ref update so ScanResponse can reference ThreatEntry
ScanResponse.model_rebuild()
