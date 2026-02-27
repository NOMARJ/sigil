"""
Sigil API — Pydantic Models

Defines all request/response schemas, domain models, and enumerations used
throughout the API.
"""

from __future__ import annotations

import enum
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


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
    verdict: Verdict = Field(Verdict.LOW_RISK, description="Overall risk classification")
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


# Forward-ref update so ScanResponse can reference ThreatEntry
ScanResponse.model_rebuild()
