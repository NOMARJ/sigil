"""
Sigil API — Pydantic Models

Defines all request/response schemas, domain models, and enumerations used
throughout the API.
"""

from __future__ import annotations

import enum
import re
import unicodedata
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SerializerFunctionWrapHandler,
    computed_field,
    field_validator,
    model_serializer,
    model_validator,
)


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


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


class Confidence(str, enum.Enum):
    """Confidence level for findings - how certain we are this is a real issue."""

    HIGH = "HIGH"  # Very likely a real security issue
    MEDIUM = "MEDIUM"  # Possibly a security issue, needs review
    LOW = "LOW"  # Likely a false positive


class ScanPhase(str, enum.Enum):
    """The scan phases: original six + AI security extensions."""

    INSTALL_HOOKS = "install_hooks"
    CODE_PATTERNS = "code_patterns"
    NETWORK_EXFIL = "network_exfil"
    CREDENTIALS = "credentials"
    OBFUSCATION = "obfuscation"
    PROVENANCE = "provenance"
    PROMPT_INJECTION = "prompt_injection"  # Phase 7: Prompt injection attacks
    SKILL_SECURITY = "skill_security"  # Phase 8: AI skill/tool abuse
    LLM_ANALYSIS = "llm_analysis"  # Phase 9: AI-powered threat detection (Pro)
    # Phase 10 of the Rust CLI (static INFER-* rules: hijackable LLM client
    # endpoints). Not an LLM verdict, so it is not folded into llm_analysis.
    INFERENCE_SECURITY = "inference_security"


class PlanTier(str, enum.Enum):
    """Subscription tier levels for feature access and credit allocation."""

    ANONYMOUS = "anonymous"
    FREE = "free"
    PRO = "pro"
    ELITE = "elite"
    TEAM = "team"
    ENTERPRISE = "enterprise"


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------


def _phase_key(name: str) -> str:
    return re.sub(r"[\s_-]", "", name).lower()


# Phase spellings the Rust CLI sends, keyed case- and separator-insensitively:
# `sigil scan --submit` / `--enhanced` up to 1.3.7 post serde PascalCase
# ("InstallHooks"), `sigil explain` 1.3.7 posts "inferencesecurity" for Phase
# 10, and current clients post the snake_case values themselves.
_PHASE_BY_KEY: Dict[str, str] = {_phase_key(p.value): p.value for p in ScanPhase}


class Finding(BaseModel):
    """A single security finding discovered during a scan phase."""

    phase: ScanPhase = Field(..., description="Scan phase that produced this finding")
    rule: str = Field(..., description="Rule identifier (e.g. 'npm-postinstall')")
    severity: Severity = Field(..., description="Severity of the finding")
    confidence: Confidence = Field(
        Confidence.HIGH,
        description="Confidence level - how certain this is a real issue",
    )
    file: str = Field(..., description="Relative path to the file")
    line: Optional[int] = Field(
        None,
        description=(
            "Line number where the finding occurs. None for findings not tied "
            "to a specific line (e.g. provenance checks); the Rust CLI emits "
            '"line": null for these.'
        ),
    )
    snippet: str = Field("", description="Code snippet around the finding")
    weight: float = Field(1.0, description="Weight multiplier for scoring")
    description: str = Field(
        "", description="Short human-readable label for the finding"
    )
    explanation: str = Field(
        "", description="Detailed reasoning for why this was flagged and its severity"
    )

    @field_validator("phase", mode="before")
    @classmethod
    def _accept_cli_phase_spelling(cls, value: Any) -> Any:
        """Map the CLI's phase spellings onto the enum; unknown names still fail."""
        if isinstance(value, str):
            return _PHASE_BY_KEY.get(_phase_key(value), value)
        return value

    @field_validator("severity", mode="before")
    @classmethod
    def _accept_any_case_severity(cls, value: Any) -> Any:
        """The Rust CLI serialises severities title-cased ("High")."""
        if isinstance(value, str):
            return value.strip().upper()
        return value


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

# Target recorded for a scan the CLI submits. `sigil scan --submit` and
# `--enhanced` send it (the CLI does not send the scanned path), and it is
# filled in for the raw ScanResult that CLI 1.3.7 and earlier post without one.
CLI_SCAN_TARGET = "cli-scan"

# Keys the Rust CLI's ScanResult always serialises. Together with a missing
# `target` they identify a `sigil scan --submit` body from CLI <= 1.3.7.
_CLI_SCAN_RESULT_KEYS = ("score", "verdict", "duration_ms", "findings")


class ScanRequest(BaseModel):
    """Payload submitted to POST /v1/scan."""

    target: str = Field(..., description="Path, URL, or package name that was scanned")
    target_type: str = Field(
        "directory",
        description="One of: directory, git, pip, npm",
    )
    files_scanned: int = Field(0, description="Total files examined")
    findings: List[Finding] = Field(
        default_factory=list, description="Raw findings list"
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict, description="Arbitrary scan metadata"
    )

    @model_validator(mode="before")
    @classmethod
    def _accept_released_cli_scan_result(cls, data: Any) -> Any:
        """Accept the raw ScanResult that `sigil scan --submit` <= 1.3.7 posts.

        That body carries no `target`; every other client must still send one.
        """
        if (
            isinstance(data, dict)
            and "target" not in data
            and all(k in data for k in _CLI_SCAN_RESULT_KEYS)
        ):
            return {**data, "target": CLI_SCAN_TARGET}
        return data


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
    findings: List[Finding] = Field(default_factory=list)
    risk_score: float = Field(0.0, description="Aggregate weighted risk score")
    verdict: Verdict = Field(
        Verdict.LOW_RISK, description="Overall risk classification"
    )
    threat_intel_hits: List[ThreatEntry] = Field(
        default_factory=list,
        description="Known threat entries matching this scan",
    )
    created_at: datetime = Field(default_factory=utcnow)
    status: str = Field(
        "completed",
        description="Processing status. The scan is scored and stored before "
        "the response is sent.",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Endpoint-specific notes, e.g. whether /v1/scan-enhanced "
        "ran LLM analysis or returned the static result only",
    )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def id(self) -> str:
        """Alias of scan_id: CLI 1.3.7 reads the scan id from `id`."""
        return self.scan_id


def _id_alias_not_required(schema: Dict[str, Any]) -> None:
    schema["required"] = [k for k in schema.get("required", []) if k != "id"]


class EnhancedScanResponse(ScanResponse):
    """Response returned from POST /v1/scan-enhanced.

    The `id` alias is sent only when `metadata.llm_analysis_performed` is
    true. CLI 1.3.7 cannot parse a response without `id`, and when it can, it
    prints "Enhanced LLM analysis completed" whatever the metadata says.
    Without `id` it reports that the enhanced analysis failed and continues
    with its static results, which is what happened. Current CLIs read
    `scan_id` and the metadata, so they are unaffected.
    """

    model_config = ConfigDict(json_schema_extra=_id_alias_not_required)

    # No return annotation: pydantic would take it as the response schema,
    # and the OpenAPI document would lose the model's fields.
    @model_serializer(mode="wrap")
    def _id_only_after_llm_analysis(self, handler: SerializerFunctionWrapHandler):
        data = handler(self)
        if (
            isinstance(data, dict)
            and self.metadata.get("llm_analysis_performed") is not True
        ):
            data.pop("id", None)
        return data

    @classmethod
    def from_scan(cls, response: ScanResponse) -> "EnhancedScanResponse":
        """The /v1/scan-enhanced form of a scan response."""
        return cls(**response.model_dump(exclude={"id"}))


# ---------------------------------------------------------------------------
# Threat Intelligence
# ---------------------------------------------------------------------------


# `source` of a threat entry promoted from a confirmed community report.
COMMUNITY_SOURCE = "community"

# `source` of a threat entry promoted from a confirmed `sigil report <hash>`
# report. Its hash is whatever the reporter typed, and a reviewer cannot check
# it without the artifact, so the entry is shown by GET /v1/threat/{hash} but
# never moves a POST /v1/verify verdict or a POST /v1/scan score
# (`is_unverified_hash_entry`).
COMMUNITY_UNVERIFIED_SOURCE = "community-unverified"


class ThreatEntry(BaseModel):
    """A known-malicious package record in the threat database."""

    hash: str = Field(..., description="SHA-256 hash of the package artifact")
    package_name: str = Field(..., description="Package name (e.g. 'evil-pkg')")
    version: str = Field("", description="Affected version or range")
    severity: Severity = Field(Severity.HIGH)
    source: str = Field(
        COMMUNITY_SOURCE, description="Intel source (community, nvd, internal)"
    )
    confirmed_at: Optional[datetime] = Field(
        None, description="When the threat was confirmed"
    )
    description: str = Field("", description="Human-readable description of the threat")


# Unicode general categories `without_control_characters` replaces.
_UNPRINTABLE_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp"})


def without_control_characters(text: str) -> str:
    """*text* with every character that is unsafe to print as a space.

    That is control characters (Unicode category Cc: terminal escapes, BEL,
    carriage returns, newlines), format characters (Cf: the bidirectional
    overrides and isolates, zero-width and joining characters) and the line
    and paragraph separators U+2028 and U+2029 (Zl, Zp): the same set the
    CLI's `terminal_text` replaces before printing.
    """
    return "".join(
        " " if unicodedata.category(c) in _UNPRINTABLE_CATEGORIES else c for c in text
    )


# The text fields of a threat entry that reach a client.
_THREAT_TEXT_FIELDS = ("hash", "package_name", "version", "source", "description")


def is_unverified_hash_entry(entry: ThreatEntry) -> bool:
    """Whether *entry* was keyed by a hash a reporter chose.

    That is an entry promoted from a `sigil report <hash>` report: source
    `community-unverified`, or `community` with a `sha256:<hash>` package name
    (the form a report confirmed before the distinct source existed has).
    """
    source = without_control_characters(entry.source).strip()
    if source == COMMUNITY_UNVERIFIED_SOURCE:
        return True
    return (
        source == COMMUNITY_SOURCE and reported_sha256(entry.package_name) is not None
    )


def attributed_threat_entry(entry: ThreatEntry) -> ThreatEntry:
    """*entry* as it may be shown to a client.

    Its text carries no control characters (`without_control_characters`), and
    a community entry's description says whose text it is. That description is
    the reporter's own, and the clients that print it (CLI 1.3.7 prints the
    description alone, without the source) cannot tell it from Sigil's. It is
    prefixed with where it came from: "Community report: ", or for a `sigil
    report <hash>` report, whose hash a reviewer cannot check without the
    artifact, "Community report (unverified hash): ". An empty description
    stays empty: there is no reporter text to attribute, and the readers that
    name the package in its place (POST /v1/verify) still can.

    `lookup_threat` returns entries in this form, so every reader of the
    threat database gets it: GET /v1/threat/{hash}, POST /v1/verify and the
    hash enrichment of POST /v1/scan.
    """
    unverified = is_unverified_hash_entry(entry)
    data = entry.model_dump()
    for key in _THREAT_TEXT_FIELDS:
        data[key] = without_control_characters(data[key])
    if unverified or data["source"].strip() == COMMUNITY_SOURCE:
        label = (
            "Community report (unverified hash)" if unverified else "Community report"
        )
        text = data["description"].strip()
        data["description"] = f"{label}: {text}" if text else ""
    return ThreatEntry(**data)


class ThreatLookupResponse(ThreatEntry):
    """Response for GET /v1/threat/{hash}: a match in the threat database.

    The lookup answers 404 when the hash is unknown, so every response body is
    a confirmed threat. `known_malicious` and `references` are the fields CLI
    1.3.7 requires before it will show a match; references are not recorded,
    so the list is empty.

    Text fields carry no control characters. CLI 1.3.7 prints the description
    raw, and a community entry's description is the reporter's own text.
    """

    known_malicious: bool = Field(
        True, description="Always true: unknown hashes return 404"
    )
    references: List[str] = Field(
        default_factory=list, description="External references (none recorded)"
    )

    @field_validator("hash", "package_name", "version", "source", "description")
    @classmethod
    def _printable_text(cls, value: str) -> str:
        return without_control_characters(value)

    @classmethod
    def from_entry(cls, entry: ThreatEntry) -> "ThreatLookupResponse":
        """The lookup response for *entry*, as `lookup_threat` returns it
        (already attributed by `attributed_threat_entry`)."""
        return cls(**entry.model_dump())


class SignatureEntry(BaseModel):
    """A pattern signature used by the scanner for detection."""

    id: str = Field(..., description="Unique signature identifier")
    phase: ScanPhase = Field(..., description="Scan phase this signature applies to")
    pattern: str = Field(..., description="Regex or literal pattern")
    severity: Severity = Field(Severity.MEDIUM)
    description: str = Field("")
    updated_at: datetime = Field(default_factory=utcnow)


class SignatureResponse(BaseModel):
    """Response for GET /v1/signatures (delta sync)."""

    signatures: List[SignatureEntry] = Field(default_factory=list)
    total: int = 0
    last_updated: Optional[datetime] = None


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
    first_seen: Optional[datetime] = None
    last_active: Optional[datetime] = None
    notes: str = Field("", description="Additional reputation notes")


# ---------------------------------------------------------------------------
# Threat Report
# ---------------------------------------------------------------------------

_SHA256_HEX = re.compile(r"[0-9a-f]{64}")

# Package-name prefix of a `sigil report <hash>` report.
HASH_REPORT_PREFIX = "sha256:"


def reported_sha256(package_name: str) -> Optional[str]:
    """The digest of a hash report's package name (`sha256:<64 hex>`), else None."""
    if not package_name.startswith(HASH_REPORT_PREFIX):
        return None
    digest = package_name[len(HASH_REPORT_PREFIX) :]
    return digest if _SHA256_HEX.fullmatch(digest) else None


class ThreatReport(BaseModel):
    """User-submitted threat report for a package."""

    package_name: str = Field(..., description="Name of the suspicious package")
    package_version: str = Field("", description="Specific version if known")
    ecosystem: str = Field("unknown", description="Ecosystem: npm, pip, cargo, etc.")
    reason: str = Field(..., description="Why the reporter believes this is malicious")
    evidence: str = Field("", description="Supporting evidence (URLs, snippets, etc.)")
    reporter_email: Optional[str] = Field(None, description="Optional contact email")

    @model_validator(mode="before")
    @classmethod
    def _accept_cli_hash_report(cls, data: Any) -> Any:
        """Accept the `{hash, threat_type, description}` body of `sigil report`.

        CLI 1.3.7 and earlier post that shape. It is stored the way current
        CLIs send it: package_name `sha256:<hash>`, the description as the
        reason, and the threat type and hash as evidence. A hash that is not
        a SHA-256 digest (64 hex characters, any case) is refused.
        """
        if not isinstance(data, dict) or "package_name" in data:
            return data
        raw_hash = data.get("hash")
        if not isinstance(raw_hash, str) or not raw_hash.strip():
            return data
        digest = raw_hash.strip().lower()
        if not _SHA256_HEX.fullmatch(digest):
            raise ValueError("hash must be a SHA-256 digest: 64 hexadecimal characters")
        evidence = []
        threat_type = data.get("threat_type")
        if isinstance(threat_type, str) and threat_type.strip():
            evidence.append(f"Threat type: {threat_type.strip()}")
        evidence.append(f"SHA-256: {digest}")
        mapped = {**data, "package_name": f"{HASH_REPORT_PREFIX}{digest}"}
        if "reason" not in data and "description" in data:
            mapped["reason"] = data["description"]
        mapped.setdefault("evidence", "\n".join(evidence))
        return mapped


class ThreatReportResponse(BaseModel):
    """Acknowledgement returned after submitting a threat report."""

    report_id: str
    status: str = Field("received", description="Processing status")
    message: str = Field("Thank you for your report. Our team will review it.")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def id(self) -> str:
        """Alias of report_id: CLI 1.3.7 reads the report id from `id`."""
        return self.report_id


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
    badge_url: Optional[str] = Field(
        None, description="URL to the Sigil-verified badge if approved"
    )
    findings_summary: str = Field("", description="Brief summary of any findings")
    verified_at: datetime = Field(default_factory=utcnow)


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


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------


class PolicyCreate(BaseModel):
    """Request to create a new team policy."""

    name: str = Field(..., description="Human-readable policy name")
    type: PolicyType = Field(..., description="Policy type")
    config: Dict[str, Any] = Field(
        default_factory=dict,
        description="Policy configuration (contents depend on type)",
    )
    enabled: bool = Field(True, description="Whether the policy is active")


class PolicyUpdate(BaseModel):
    """Request to update an existing policy."""

    name: Optional[str] = Field(None, description="Updated policy name")
    type: Optional[PolicyType] = Field(None, description="Updated policy type")
    config: Optional[Dict[str, Any]] = Field(None, description="Updated configuration")
    enabled: Optional[bool] = Field(None, description="Updated enabled state")


class PolicyResponse(BaseModel):
    """A team policy record."""

    id: str
    team_id: str
    name: str
    type: PolicyType
    config: Dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)


class PolicyEvaluateRequest(BaseModel):
    """Request to evaluate a scan result against team policies."""

    risk_score: float = Field(..., description="Scan risk score to evaluate")
    verdict: Verdict = Field(..., description="Scan verdict")
    findings: List[Finding] = Field(default_factory=list, description="Scan findings")
    target: str = Field("", description="Scan target name")
    target_type: str = Field("directory", description="Scan target type")


class PolicyEvaluateResponse(BaseModel):
    """Result of evaluating a scan against team policies."""

    allowed: bool = Field(True, description="Whether the scan passes all policies")
    violations: List[str] = Field(default_factory=list, description="Policy violations")
    auto_approved: bool = Field(False, description="Whether the scan was auto-approved")
    evaluated_policies: int = Field(0, description="Number of policies evaluated")


# ---------------------------------------------------------------------------
# Alerts / Notifications
# ---------------------------------------------------------------------------


class AlertCreate(BaseModel):
    """Request to create a notification channel."""

    channel_type: ChannelType = Field(..., description="Notification channel type")
    channel_config: Dict[str, Any] = Field(
        ...,
        description="Channel configuration (webhook_url for slack/webhook, recipients for email)",
    )
    enabled: bool = Field(True, description="Whether the channel is active")


class AlertUpdate(BaseModel):
    """Request to update an alert channel."""

    channel_type: Optional[ChannelType] = Field(
        None, description="Updated channel type"
    )
    channel_config: Optional[Dict[str, Any]] = Field(
        None, description="Updated configuration"
    )
    enabled: Optional[bool] = Field(None, description="Updated enabled state")


class AlertResponse(BaseModel):
    """An alert channel record."""

    id: str
    team_id: str
    channel_type: ChannelType
    channel_config: Dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True
    created_at: datetime = Field(default_factory=utcnow)


class AlertTestRequest(BaseModel):
    """Request to send a test notification."""

    channel_type: ChannelType = Field(..., description="Channel type to test")
    channel_config: Dict[str, Any] = Field(..., description="Channel config to test")


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
    features: List[str] = Field(default_factory=list, description="Feature list")


class SubscribeRequest(BaseModel):
    """Request to create or change a subscription."""

    plan: PlanTier = Field(..., description="Plan tier to subscribe to")
    interval: Literal["monthly", "annual"] = Field(
        "monthly", description="Billing interval"
    )
    payment_method_id: Optional[str] = Field(
        None, description="Stripe payment method ID"
    )


class SubscriptionResponse(BaseModel):
    """Current subscription details."""

    plan: PlanTier
    status: str = Field("active", description="Subscription status")
    billing_interval: str = Field(
        "monthly", description="Billing interval: monthly or annual"
    )
    current_period_start: Optional[datetime] = None
    current_period_end: Optional[datetime] = None
    cancel_at_period_end: bool = False
    stripe_subscription_id: Optional[str] = None
    checkout_url: Optional[str] = Field(
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
    role: str = "member"
    team_id: Optional[str] = None
    created_at: datetime = Field(default_factory=utcnow)


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
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utcnow)


class ScanListResponse(BaseModel):
    """Paginated list of scans."""

    items: List[ScanListItem] = Field(default_factory=list)
    total: int = 0
    page: int = 1
    per_page: int = 20
    upgrade_message: Optional[str] = Field(
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
    findings_json: List[Any] = Field(default_factory=list)
    metadata_json: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utcnow)


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
    created_at: datetime = Field(default_factory=utcnow)


class TeamResponse(BaseModel):
    """Team details with members list."""

    id: str
    name: str
    owner_id: Optional[str] = None
    plan: str = "free"
    members: List[TeamMember] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utcnow)


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
    preferences: Dict[str, bool] = Field(
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
    preferences: Dict[str, bool] = Field(default_factory=dict)
    unsubscribe_token: str = Field("", description="Token for unsubscribe links")


class EmailPreferencesUpdate(BaseModel):
    """Request to update email preferences."""

    preferences: Dict[str, bool] = Field(..., description="Updated email preferences")


class WeeklyDigestContent(BaseModel):
    """Content structure for weekly digest generation."""

    week_ending: datetime = Field(..., description="Week ending date")
    new_tools: List[Dict[str, Any]] = Field(
        default_factory=list, description="New tool discoveries"
    )
    security_alerts: List[Dict[str, Any]] = Field(
        default_factory=list, description="Security alerts and threats"
    )
    trending_categories: List[Dict[str, Any]] = Field(
        default_factory=list, description="Trending tool categories"
    )
    trust_score_changes: List[Dict[str, Any]] = Field(
        default_factory=list, description="Notable trust score changes"
    )
    community_highlights: List[Dict[str, str]] = Field(
        default_factory=list, description="Community submissions and highlights"
    )
    metrics: Dict[str, int] = Field(
        default_factory=dict, description="Weekly metrics (scans, discoveries, etc.)"
    )


class EmailCampaignRequest(BaseModel):
    """Request to send an email campaign."""

    subject: str = Field(..., description="Email subject line")
    content: WeeklyDigestContent = Field(..., description="Email content")
    send_at: Optional[datetime] = Field(None, description="Scheduled send time")
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
    event_data: Dict[str, Any] = Field(
        default_factory=dict, description="Event-specific data payload"
    )
    session_id: Optional[str] = Field(None, description="User session identifier")
    ip_address: Optional[str] = Field(None, description="Source IP address")
    user_agent: Optional[str] = Field(None, description="User agent string")
    timestamp: datetime = Field(default_factory=utcnow)


class PersonalAnalyticsRequest(BaseModel):
    """Request for personal analytics (Pro+ plan)."""

    days_back: int = Field(30, ge=1, le=365, description="Days to look back")
    categories: Optional[List[str]] = Field(None, description="Filter by categories")
    ecosystems: Optional[List[str]] = Field(None, description="Filter by ecosystems")


class PersonalAnalyticsResponse(BaseModel):
    """Personal analytics response for Pro+ users."""

    period_days: int
    total_tool_views: int
    total_tools_tracked: int
    total_searches: int
    total_stacks_created: int

    # Top tools by interaction
    most_viewed_tools: List[Dict[str, Any]] = Field(default_factory=list)
    most_tracked_tools: List[Dict[str, Any]] = Field(default_factory=list)

    # Usage patterns
    discovery_sources: Dict[str, int] = Field(
        default_factory=dict, description="How user finds tools (search, browse, etc.)"
    )
    category_preferences: Dict[str, int] = Field(
        default_factory=dict, description="Category interaction counts"
    )
    ecosystem_usage: Dict[str, int] = Field(
        default_factory=dict, description="Ecosystem interaction counts"
    )

    # Security trends
    trust_score_trends: List[Dict[str, Any]] = Field(
        default_factory=list, description="Trust score changes over time"
    )
    security_findings_timeline: List[Dict[str, Any]] = Field(
        default_factory=list, description="Security findings for tracked tools"
    )

    # Activity patterns
    daily_activity: Dict[str, int] = Field(
        default_factory=dict, description="Activity by day of week"
    )
    hourly_activity: Dict[str, int] = Field(
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
    most_popular_tools: List[Dict[str, Any]] = Field(default_factory=list)
    shared_tool_stacks: List[Dict[str, Any]] = Field(default_factory=list)
    member_activity: List[Dict[str, Any]] = Field(default_factory=list)

    # Team tool adoption
    tool_adoption_timeline: List[Dict[str, Any]] = Field(default_factory=list)
    category_distribution: Dict[str, int] = Field(default_factory=dict)
    ecosystem_distribution: Dict[str, int] = Field(default_factory=dict)

    # Security compliance
    security_compliance_score: float = Field(
        0.0, description="Team security compliance percentage"
    )
    security_findings_summary: Dict[str, int] = Field(default_factory=dict)
    tools_needing_review: List[Dict[str, Any]] = Field(default_factory=list)


class OrganizationAnalyticsResponse(BaseModel):
    """Organization analytics response for Enterprise users."""

    organization_id: str

    # Department breakdown
    departments: List[Dict[str, Any]] = Field(
        default_factory=list, description="Department-level analytics"
    )

    # Cost analysis
    total_tools_in_use: int
    estimated_monthly_costs: Dict[str, float] = Field(
        default_factory=dict, description="Cost estimates by category"
    )
    cost_optimization_opportunities: List[Dict[str, Any]] = Field(default_factory=list)

    # Risk dashboard
    organization_risk_score: float = Field(
        0.0, description="Overall organization security risk"
    )
    high_risk_tools: List[Dict[str, Any]] = Field(default_factory=list)
    compliance_metrics: Dict[str, float] = Field(default_factory=dict)
    security_trends: List[Dict[str, Any]] = Field(default_factory=list)


class AnalyticsEventCreateRequest(BaseModel):
    """Request to track an analytics event."""

    event_type: ForgeEventType
    event_data: Dict[str, Any] = Field(default_factory=dict)
    session_id: Optional[str] = None


class AnalyticsEventBatchRequest(BaseModel):
    """Request to track multiple analytics events in batch."""

    events: List[AnalyticsEventCreateRequest]


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
    custom_tags: List[str] = Field(
        default_factory=list, description="User-defined tags"
    )
    notes: str = Field("", description="User notes about this tool")
    trust_score: float = Field(0.0, description="Current trust score")


class TrackToolRequest(BaseModel):
    """Request to track a tool."""

    tool_id: str = Field(..., description="Package name to track")
    ecosystem: str = Field(..., description="Tool ecosystem")
    is_starred: bool = Field(False, description="Star the tool immediately")
    custom_tags: List[str] = Field(default_factory=list, description="Initial tags")
    notes: str = Field("", description="Initial notes")


class UpdateTrackedToolRequest(BaseModel):
    """Request to update tracked tool metadata."""

    is_starred: Optional[bool] = None
    custom_tags: Optional[List[str]] = None
    notes: Optional[str] = None


class ForgeStack(BaseModel):
    """A custom tool stack created by a user."""

    id: str = Field(..., description="Stack ID")
    name: str = Field(..., description="Stack name")
    description: str = Field("", description="Stack description")
    tools: List[Dict[str, Any]] = Field(
        default_factory=list, description="Tools in stack"
    )
    is_public: bool = Field(False, description="Stack is publicly visible")
    user_id: str = Field(..., description="Creator user ID")
    team_id: Optional[str] = Field(None, description="Associated team ID")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")


class CreateStackRequest(BaseModel):
    """Request to create a new tool stack."""

    name: str = Field(..., max_length=255, description="Stack name")
    description: str = Field("", description="Stack description")
    tools: List[Dict[str, Any]] = Field(..., description="Tools in the stack")
    is_public: bool = Field(False, description="Make stack publicly visible")


class UpdateStackRequest(BaseModel):
    """Request to update an existing stack."""

    name: Optional[str] = None
    description: Optional[str] = None
    tools: Optional[List[Dict[str, Any]]] = None
    is_public: Optional[bool] = None


class AlertSubscription(BaseModel):
    """A user's alert subscription configuration."""

    id: str = Field(..., description="Subscription ID")
    tool_id: Optional[str] = Field(None, description="Specific tool (None = all tools)")
    ecosystem: Optional[str] = Field(
        None, description="Specific ecosystem (None = all)"
    )
    alert_types: List[str] = Field(..., description="Types of alerts to receive")
    channels: Dict[str, bool] = Field(
        default_factory=dict, description="Notification channels"
    )
    is_active: bool = Field(True, description="Subscription is active")
    created_at: datetime = Field(..., description="Creation timestamp")


class CreateAlertSubscriptionRequest(BaseModel):
    """Request to create an alert subscription."""

    tool_id: Optional[str] = Field(None, description="Specific tool (optional)")
    ecosystem: Optional[str] = Field(None, description="Specific ecosystem (optional)")
    alert_types: List[str] = Field(..., description="Alert types to subscribe to")
    channels: Dict[str, bool] = Field(
        default_factory=dict, description="Notification channels"
    )


class UpdateAlertSubscriptionRequest(BaseModel):
    """Request to update an alert subscription."""

    alert_types: Optional[List[str]] = None
    channels: Optional[Dict[str, bool]] = None
    is_active: Optional[bool] = None


class ForgeUserSettings(BaseModel):
    """User's Forge preferences and settings."""

    alert_frequency: str = Field("daily", description="How often to receive alerts")
    alert_types: List[str] = Field(
        default_factory=lambda: ["security", "updates"],
        description="Default alert types",
    )
    delivery_channels: List[str] = Field(
        default_factory=lambda: ["email"], description="Default delivery channels"
    )
    quiet_hours: Optional[Dict[str, str]] = Field(
        None, description="Quiet hours configuration"
    )
    email_notifications: bool = Field(True, description="Enable email notifications")
    slack_notifications: bool = Field(False, description="Enable Slack notifications")
    weekly_digest: bool = Field(True, description="Send weekly digest email")
    created_at: datetime = Field(..., description="Settings creation time")
    updated_at: datetime = Field(..., description="Settings last update")


class UpdateForgeSettingsRequest(BaseModel):
    """Request to update Forge user settings."""

    alert_frequency: Optional[str] = Field(None, pattern="^(instant|daily|weekly)$")
    alert_types: Optional[List[str]] = None
    delivery_channels: Optional[List[str]] = None
    quiet_hours: Optional[Dict[str, str]] = None
    email_notifications: Optional[bool] = None
    slack_notifications: Optional[bool] = None
    weekly_digest: Optional[bool] = None


# Forward-ref update so ScanResponse can reference ThreatEntry
ScanResponse.model_rebuild()
