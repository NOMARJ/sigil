"""
Sigil API — Pydantic Models

Defines all request/response schemas, domain models, and enumerations used
throughout the API.
"""

from __future__ import annotations

import enum
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Verdict(str, enum.Enum):
    """Overall risk verdict derived from the aggregate score."""

    CLEAN = "CLEAN"
    LOW_RISK = "LOW_RISK"
    MEDIUM_RISK = "MEDIUM_RISK"
    HIGH_RISK = "HIGH_RISK"
    CRITICAL = "CRITICAL"


class Severity(str, enum.Enum):
    """Individual finding severity level."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ScanPhase(str, enum.Enum):
    """The six scan phases defined in the Sigil PRD."""

    INSTALL_HOOKS = "install_hooks"
    CODE_PATTERNS = "code_patterns"
    NETWORK_EXFIL = "network_exfil"
    CREDENTIALS = "credentials"
    OBFUSCATION = "obfuscation"
    PROVENANCE = "provenance"


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
    findings: list[Finding] = Field(default_factory=list, description="Raw findings list")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Arbitrary scan metadata")


class ScanResponse(BaseModel):
    """Response returned from POST /v1/scan after enrichment."""

    scan_id: str = Field(..., description="Unique identifier for this scan")
    target: str
    target_type: str
    files_scanned: int = 0
    findings: list[Finding] = Field(default_factory=list)
    risk_score: float = Field(0.0, description="Aggregate weighted risk score")
    verdict: Verdict = Field(Verdict.CLEAN, description="Overall risk verdict")
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
    source: str = Field("community", description="Intel source (community, nvd, internal)")
    confirmed_at: datetime | None = Field(None, description="When the threat was confirmed")
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

    publisher_id: str = Field(..., description="Publisher identifier (npm username, PyPI user, etc.)")
    trust_score: float = Field(
        100.0,
        ge=0.0,
        le=100.0,
        description="Trust score from 0 (untrusted) to 100 (fully trusted)",
    )
    total_packages: int = Field(0, description="Total packages published")
    flagged_count: int = Field(0, description="Number of packages flagged as suspicious")
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
    artifact_hash: str = Field("", description="SHA-256 hash of the distribution artifact")


class VerifyResponse(BaseModel):
    """Verification result for a marketplace badge request."""

    package_name: str
    package_version: str
    verified: bool = Field(False, description="Whether the package passed verification")
    verdict: Verdict = Field(Verdict.CLEAN)
    risk_score: float = 0.0
    badge_url: str | None = Field(None, description="URL to the Sigil-verified badge if approved")
    findings_summary: str = Field("", description="Brief summary of any findings")
    verified_at: datetime = Field(default_factory=datetime.utcnow)


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
    """Public-safe user representation."""

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
# Generic helpers
# ---------------------------------------------------------------------------

class ErrorResponse(BaseModel):
    """Standard error body."""

    detail: str


# Forward-ref update so ScanResponse can reference ThreatEntry
ScanResponse.model_rebuild()
