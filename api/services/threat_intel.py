"""
Sigil API — Threat Intelligence Service

Manages the threat database: hash lookups, pattern signature distribution,
and community-submitted threat reports.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any
from uuid import uuid4

from api.database import cache, db
from api.models import (
    ScanPhase,
    Severity,
    SignatureEntry,
    SignatureResponse,
    ThreatEntry,
    ThreatReport,
    ThreatReportResponse,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Tables / cache key prefixes
# ---------------------------------------------------------------------------
THREAT_TABLE = "threats"
REPORT_TABLE = "threat_reports"
SIGNATURE_TABLE = "signatures"
PUBLISHER_TABLE = "publishers"

_THREAT_CACHE_PREFIX = "threat:"
_SIG_CACHE_KEY = "signatures:all"


# ---------------------------------------------------------------------------
# Built-in signatures (shipped with the service)
# ---------------------------------------------------------------------------

_BUILTIN_SIGNATURES: list[dict[str, Any]] = [
    {
        "id": "sig-install-postinstall",
        "phase": ScanPhase.INSTALL_HOOKS,
        "pattern": r"\"(pre|post)install\"\s*:",
        "severity": Severity.CRITICAL,
        "description": "npm lifecycle hook — preinstall/postinstall",
    },
    {
        "id": "sig-install-cmdclass",
        "phase": ScanPhase.INSTALL_HOOKS,
        "pattern": r"cmdclass\s*=\s*\{",
        "severity": Severity.CRITICAL,
        "description": "Python setup.py cmdclass override",
    },
    {
        "id": "sig-code-eval",
        "phase": ScanPhase.CODE_PATTERNS,
        "pattern": r"\beval\s*\(",
        "severity": Severity.HIGH,
        "description": "Dynamic code execution via eval()",
    },
    {
        "id": "sig-code-exec",
        "phase": ScanPhase.CODE_PATTERNS,
        "pattern": r"\bexec\s*\(",
        "severity": Severity.HIGH,
        "description": "Dynamic code execution via exec()",
    },
    {
        "id": "sig-code-pickle",
        "phase": ScanPhase.CODE_PATTERNS,
        "pattern": r"pickle\.(loads?|Unpickler)\s*\(",
        "severity": Severity.HIGH,
        "description": "Pickle deserialization risk",
    },
    {
        "id": "sig-net-webhook",
        "phase": ScanPhase.NETWORK_EXFIL,
        "pattern": r"(webhook|discord\.com/api/webhooks|hooks\.slack\.com)",
        "severity": Severity.HIGH,
        "description": "Webhook URL — possible exfiltration endpoint",
    },
    {
        "id": "sig-net-socket",
        "phase": ScanPhase.NETWORK_EXFIL,
        "pattern": r"socket\.socket\s*\(",
        "severity": Severity.HIGH,
        "description": "Raw socket creation",
    },
    {
        "id": "sig-cred-private-key",
        "phase": ScanPhase.CREDENTIALS,
        "pattern": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "severity": Severity.CRITICAL,
        "description": "Embedded private key",
    },
    {
        "id": "sig-cred-aws",
        "phase": ScanPhase.CREDENTIALS,
        "pattern": r"AKIA[0-9A-Z]{16}",
        "severity": Severity.CRITICAL,
        "description": "AWS access key ID",
    },
    {
        "id": "sig-obf-base64",
        "phase": ScanPhase.OBFUSCATION,
        "pattern": r"(base64\.(b64decode|decodebytes)|atob)\s*\(",
        "severity": Severity.HIGH,
        "description": "Base64 decoding — payload obfuscation",
    },
    {
        "id": "sig-obf-hex",
        "phase": ScanPhase.OBFUSCATION,
        "pattern": r"(\\x[0-9a-fA-F]{2}){4,}|bytes\.fromhex\s*\(",
        "severity": Severity.HIGH,
        "description": "Hex-encoded data",
    },
]


# ---------------------------------------------------------------------------
# Threat hash lookup
# ---------------------------------------------------------------------------

async def lookup_threat(package_hash: str) -> ThreatEntry | None:
    """Look up a package hash in the threat database.

    Checks Redis cache first, then falls back to Supabase.  Returns ``None``
    when no matching threat is found.
    """
    cache_key = f"{_THREAT_CACHE_PREFIX}{package_hash}"

    # 1. Check cache
    cached = await cache.get(cache_key)
    if cached is not None:
        try:
            return ThreatEntry.model_validate_json(cached)
        except Exception:
            pass

    # 2. Query DB
    row = await db.select_one(THREAT_TABLE, {"hash": package_hash})
    if row is None:
        return None

    entry = ThreatEntry(**row)

    # 3. Populate cache
    await cache.set(cache_key, entry.model_dump_json(), ttl=3600)

    return entry


async def lookup_threats_for_hashes(hashes: list[str]) -> list[ThreatEntry]:
    """Batch lookup — returns all matching threat entries."""
    results: list[ThreatEntry] = []
    for h in hashes:
        entry = await lookup_threat(h)
        if entry is not None:
            results.append(entry)
    return results


# ---------------------------------------------------------------------------
# Pattern signatures (delta sync)
# ---------------------------------------------------------------------------

async def get_signatures(since: datetime | None = None) -> SignatureResponse:
    """Return pattern signatures, optionally filtered to those updated after *since*.

    Includes both DB-stored signatures and the built-in set.
    """
    # Build the full set: built-in + DB-stored
    sigs: list[SignatureEntry] = []

    # Built-in
    now = datetime.utcnow()
    for raw in _BUILTIN_SIGNATURES:
        sigs.append(
            SignatureEntry(
                id=raw["id"],
                phase=raw["phase"],
                pattern=raw["pattern"],
                severity=raw["severity"],
                description=raw.get("description", ""),
                updated_at=now,
            )
        )

    # DB-stored (additive)
    db_rows = await db.select(SIGNATURE_TABLE, limit=1000)
    for row in db_rows:
        try:
            sigs.append(SignatureEntry(**row))
        except Exception:
            logger.warning("Skipping invalid signature row: %s", row)

    # Filter by `since` if provided
    if since is not None:
        sigs = [s for s in sigs if s.updated_at >= since]

    last = max((s.updated_at for s in sigs), default=None) if sigs else None

    return SignatureResponse(
        signatures=sigs,
        total=len(sigs),
        last_updated=last,
    )


# ---------------------------------------------------------------------------
# Community threat reports
# ---------------------------------------------------------------------------

async def submit_report(report: ThreatReport) -> ThreatReportResponse:
    """Persist a user-submitted threat report and return an acknowledgement."""
    report_id = uuid4().hex[:12]

    row = {
        "id": report_id,
        "package_name": report.package_name,
        "package_version": report.package_version,
        "ecosystem": report.ecosystem,
        "reason": report.reason,
        "evidence": report.evidence,
        "reporter_email": report.reporter_email,
        "status": "received",
        "created_at": datetime.utcnow().isoformat(),
    }

    await db.insert(REPORT_TABLE, row)

    logger.info("Threat report %s received for %s", report_id, report.package_name)

    return ThreatReportResponse(
        report_id=report_id,
        status="received",
        message="Thank you for your report. Our team will review it.",
    )


# ---------------------------------------------------------------------------
# Publisher reputation
# ---------------------------------------------------------------------------

async def get_publisher_reputation(publisher_id: str) -> dict[str, Any] | None:
    """Fetch the reputation record for a publisher.

    Returns the raw dict (caller converts to ``PublisherReputation``).
    """
    row = await db.select_one(PUBLISHER_TABLE, {"publisher_id": publisher_id})
    return row
