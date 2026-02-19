"""
Sigil API — Threat Intelligence Service

Manages the threat database: hash lookups, pattern signature distribution,
community-submitted threat reports, report review workflow, and publisher
reputation enrichment from scan telemetry.
"""

from __future__ import annotations

import hashlib
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


# ---------------------------------------------------------------------------
# Paginated threat listing (dashboard)
# ---------------------------------------------------------------------------


async def list_threats(
    *,
    severity: str | None = None,
    source: str | None = None,
    search: str | None = None,
    page: int = 1,
    per_page: int = 20,
) -> dict[str, Any]:
    """Return a paginated list of threats with optional filters."""
    filters: dict[str, Any] = {}
    if severity:
        filters["severity"] = severity
    if source:
        filters["source"] = source

    rows = await db.select(THREAT_TABLE, filters if filters else None, limit=1000)

    if search:
        search_lower = search.lower()
        rows = [
            r
            for r in rows
            if search_lower in r.get("package_name", "").lower()
            or search_lower in r.get("description", "").lower()
        ]

    rows.sort(key=lambda r: r.get("created_at", ""), reverse=True)
    total = len(rows)
    start = (page - 1) * per_page
    items = rows[start : start + per_page]

    return {
        "items": items,
        "total": total,
        "page": page,
        "per_page": per_page,
        "has_more": (start + per_page) < total,
    }


# ---------------------------------------------------------------------------
# Threat report review workflow
# ---------------------------------------------------------------------------

VALID_REPORT_TRANSITIONS: dict[str, list[str]] = {
    "received": ["under_review", "rejected"],
    "under_review": ["confirmed", "rejected"],
    "confirmed": [],
    "rejected": [],
}


async def list_reports(
    *,
    status: str | None = None,
    page: int = 1,
    per_page: int = 20,
) -> dict[str, Any]:
    """Return a paginated list of threat reports with optional status filter."""
    filters: dict[str, Any] = {}
    if status:
        filters["status"] = status

    rows = await db.select(REPORT_TABLE, filters if filters else None, limit=1000)
    rows.sort(key=lambda r: r.get("created_at", ""), reverse=True)

    total = len(rows)
    start = (page - 1) * per_page
    items = rows[start : start + per_page]

    return {
        "items": items,
        "total": total,
        "page": page,
        "per_page": per_page,
        "has_more": (start + per_page) < total,
    }


async def get_report(report_id: str) -> dict[str, Any] | None:
    """Fetch a single threat report by ID."""
    return await db.select_one(REPORT_TABLE, {"id": report_id})


async def update_report_status(
    report_id: str,
    new_status: str,
    reviewer_id: str | None = None,
    notes: str = "",
) -> dict[str, Any]:
    """Transition a report to a new status.

    Validates the transition is legal.  When the new status is ``confirmed``,
    the report is promoted: a threat entry is created in the threats table and
    a detection signature is generated.
    """
    row = await db.select_one(REPORT_TABLE, {"id": report_id})
    if row is None:
        raise ValueError(f"Report '{report_id}' not found")

    current_status = row.get("status", "received")
    allowed = VALID_REPORT_TRANSITIONS.get(current_status, [])
    if new_status not in allowed:
        raise ValueError(
            f"Cannot transition report from '{current_status}' to '{new_status}'. "
            f"Allowed: {allowed}"
        )

    row["status"] = new_status
    if reviewer_id:
        row["reviewer_id"] = reviewer_id
    if notes:
        row["review_notes"] = notes
    row["reviewed_at"] = datetime.utcnow().isoformat()

    await db.upsert(REPORT_TABLE, row)

    logger.info(
        "Report %s transitioned %s -> %s by %s",
        report_id,
        current_status,
        new_status,
        reviewer_id or "system",
    )

    # If confirmed, promote to threats table and create a signature
    if new_status == "confirmed":
        await _promote_report_to_threat(row)

    return row


async def _promote_report_to_threat(report: dict[str, Any]) -> None:
    """Create a threat entry and a detection signature from a confirmed report."""
    package_name = report.get("package_name", "")
    ecosystem = report.get("ecosystem", "unknown")
    now = datetime.utcnow()

    # Create a synthetic hash from the package identity
    pkg_identity = f"{ecosystem}:{package_name}:{report.get('package_version', '')}"
    pkg_hash = hashlib.sha256(pkg_identity.encode()).hexdigest()

    threat_id = uuid4().hex[:16]
    threat_row = {
        "id": threat_id,
        "hash": pkg_hash,
        "package_name": package_name,
        "version": report.get("package_version", ""),
        "severity": "CRITICAL",
        "source": "community",
        "confirmed_at": now.isoformat(),
        "description": report.get("reason", "Community-confirmed threat"),
        "created_at": now.isoformat(),
    }

    try:
        await db.insert(THREAT_TABLE, threat_row)
        logger.info("Promoted report to threat: %s (hash=%s)", package_name, pkg_hash)
    except Exception:
        logger.exception("Failed to create threat entry for %s", package_name)

    # Create a detection signature from the report evidence
    evidence = report.get("evidence", "")
    if evidence:
        sig_id = f"sig-community-{threat_id}"
        sig_row = {
            "id": sig_id,
            "phase": "code_patterns",
            "pattern": _evidence_to_pattern(package_name, evidence),
            "severity": "CRITICAL",
            "description": f"Community-reported: {report.get('reason', '')[:200]}",
            "updated_at": now.isoformat(),
        }

        try:
            await db.insert(SIGNATURE_TABLE, sig_row)
            logger.info("Created signature %s from confirmed report", sig_id)
        except Exception:
            logger.exception("Failed to create signature from report")

    # Invalidate caches
    await cache.delete(_SIG_CACHE_KEY)
    await cache.delete(f"{_THREAT_CACHE_PREFIX}{pkg_hash}")


def _evidence_to_pattern(package_name: str, evidence: str) -> str:
    """Convert report evidence into a regex pattern.

    Falls back to matching the package name import if evidence is not
    a usable regex.
    """
    import re

    # If evidence looks like a regex (contains metacharacters), use it directly
    if any(c in evidence for c in r"[]()*+?{}|\\^$"):
        try:
            re.compile(evidence)
            return evidence
        except re.error:
            pass

    # Otherwise, create a pattern that matches the package import
    safe_name = re.escape(package_name)
    return rf"(import\s+{safe_name}|require\s*\(\s*['\"]({safe_name})['\"])"


# ---------------------------------------------------------------------------
# Signature CRUD
# ---------------------------------------------------------------------------


async def upsert_signature(
    sig_id: str,
    phase: str,
    pattern: str,
    severity: str,
    description: str = "",
) -> dict[str, Any]:
    """Create or update a detection signature."""
    now = datetime.utcnow()
    row = {
        "id": sig_id,
        "phase": phase,
        "pattern": pattern,
        "severity": severity,
        "description": description,
        "updated_at": now.isoformat(),
    }
    result = await db.upsert(SIGNATURE_TABLE, row)
    await cache.delete(_SIG_CACHE_KEY)
    logger.info("Upserted signature %s (phase=%s)", sig_id, phase)
    return result


async def delete_signature(sig_id: str) -> bool:
    """Remove a signature from the DB. Returns True if it existed."""
    row = await db.select_one(SIGNATURE_TABLE, {"id": sig_id})
    if row is None:
        return False
    # In-memory store: remove directly
    from api.database import _memory_store

    table = _memory_store.get(SIGNATURE_TABLE, {})
    table.pop(sig_id, None)
    await cache.delete(_SIG_CACHE_KEY)
    logger.info("Deleted signature %s", sig_id)
    return True


# ---------------------------------------------------------------------------
# Publisher reputation enrichment from scan telemetry
# ---------------------------------------------------------------------------


async def update_publisher_from_scan(
    publisher_id: str,
    *,
    is_flagged: bool = False,
) -> dict[str, Any]:
    """Update a publisher's reputation based on scan results.

    Called after each scan that can be attributed to a publisher.
    Increments package count, updates last_active, and adjusts trust score.
    """
    now = datetime.utcnow()
    row = await db.select_one(PUBLISHER_TABLE, {"publisher_id": publisher_id})

    if row is None:
        row = {
            "id": uuid4().hex[:16],
            "publisher_id": publisher_id,
            "trust_score": 100.0,
            "total_packages": 0,
            "flagged_count": 0,
            "first_seen": now.isoformat(),
            "last_active": now.isoformat(),
            "notes": "",
        }

    row["total_packages"] = row.get("total_packages", 0) + 1
    row["last_active"] = now.isoformat()

    if is_flagged:
        row["flagged_count"] = row.get("flagged_count", 0) + 1
        # Decrease trust score (floor at 0)
        current_trust = row.get("trust_score", 100.0)
        row["trust_score"] = max(0.0, current_trust - 15.0)
    else:
        # Clean scan: nudge trust score up slightly (cap at 100)
        current_trust = row.get("trust_score", 100.0)
        row["trust_score"] = min(100.0, current_trust + 1.0)

    result = await db.upsert(PUBLISHER_TABLE, row)

    logger.info(
        "Publisher %s updated: trust=%.1f packages=%d flagged=%d",
        publisher_id,
        row["trust_score"],
        row["total_packages"],
        row["flagged_count"],
    )

    return result
