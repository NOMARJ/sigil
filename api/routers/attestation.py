"""
Sigil API — Attestation Router

Serves and verifies scan attestations using DSSE envelopes and Sigstore transparency.

GET  /api/v1/attestation/{scan_id}   — Retrieve DSSE envelope for a scan
POST /api/v1/verify                  — Verify an attestation signature
GET  /.well-known/sigil-verify.json  — Public key and verification instructions
"""

from __future__ import annotations

import base64
import json
import logging
import os
from typing import Any
from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel

from api.database import db

logger = logging.getLogger(__name__)

router = APIRouter(tags=["attestation"])

# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------


class VerifyRequest(BaseModel):
    """Request to verify an attestation by scan_id or content_digest."""

    scan_id: str | None = None
    content_digest: str | None = None


class VerifyResponse(BaseModel):
    """Response from attestation verification."""

    verified: bool
    scan_id: str | None = None
    signed_at: str | None = None
    log_entry: str | None = None
    key_id: str | None = None
    error: str | None = None


# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------


def _load_public_key() -> str | None:
    """Load the public key PEM from environment variables.

    Checks SIGIL_BOT_PUBLIC_KEY (base64 encoded) or SIGIL_BOT_PUBLIC_KEY_FILE (file path).
    Returns the PEM string or None if not configured.
    """
    # Try base64 encoded env var first
    b64_key = os.getenv("SIGIL_BOT_PUBLIC_KEY")
    if b64_key:
        try:
            return base64.b64decode(b64_key).decode("utf-8")
        except Exception as e:
            logger.error(f"Failed to decode SIGIL_BOT_PUBLIC_KEY: {e}")
            return None

    # Try file path
    key_file = os.getenv("SIGIL_BOT_PUBLIC_KEY_FILE")
    if key_file:
        try:
            with open(key_file, "r") as f:
                return f.read()
        except Exception as e:
            logger.error(f"Failed to read public key from {key_file}: {e}")
            return None

    return None


def _verify_envelope(envelope: dict[str, Any], public_key_pem: str) -> bool:
    """Verify a DSSE envelope signature using bot.attestation.

    Args:
        envelope: The DSSE envelope to verify
        public_key_pem: The public key PEM string

    Returns:
        True if signature is valid, False otherwise
    """
    try:
        from bot.attestation import verify_attestation

        return verify_attestation(envelope, public_key_pem.encode("utf-8"))
    except ImportError:
        logger.warning("bot.attestation not available — verification disabled")
        return False
    except Exception as e:
        logger.error("Attestation verification error: %s", e)
        return False


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/api/v1/attestation/{scan_id}",
    response_class=Response,
    summary="Retrieve attestation for a scan",
    responses={
        200: {
            "description": "DSSE envelope in in-toto format",
            "content": {"application/vnd.in-toto+json": {}},
        },
        404: {"description": "Scan not found or no attestation available"},
    },
)
async def get_attestation(scan_id: str) -> Response:
    """Retrieve the DSSE attestation envelope for a specific scan.

    The attestation is a signed DSSE envelope containing the scan results
    and metadata. It can be verified independently using the public key
    available at /.well-known/sigil-verify.json.

    Args:
        scan_id: The unique identifier of the scan

    Returns:
        Response with Content-Type: application/vnd.in-toto+json containing the DSSE envelope

    Raises:
        HTTPException: 404 if scan not found or has no attestation
    """
    # Look up the scan in public_scans table
    scan = await db.select_one("public_scans", {"id": scan_id})

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    attestation = scan.get("attestation")
    if not attestation:
        raise HTTPException(
            status_code=404, detail="No attestation available for this scan"
        )

    # Parse the attestation if it's a JSON string
    if isinstance(attestation, str):
        try:
            attestation = json.loads(attestation)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse attestation for scan {scan_id}: {e}")
            raise HTTPException(status_code=500, detail="Invalid attestation format")

    # Return as in-toto DSSE format
    return Response(
        content=json.dumps(attestation, indent=2),
        media_type="application/vnd.in-toto+json",
    )


@router.post(
    "/api/v1/verify",
    response_model=VerifyResponse,
    summary="Verify an attestation signature",
)
async def verify(request: VerifyRequest) -> VerifyResponse:
    """Verify the cryptographic signature of a scan attestation.

    This endpoint performs server-side verification of the attestation signature
    using the public key. Clients can also verify attestations independently.

    Args:
        request: Contains either scan_id or content_digest to look up the attestation

    Returns:
        VerifyResponse with verification status and details

    Raises:
        HTTPException: 400 if neither scan_id nor content_digest provided
        HTTPException: 404 if scan not found
    """
    # Validate request
    if not request.scan_id and not request.content_digest:
        raise HTTPException(
            status_code=400,
            detail="Either scan_id or content_digest must be provided",
        )

    # Load public key
    public_key_pem = _load_public_key()
    if not public_key_pem:
        return VerifyResponse(
            verified=False,
            error="Public key not configured",
        )

    # Look up the scan
    if request.scan_id:
        scan = await db.select_one("public_scans", {"id": request.scan_id})
    else:
        scan = await db.select_one(
            "public_scans", {"content_digest": request.content_digest}
        )

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    attestation = scan.get("attestation")
    if not attestation:
        return VerifyResponse(
            verified=False,
            scan_id=scan.get("id"),
            error="No attestation available for this scan",
        )

    # Parse the attestation if it's a JSON string
    if isinstance(attestation, str):
        try:
            attestation = json.loads(attestation)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse attestation: {e}")
            return VerifyResponse(
                verified=False,
                scan_id=scan.get("id"),
                error="Invalid attestation format",
            )

    # Verify the DSSE signature
    verified = _verify_envelope(attestation, public_key_pem)

    # Extract key ID from the envelope signatures
    sigs = attestation.get("signatures", [])
    key_id = sigs[0].get("keyid") if sigs else None

    return VerifyResponse(
        verified=verified,
        scan_id=scan.get("id"),
        signed_at=str(scan.get("scanned_at", "")),
        log_entry=scan.get("log_entry_id"),
        key_id=key_id,
    )


@router.get(
    "/.well-known/sigil-verify.json",
    response_class=JSONResponse,
    summary="Public key and verification instructions",
)
async def well_known_verify() -> JSONResponse:
    """Serve the public key and verification instructions for Sigil attestations.

    This endpoint provides all the information needed to independently verify
    scan attestations, including the public key, predicate type, transparency
    log details, and SDK/CLI usage instructions.

    Returns:
        JSONResponse with verification metadata and public key
    """
    public_key_pem = _load_public_key()

    keys = []
    if public_key_pem:
        # Base64-DER encode the public key for the well-known response
        pub_b64 = base64.b64encode(public_key_pem.encode("utf-8")).decode("ascii")
        keys.append(
            {
                "keyId": os.getenv(
                    "SIGIL_BOT_SIGNING_KEY_ID", "sha256:sigil-bot-signing-key-2026"
                ),
                "algorithm": "Ed25519",
                "publicKey": pub_b64,
                "encoding": "base64-pem",
                "validFrom": "2026-01-01T00:00:00Z",
                "validUntil": None,
                "status": "active",
            }
        )

    response = {
        "schema": "https://sigilsec.ai/attestation/verify/v1",
        "issuer": "NOMARK Pty Ltd",
        "product": "Sigil",
        "description": "Public keys and verification instructions for Sigil scan attestations.",
        "keys": keys,
        "predicateType": "https://sigilsec.ai/attestation/scan/v1",
        "transparencyLog": {
            "uri": "https://rekor.sigstore.dev",
            "type": "rekor",
        },
        "verification": {
            "steps": [
                "Fetch the scan attestation from /api/v1/feed (included in each result) or /api/v1/attestation/{scan_id}",
                "Decode the DSSE envelope payload (base64url -> JSON)",
                "Verify the in-toto Statement _type is 'https://in-toto.io/Statement/v1'",
                "Verify the predicateType is 'https://sigilsec.ai/attestation/scan/v1'",
                "Verify the subject digest matches the package archive hash from the registry",
                "Verify the DSSE signature against this public key",
                "Optionally verify the transparency log entry at the log_uri + log_entry_id",
            ],
            "sdks": {
                "node": "npm install @nomarj/sigil-verify",
                "python": "pip install sigil-verify",
                "cli": "sigil verify --attestation <path-or-url>",
            },
        },
        "lastUpdated": "2026-03-01T00:00:00Z",
    }

    return JSONResponse(content=response)
