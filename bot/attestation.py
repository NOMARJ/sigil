"""
Attestation signing module for Sigil bot.

Implements:
- Ed25519 keypair generation
- in-toto Statement v1 building with custom Sigil scan predicate
- DSSE (Dead Simple Signing Envelope) wrapping
- Content digest computation (SHA-256 of canonical scan JSON)
- Per-finding digest computation
- Optional Rekor transparency log submission
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from datetime import datetime
import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

logger = logging.getLogger(__name__)

# Constants
INTOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
SIGIL_PREDICATE_TYPE = "https://sigilsec.ai/attestation/scan/v1"
DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"
REKOR_API_ENDPOINT = "https://rekor.sigstore.dev/api/v1/log/entries"


def _canonical_json(obj: dict) -> bytes:
    """
    Deterministic JSON serialization.

    Uses sorted keys, no whitespace, ensure_ascii=False for reproducible hashes.

    Args:
        obj: Dictionary to serialize

    Returns:
        UTF-8 encoded canonical JSON bytes
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=False,
    ).encode('utf-8')


def compute_content_digest(scan_data: dict) -> str:
    """
    Compute SHA-256 hex digest of the canonical scan JSON.

    Args:
        scan_data: The scan result dictionary

    Returns:
        SHA-256 hex digest string
    """
    canonical = _canonical_json(scan_data)
    return hashlib.sha256(canonical).hexdigest()


def compute_finding_digest(finding: dict) -> str:
    """
    Compute SHA-256 of file:line:snippet for finding-level integrity.

    Args:
        finding: Finding dictionary with file, line, snippet fields

    Returns:
        SHA-256 hex digest string
    """
    file_path = finding.get('file', '')
    line = finding.get('line', 0)
    snippet = finding.get('snippet', '')

    content = f"{file_path}:{line}:{snippet}"
    return hashlib.sha256(content.encode('utf-8')).hexdigest()


def build_intoto_statement(
    scan_id: str,
    ecosystem: str,
    package_name: str,
    package_version: str,
    subject_digest: str,
    verdict: str,
    risk_score: float,
    findings: list[dict],
    files_scanned: int,
    duration_ms: int,
    metadata: dict,
    scanner_version: str = "1.0.0",
    transparency: dict | None = None,
) -> dict:
    """
    Build the in-toto Statement v1 with Sigil scan predicate.

    Args:
        scan_id: Unique scan identifier
        ecosystem: Package ecosystem (npm, pypi, clawhub, github)
        package_name: Package name
        package_version: Package version
        subject_digest: SHA-256 digest of the package archive
        verdict: Scan verdict (safe, suspicious, malicious)
        risk_score: Risk score (0.0-1.0)
        findings: List of finding dictionaries
        files_scanned: Number of files scanned
        duration_ms: Scan duration in milliseconds
        metadata: Additional metadata
        scanner_version: Scanner version string
        transparency: Optional transparency log info

    Returns:
        in-toto Statement v1 dictionary
    """
    # Compute finding digests
    findings_with_digests = []
    for finding in findings:
        finding_copy = finding.copy()
        finding_copy['digest'] = compute_finding_digest(finding)
        findings_with_digests.append(finding_copy)

    # Build subject (spec: {ecosystem}/{package_name}@{version})
    subject = {
        "name": f"{ecosystem}/{package_name}@{package_version}",
        "digest": {
            "sha256": subject_digest
        }
    }

    # Scan phases that were executed
    phases = [
        "install_hooks", "code_patterns", "network_exfil",
        "credentials", "obfuscation", "provenance",
        "prompt_injection", "skill_security",
    ]

    scanned_at = datetime.utcnow().isoformat() + "Z"

    # Build predicate (spec-compliant structure)
    predicate = {
        "scanner": {
            "uri": "https://github.com/NOMARJ/sigil",
            "version": scanner_version,
            "phases": phases,
        },
        "scan": {
            "id": scan_id,
            "ecosystem": ecosystem,
            "package_name": package_name,
            "package_version": package_version,
            "verdict": verdict,
            "risk_score": risk_score,
            "findings_count": len(findings),
            "files_scanned": files_scanned,
            "duration_ms": duration_ms,
        },
        "findings": findings_with_digests,
        "metadata": {
            "source": metadata.get("source", "sigil-bot"),
            "bot_scan": metadata.get("bot_scan", True),
            "scanned_at": scanned_at,
            "content_hash_algorithm": "sha256",
            "content_hash": compute_content_digest(
                {"findings": findings, "verdict": verdict, "risk_score": risk_score}
            ),
            **{k: v for k, v in metadata.items()
               if k in ("registry_url", "repository_url", "published_at",
                         "download_count", "description", "keywords")},
        },
    }

    # Add transparency info if provided
    if transparency:
        predicate["transparency"] = transparency

    # Build statement
    statement = {
        "_type": INTOTO_STATEMENT_TYPE,
        "subject": [subject],
        "predicateType": SIGIL_PREDICATE_TYPE,
        "predicate": predicate
    }

    return statement


def _build_pae(payload_type: str, payload: bytes) -> bytes:
    """Build DSSE Pre-Authentication Encoding per spec.

    PAE(type, body) = "DSSEv1" + SP + LEN(type) + SP + type + SP + LEN(body) + SP + body
    """
    return (
        b"DSSEv1 "
        + str(len(payload_type)).encode('ascii')
        + b" "
        + payload_type.encode('ascii')
        + b" "
        + str(len(payload)).encode('ascii')
        + b" "
        + payload
    )


def sign_dsse(statement: dict, private_key: ed25519.Ed25519PrivateKey, key_id: str) -> dict:
    """Sign the statement with DSSE envelope using Ed25519."""
    statement_json = _canonical_json(statement)
    payload_b64 = base64.urlsafe_b64encode(statement_json).decode('ascii').rstrip('=')

    pae = _build_pae(DSSE_PAYLOAD_TYPE, statement_json)
    signature_bytes = private_key.sign(pae)
    signature_b64 = base64.urlsafe_b64encode(signature_bytes).decode('ascii').rstrip('=')

    return {
        "payload": payload_b64,
        "payloadType": DSSE_PAYLOAD_TYPE,
        "signatures": [{"keyid": key_id, "sig": signature_b64}],
    }


async def submit_to_rekor(dsse_envelope: dict, public_key_pem: bytes) -> dict | None:
    """
    Submit the signed envelope to Sigstore Rekor transparency log.

    Args:
        dsse_envelope: DSSE envelope dictionary
        public_key_pem: Public key in PEM format

    Returns:
        Log entry info dictionary or None on failure
    """
    try:
        # Build Rekor entry
        entry = {
            "kind": "dsse",
            "apiVersion": "0.0.1",
            "spec": {
                "proposedContent": {
                    "envelope": dsse_envelope,
                    "verifiers": [public_key_pem.decode('ascii')]
                }
            }
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                REKOR_API_ENDPOINT,
                json=entry,
                headers={"Content-Type": "application/json"}
            )

            if response.status_code == 201:
                # Extract log entry ID from response
                location = response.headers.get('Location', '')
                log_entry_id = location.split('/')[-1] if location else None

                result = {
                    "log_entry_id": log_entry_id,
                    "log_index": response.json().get('logIndex'),
                    "integrated_time": response.json().get('integratedTime'),
                }

                logger.info(f"Successfully submitted to Rekor: {log_entry_id}")
                return result
            else:
                logger.warning(
                    f"Rekor submission failed: {response.status_code} - {response.text}"
                )
                return None

    except Exception as e:
        logger.warning(f"Failed to submit to Rekor: {e}")
        return None


def generate_keypair() -> tuple[bytes, bytes]:
    """
    Generate a new Ed25519 keypair.

    Returns:
        Tuple of (private_key_bytes, public_key_pem)
    """
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Serialize private key (32 bytes raw)
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serialize public key (PEM format)
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key_bytes, public_key_pem


def verify_attestation(dsse_envelope: dict, public_key_pem: bytes) -> bool:
    """
    Verify a DSSE envelope signature against a public key.

    Args:
        dsse_envelope: DSSE envelope dictionary
        public_key_pem: Public key in PEM format

    Returns:
        True if signature is valid, False otherwise
    """
    try:
        # Load public key
        public_key = serialization.load_pem_public_key(public_key_pem)
        if not isinstance(public_key, ed25519.Ed25519PublicKey):
            logger.error("Public key is not Ed25519")
            return False

        # Extract payload and signature
        payload_b64 = dsse_envelope.get('payload', '')
        signatures = dsse_envelope.get('signatures', [])

        if not signatures:
            logger.error("No signatures in envelope")
            return False

        signature_b64 = signatures[0].get('sig', '')

        # Decode payload (add padding if needed)
        payload_b64_padded = payload_b64 + '=' * (4 - len(payload_b64) % 4)
        payload = base64.urlsafe_b64decode(payload_b64_padded)

        # Decode signature (add padding if needed)
        signature_b64_padded = signature_b64 + '=' * (4 - len(signature_b64) % 4)
        signature = base64.urlsafe_b64decode(signature_b64_padded)

        # Rebuild PAE and verify
        payload_type = dsse_envelope.get('payloadType', DSSE_PAYLOAD_TYPE)
        pae = _build_pae(payload_type, payload)
        public_key.verify(signature, pae)
        return True

    except Exception as e:
        logger.error(f"Signature verification failed: {e}")
        return False


async def create_attestation(
    scan_id: str,
    ecosystem: str,
    package_name: str,
    package_version: str,
    subject_digest: str,
    scan_output: dict,
    metadata: dict,
) -> tuple[dict, str, str | None]:
    """
    Main entry point for creating attestations.

    Loads signing key, builds statement, signs, optionally submits to Rekor.

    Args:
        scan_id: Unique scan identifier
        ecosystem: Package ecosystem
        package_name: Package name
        package_version: Package version
        subject_digest: SHA-256 of the package archive
        scan_output: Scan result dictionary
        metadata: Additional metadata

    Returns:
        Tuple of (dsse_envelope, content_digest, log_entry_id)
        log_entry_id is None if Rekor is disabled or submission fails

    Raises:
        ValueError: If signing key is not configured
    """
    # Load signing key from centralized config
    from bot.config import bot_settings

    private_key_bytes = None

    # Try base64-encoded key from config
    if bot_settings.signing_key:
        try:
            private_key_bytes = base64.b64decode(bot_settings.signing_key)
            if len(private_key_bytes) != 32:
                raise ValueError(f"Ed25519 key must be 32 bytes, got {len(private_key_bytes)}")
            logger.info("Loaded signing key from config (SIGIL_BOT_SIGNING_KEY)")
        except Exception as e:
            logger.error("Failed to decode signing key from config: %s", e)

    # Fallback to file path
    if not private_key_bytes and bot_settings.signing_key_file:
        try:
            with open(bot_settings.signing_key_file, 'rb') as f:
                private_key_bytes = f.read()
            logger.info("Loaded signing key from %s", bot_settings.signing_key_file)
        except Exception as e:
            logger.error("Failed to load signing key from file: %s", e)

    if not private_key_bytes:
        raise ValueError(
            "Signing key not configured. Set SIGIL_BOT_SIGNING_KEY or "
            "SIGIL_BOT_SIGNING_KEY_FILE environment variable."
        )

    # Load private key
    try:
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        public_key = private_key.public_key()

        # Serialize public key for Rekor
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    except Exception as e:
        logger.error(f"Failed to load Ed25519 key: {e}")
        raise ValueError(f"Invalid Ed25519 signing key: {e}")

    # Key ID from config
    key_id = bot_settings.signing_key_id

    # Extract scan data
    verdict = scan_output.get('verdict', 'unknown')
    risk_score = scan_output.get('risk_score', 0.0)
    findings = scan_output.get('findings', [])
    files_scanned = scan_output.get('files_scanned', 0)
    duration_ms = scan_output.get('duration_ms', 0)
    scanner_version = metadata.get('scanner_version', '1.0.0')

    # Compute content digest
    content_digest = compute_content_digest(scan_output)

    # Build in-toto statement
    statement = build_intoto_statement(
        scan_id=scan_id,
        ecosystem=ecosystem,
        package_name=package_name,
        package_version=package_version,
        subject_digest=subject_digest,
        verdict=verdict,
        risk_score=risk_score,
        findings=findings,
        files_scanned=files_scanned,
        duration_ms=duration_ms,
        metadata=metadata,
        scanner_version=scanner_version,
    )

    # Sign with DSSE
    dsse_envelope = sign_dsse(statement, private_key, key_id)

    # Optionally submit to Rekor
    log_entry_id = None

    if bot_settings.rekor_enabled:
        logger.info("Rekor transparency log enabled, submitting attestation")
        rekor_result = await submit_to_rekor(dsse_envelope, public_key_pem)

        if rekor_result:
            log_entry_id = rekor_result.get('log_entry_id')

            # Update statement with transparency info
            transparency = {
                "log_entry_id": log_entry_id,
                "log_index": rekor_result.get('log_index'),
                "integrated_time": rekor_result.get('integrated_time'),
            }

            # Rebuild statement with transparency info
            statement = build_intoto_statement(
                scan_id=scan_id,
                ecosystem=ecosystem,
                package_name=package_name,
                package_version=package_version,
                subject_digest=subject_digest,
                verdict=verdict,
                risk_score=risk_score,
                findings=findings,
                files_scanned=files_scanned,
                duration_ms=duration_ms,
                metadata=metadata,
                scanner_version=scanner_version,
                transparency=transparency,
            )

            # Re-sign with updated statement
            dsse_envelope = sign_dsse(statement, private_key, key_id)
    else:
        logger.info("Rekor transparency log disabled")

    return dsse_envelope, content_digest, log_entry_id
