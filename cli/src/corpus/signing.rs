//! Pack signature verification using Ed25519 (ed25519-dalek).
//!
//! Packs may carry an optional `"signature"` key in their `meta` block.
//! When a verified public key is configured, the loader passes packs through
//! [`verify_pack`] before accepting them.  A tampered pack (wrong signature,
//! missing signature when required, or malformed key material) is rejected and
//! never surfaced to the engine.
//!
//! # Signing format
//!
//! The signature is produced over the canonical form of the pack JSON *without*
//! the `meta.signature` field (i.e. the pack content as it would appear before
//! signing).  The canonical form is:
//!
//! 1. Deserialise the raw JSON bytes.
//! 2. Remove `meta.signature` from the value tree.
//! 3. Re-serialise with `serde_json::to_string` (compact, key-sorted is NOT
//!    required — the verifier uses the same canonical form as the signer).
//!
//! The signature bytes are Base64-encoded (standard alphabet, no padding
//! stripped) and stored as a string in `meta.signature`.
//!
//! # Example (tool-side signing, not part of the scanner binary)
//!
//! ```text
//! # Pseudocode — signing lives in a separate offline tool, not here
//! let canonical = remove_signature_field(&pack_json);
//! let sig = signing_key.sign(canonical.as_bytes());
//! pack_json["meta"]["signature"] = base64::encode(sig.to_bytes());
//! ```
//!
//! # Example (verification)
//!
//! ```no_run
//! use sigil_cli::corpus::signing::{PackVerifier, VerifyError};
//!
//! let verifier = PackVerifier::from_public_key_bytes(&PUBLIC_KEY_BYTES).unwrap();
//! verifier.verify(raw_pack_json).unwrap();
//! ```

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors returned by pack signature verification.
#[derive(Debug)]
#[allow(dead_code)]
pub enum VerifyError {
    /// The raw JSON could not be parsed.
    InvalidJson(serde_json::Error),
    /// The public key bytes are malformed.
    InvalidPublicKey(ed25519_dalek::SignatureError),
    /// The signature field is missing from `meta`.
    MissingSignature,
    /// The signature field is not valid Base64.
    InvalidBase64(base64::DecodeError),
    /// The signature bytes do not form a valid Ed25519 signature.
    InvalidSignatureBytes(ed25519_dalek::SignatureError),
    /// The signature does not match the pack content.
    SignatureMismatch(ed25519_dalek::SignatureError),
    /// The canonical form of the pack could not be re-serialised.
    CanonicaliseError(serde_json::Error),
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::InvalidJson(e) => write!(f, "pack JSON parse error: {e}"),
            VerifyError::InvalidPublicKey(e) => write!(f, "invalid public key: {e}"),
            VerifyError::MissingSignature => write!(f, "pack is missing meta.signature"),
            VerifyError::InvalidBase64(e) => write!(f, "meta.signature is not valid base64: {e}"),
            VerifyError::InvalidSignatureBytes(e) => write!(f, "signature bytes malformed: {e}"),
            VerifyError::SignatureMismatch(e) => write!(f, "signature mismatch: {e}"),
            VerifyError::CanonicaliseError(e) => {
                write!(f, "failed to canonicalise pack for verification: {e}")
            }
        }
    }
}

impl std::error::Error for VerifyError {}

// ---------------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------------

/// Holds an Ed25519 verifying key and verifies pack signatures.
#[allow(dead_code)]
pub struct PackVerifier {
    key: VerifyingKey,
}

#[allow(dead_code)]
impl PackVerifier {
    /// Construct a verifier from 32 raw public key bytes.
    ///
    /// ```no_run
    /// # use sigil_cli::corpus::signing::PackVerifier;
    /// let verifier = PackVerifier::from_public_key_bytes(&[0u8; 32]).unwrap();
    /// ```
    pub fn from_public_key_bytes(bytes: &[u8; 32]) -> Result<Self, VerifyError> {
        VerifyingKey::from_bytes(bytes)
            .map(|key| PackVerifier { key })
            .map_err(VerifyError::InvalidPublicKey)
    }

    /// Verify the signature embedded in `raw_json`.
    ///
    /// Returns `Ok(())` when the signature is valid.  Returns an error when:
    /// - the JSON is malformed,
    /// - `meta.signature` is absent,
    /// - the signature cannot be decoded or parsed,
    /// - or the signature does not match the canonical content.
    pub fn verify(&self, raw_json: &str) -> Result<(), VerifyError> {
        // 1. Parse to a mutable Value so we can extract + remove the signature.
        let mut doc: Value = serde_json::from_str(raw_json).map_err(VerifyError::InvalidJson)?;

        // 2. Extract the signature string from meta.signature.
        let sig_b64 = doc
            .get("meta")
            .and_then(|m| m.get("signature"))
            .and_then(|s| s.as_str())
            .ok_or(VerifyError::MissingSignature)?
            .to_owned();

        // 3. Remove the signature field to reconstruct the canonical form.
        if let Some(meta) = doc.get_mut("meta").and_then(|m| m.as_object_mut()) {
            meta.remove("signature");
        }

        // 4. Re-serialise to canonical bytes (compact JSON).
        let canonical = serde_json::to_string(&doc).map_err(VerifyError::CanonicaliseError)?;

        // 5. Decode the Base64 signature.
        let sig_bytes = BASE64
            .decode(sig_b64.as_bytes())
            .map_err(VerifyError::InvalidBase64)?;

        // 6. Parse into an Ed25519 Signature.
        let sig_array: &[u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
            VerifyError::InvalidSignatureBytes(ed25519_dalek::SignatureError::new())
        })?;
        let signature = Signature::from_bytes(sig_array);

        // 7. Verify.
        use ed25519_dalek::Verifier as _;
        self.key
            .verify(canonical.as_bytes(), &signature)
            .map_err(VerifyError::SignatureMismatch)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod pack_signature {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    /// Generate a fresh signing key pair and return (signing_key, verifying_key_bytes).
    fn fresh_keypair() -> (SigningKey, [u8; 32]) {
        // Use a deterministic seed for reproducibility in tests.
        let seed: [u8; 32] = [
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0x44, 0xda, 0x08, 0x53, 0x47, 0x84, 0x11, 0x39, 0xbe, 0x0b, 0xe8, 0xd6, 0x56,
            0x48, 0x20, 0x89, 0x17,
        ];
        let sk = SigningKey::from_bytes(&seed);
        let vk = sk.verifying_key().to_bytes();
        (sk, vk)
    }

    /// Build a minimal pack JSON value for testing.
    fn minimal_pack() -> serde_json::Value {
        serde_json::json!({
            "meta": {
                "id": "test-pack",
                "name": "Test Pack",
                "version": "0.0.1",
                "updated_at": "2026-06-11",
                "author": "test",
                "description": "unit test pack"
            },
            "rules": [],
            "provenance_rules": []
        })
    }

    /// Sign a pack value and return the JSON string with `meta.signature` injected.
    fn sign_pack(sk: &SigningKey, mut doc: serde_json::Value) -> String {
        // Canonical form = doc without signature field (it doesn't exist yet).
        let canonical = serde_json::to_string(&doc).unwrap();
        let sig = sk.sign(canonical.as_bytes());
        let sig_b64 = BASE64.encode(sig.to_bytes());
        doc["meta"]["signature"] = serde_json::Value::String(sig_b64);
        serde_json::to_string(&doc).unwrap()
    }

    #[test]
    fn pack_signature_valid_signature_accepted() {
        let (sk, vk_bytes) = fresh_keypair();
        let pack_json = sign_pack(&sk, minimal_pack());
        let verifier = PackVerifier::from_public_key_bytes(&vk_bytes).unwrap();
        assert!(
            verifier.verify(&pack_json).is_ok(),
            "valid signature should be accepted"
        );
    }

    #[test]
    fn pack_signature_missing_signature_rejected() {
        let (_, vk_bytes) = fresh_keypair();
        let pack_json = serde_json::to_string(&minimal_pack()).unwrap();
        let verifier = PackVerifier::from_public_key_bytes(&vk_bytes).unwrap();
        let err = verifier.verify(&pack_json).unwrap_err();
        assert!(
            matches!(err, VerifyError::MissingSignature),
            "missing signature should produce MissingSignature error, got: {err}"
        );
    }

    #[test]
    fn pack_signature_tampered_content_rejected() {
        let (sk, vk_bytes) = fresh_keypair();
        let pack = minimal_pack();
        let pack_json = sign_pack(&sk, pack.clone());

        // Parse the signed JSON, tamper with it, re-serialise.
        let mut tampered: serde_json::Value = serde_json::from_str(&pack_json).unwrap();
        // Add a rule that wasn't present when the signature was computed.
        tampered["rules"] = serde_json::json!([{
            "id": "INJECTED-001",
            "phase": "code_patterns",
            "severity": "critical",
            "pattern": "evil",
            "description": "injected rule"
        }]);
        let tampered_json = serde_json::to_string(&tampered).unwrap();

        let verifier = PackVerifier::from_public_key_bytes(&vk_bytes).unwrap();
        let err = verifier.verify(&tampered_json).unwrap_err();
        assert!(
            matches!(err, VerifyError::SignatureMismatch(_)),
            "tampered content should produce SignatureMismatch, got: {err}"
        );
    }

    #[test]
    fn pack_signature_wrong_key_rejected() {
        let (sk, _) = fresh_keypair();
        let pack_json = sign_pack(&sk, minimal_pack());

        // Use a different (all-zeros) public key.
        let wrong_vk_bytes = [0u8; 32];
        // all-zeros is not a valid compressed point — from_bytes will error.
        let result = PackVerifier::from_public_key_bytes(&wrong_vk_bytes);
        // Either the key is rejected at construction, or at verify time.
        match result {
            Err(VerifyError::InvalidPublicKey(_)) => {
                // Correctly rejected at construction.
            }
            Ok(verifier) => {
                let verify_result = verifier.verify(&pack_json);
                assert!(
                    verify_result.is_err(),
                    "wrong public key should not verify the signature"
                );
            }
            Err(other) => panic!("unexpected error variant constructing verifier: {other}"),
        }
    }

    #[test]
    fn pack_signature_invalid_base64_rejected() {
        let (_, vk_bytes) = fresh_keypair();
        let mut pack = minimal_pack();
        // Inject a non-base64 string as the signature.
        pack["meta"]["signature"] = serde_json::Value::String("!!!not_base64!!!".into());
        let pack_json = serde_json::to_string(&pack).unwrap();

        let verifier = PackVerifier::from_public_key_bytes(&vk_bytes).unwrap();
        let err = verifier.verify(&pack_json).unwrap_err();
        assert!(
            matches!(err, VerifyError::InvalidBase64(_)),
            "invalid base64 should produce InvalidBase64 error, got: {err}"
        );
    }
}
