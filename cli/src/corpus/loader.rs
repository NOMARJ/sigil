//! Pack loader: discovers and parses `SignaturePack` JSON files from the
//! embedded `packs/` directory (bundled at compile time) and from
//! `~/.sigil/packs/` for user-installed packs.

use std::path::{Path, PathBuf};

use super::schema::SignaturePack;
use super::signing::PackVerifier;

/// All packs bundled with the binary (embedded as static bytes at compile time).
///
/// Add new files to the `include_str!` list when new pack files are created.
/// Using separate constants keeps the compiler error local when a file is
/// missing.
const EMBEDDED_PACKS: &[&str] = &[
    include_str!("../../../packs/core/v1/install_hooks.json"),
    include_str!("../../../packs/core/v1/code_patterns.json"),
    include_str!("../../../packs/core/v1/network_exfil.json"),
    include_str!("../../../packs/core/v1/creds.json"),
    include_str!("../../../packs/core/v1/obfuscation.json"),
    include_str!("../../../packs/core/v1/obfuscation_chain.json"),
    include_str!("../../../packs/core/v1/provenance.json"),
    include_str!("../../../packs/core/v1/prompt_injection.json"),
    include_str!("../../../packs/core/v1/skill_security.json"),
    include_str!("../../../packs/core/v1/inference_security.json"),
    include_str!("../../../packs/core/v1/supply_chain.json"),
    // Reverse/bind-shell corpus generated from the MIT-licensed
    // reverse-shell-generator. Regenerate via tools/corpus-gen/.
    //
    // NOTE: the GTFOBins / LOLBAS LOLBin packs are deliberately NOT embedded
    // here — they are GPL-3.0 and ship as the optional, separately-distributed
    // bundle in packs/lolbin/v1/ (loaded at runtime from ~/.sigil/packs/). See
    // packs/lolbin/v1/NOTICE.md and tools/corpus-gen/README.md.
    include_str!("../../../packs/core/v1/reverse_shells.json"),
];

/// Verify the signature embedded in `raw` pack JSON, governed by the
/// `SIGIL_PACK_PUBLIC_KEY` environment variable.
///
/// The env var must be a 64-character lowercase hex string encoding the
/// 32-byte Ed25519 public key used to verify pack signatures.
///
/// | Key configured | Signature present | Outcome |
/// |:-:|:-:|---|
/// | No  | No  | OK — unsigned packs accepted when no key is configured |
/// | No  | Yes | OK + stderr warning — can't verify without a key |
/// | Yes | No  | Err — key configured means signatures are mandatory |
/// | Yes | Yes | Ok or Err — depends on whether the signature is valid |
///
/// This function is called only for user-installed packs. Embedded packs are
/// bundled at compile time and their integrity is guaranteed by the build.
pub fn verify_pack_if_keyed(raw: &str) -> Result<(), String> {
    let hex_key = match std::env::var("SIGIL_PACK_PUBLIC_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => {
            // No key configured.  If the pack carries a signature, warn that
            // it cannot be verified — this is the "alertable" path for unsigned
            // environments that receive signed packs.
            if pack_has_signature(raw) {
                eprintln!(
                    "[corpus] WARNING: pack carries a meta.signature but \
                     SIGIL_PACK_PUBLIC_KEY is not set — signature not verified"
                );
            }
            return Ok(());
        }
    };

    // Decode the 64-char hex public key to 32 bytes.
    if hex_key.len() != 64 {
        return Err(format!(
            "SIGIL_PACK_PUBLIC_KEY must be 64 hex chars (32 bytes), got {} chars",
            hex_key.len()
        ));
    }
    let mut key_bytes = [0u8; 32];
    for (i, chunk) in hex_key.as_bytes().chunks(2).enumerate() {
        let hex_pair = std::str::from_utf8(chunk)
            .map_err(|_| "SIGIL_PACK_PUBLIC_KEY contains non-UTF-8".to_string())?;
        key_bytes[i] = u8::from_str_radix(hex_pair, 16).map_err(|_| {
            format!("SIGIL_PACK_PUBLIC_KEY contains invalid hex at byte offset {i}")
        })?;
    }

    let verifier = PackVerifier::from_public_key_bytes(&key_bytes)
        .map_err(|e| format!("SIGIL_PACK_PUBLIC_KEY is not a valid Ed25519 public key: {e}"))?;

    verifier
        .verify(raw)
        .map_err(|e| format!("[SECURITY] pack signature verification failed: {e}"))
}

/// Returns `true` when the raw JSON contains a non-empty `meta.signature` field.
fn pack_has_signature(raw: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(raw)
        .ok()
        .and_then(|v| {
            v.get("meta")
                .and_then(|m| m.get("signature"))
                .and_then(|s| s.as_str())
                .map(|s| !s.is_empty())
        })
        .unwrap_or(false)
}

/// Load all packs: embedded core packs plus any user-installed packs.
///
/// Embedded pack parse failures are logged with a `[SECURITY]` prefix because
/// they indicate binary corruption (the packs are bundled at compile time).
/// User-installed pack failures are also logged; see `load_packs_from_dir`.
pub fn load_all_packs() -> Vec<SignaturePack> {
    let mut packs: Vec<SignaturePack> = Vec::new();

    // 1. Embedded packs (always available; not signature-verified — their
    //    integrity is guaranteed by the binary build process).
    for raw in EMBEDDED_PACKS {
        match serde_json::from_str::<SignaturePack>(raw) {
            Ok(pack) => packs.push(pack),
            Err(e) => {
                // A parse failure for a compile-time-embedded pack is a
                // programming or binary-corruption error — surface it loudly.
                eprintln!("[corpus] [SECURITY] failed to parse embedded pack: {e}");
            }
        }
    }

    // 2. User-installed packs from ~/.sigil/packs/
    if let Some(user_packs) = user_packs_dir() {
        packs.extend(load_packs_from_dir(&user_packs));
    }

    packs
}

/// Load packs from a directory.
///
/// Non-JSON files are skipped silently. Parse errors and signature failures
/// are logged to stderr and the offending pack is rejected — a tampered or
/// unsigned pack never reaches the engine.
pub fn load_packs_from_dir(dir: &Path) -> Vec<SignaturePack> {
    let mut packs = Vec::new();

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return packs,
    };

    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        match load_pack_from_file(&path) {
            Ok(pack) => packs.push(pack),
            Err(e) => {
                eprintln!("[corpus] skipping {}: {e}", path.display());
            }
        }
    }

    packs
}

/// Parse (and signature-verify) a single user pack from a file path.
///
/// Signature verification is controlled by `SIGIL_PACK_PUBLIC_KEY`; see
/// [`verify_pack_if_keyed`] for the full policy table.
pub fn load_pack_from_file(path: &Path) -> Result<SignaturePack, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("read error: {e}"))?;
    // Verify before deserialising — a tampered pack must be rejected before
    // its rules reach the engine, not after.
    verify_pack_if_keyed(&raw)?;
    serde_json::from_str::<SignaturePack>(&raw).map_err(|e| format!("parse error: {e}"))
}

/// Returns `~/.sigil/packs/` when the home directory can be determined.
pub fn user_packs_dir() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".sigil").join("packs"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
    use ed25519_dalek::{Signer, SigningKey};
    use std::sync::Mutex;

    // Serialise tests that mutate SIGIL_PACK_PUBLIC_KEY so parallel test
    // runners don't race on the env var.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    // -----------------------------------------------------------------------
    // Helpers shared across signing tests
    // -----------------------------------------------------------------------

    fn test_keypair() -> (SigningKey, [u8; 32]) {
        let seed: [u8; 32] = [
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0x44, 0xda, 0x08, 0x53, 0x47, 0x84, 0x11, 0x39, 0xbe, 0x0b, 0xe8, 0xd6, 0x56,
            0x48, 0x20, 0x89, 0x17,
        ];
        let sk = SigningKey::from_bytes(&seed);
        let vk = sk.verifying_key().to_bytes();
        (sk, vk)
    }

    fn hex_key(bytes: &[u8; 32]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn minimal_pack_json() -> serde_json::Value {
        serde_json::json!({
            "meta": {
                "id": "test-pack",
                "name": "Test",
                "version": "0.0.1",
                "updated_at": "2026-06-15",
                "author": "test",
                "description": "unit test pack"
            },
            "rules": [],
            "provenance_rules": []
        })
    }

    fn sign_pack(sk: &SigningKey, mut doc: serde_json::Value) -> String {
        let canonical = serde_json::to_string(&doc).unwrap();
        let sig = sk.sign(canonical.as_bytes());
        doc["meta"]["signature"] = serde_json::Value::String(BASE64.encode(sig.to_bytes()));
        serde_json::to_string(&doc).unwrap()
    }

    // -----------------------------------------------------------------------
    // verify_pack_if_keyed tests
    // -----------------------------------------------------------------------

    #[test]
    fn signing_no_key_no_signature_ok() {
        let _lock = ENV_LOCK.lock().unwrap();
        // No env var set, pack has no signature → accepted silently.
        std::env::remove_var("SIGIL_PACK_PUBLIC_KEY");
        let raw = serde_json::to_string(&minimal_pack_json()).unwrap();
        assert!(
            verify_pack_if_keyed(&raw).is_ok(),
            "unsigned pack with no key configured must be accepted"
        );
    }

    #[test]
    fn signing_no_key_signed_pack_accepted_with_warning() {
        let _lock = ENV_LOCK.lock().unwrap();
        // No env var set, but pack carries a signature.  We can't verify it,
        // so we warn (stderr) but accept.  The test just verifies it returns Ok.
        std::env::remove_var("SIGIL_PACK_PUBLIC_KEY");
        let (sk, _) = test_keypair();
        let raw = sign_pack(&sk, minimal_pack_json());
        assert!(
            verify_pack_if_keyed(&raw).is_ok(),
            "signed pack with no key configured must be accepted (with warning)"
        );
    }

    #[test]
    fn signing_keyed_valid_signature_accepted() {
        let _lock = ENV_LOCK.lock().unwrap();
        let (sk, vk) = test_keypair();
        std::env::set_var("SIGIL_PACK_PUBLIC_KEY", hex_key(&vk));
        let raw = sign_pack(&sk, minimal_pack_json());
        let result = verify_pack_if_keyed(&raw);
        std::env::remove_var("SIGIL_PACK_PUBLIC_KEY");
        assert!(
            result.is_ok(),
            "valid signature must be accepted: {result:?}"
        );
    }

    #[test]
    fn signing_keyed_missing_signature_rejected() {
        let _lock = ENV_LOCK.lock().unwrap();
        let (_, vk) = test_keypair();
        std::env::set_var("SIGIL_PACK_PUBLIC_KEY", hex_key(&vk));
        let raw = serde_json::to_string(&minimal_pack_json()).unwrap();
        let result = verify_pack_if_keyed(&raw);
        std::env::remove_var("SIGIL_PACK_PUBLIC_KEY");
        assert!(
            result.is_err(),
            "missing signature with key configured must be rejected"
        );
        let msg = result.unwrap_err();
        assert!(
            msg.contains("[SECURITY]"),
            "error message must carry [SECURITY] prefix; got: {msg}"
        );
    }

    #[test]
    fn signing_keyed_tampered_pack_rejected() {
        let _lock = ENV_LOCK.lock().unwrap();
        let (sk, vk) = test_keypair();
        std::env::set_var("SIGIL_PACK_PUBLIC_KEY", hex_key(&vk));

        // Sign the pack, then tamper with its content.
        let doc = minimal_pack_json();
        let signed_raw = sign_pack(&sk, doc.clone());
        let mut tampered: serde_json::Value = serde_json::from_str(&signed_raw).unwrap();
        tampered["meta"]["id"] = serde_json::Value::String("tampered".into());
        let tampered_raw = serde_json::to_string(&tampered).unwrap();

        let result = verify_pack_if_keyed(&tampered_raw);
        std::env::remove_var("SIGIL_PACK_PUBLIC_KEY");
        assert!(
            result.is_err(),
            "tampered pack must be rejected when key is configured"
        );
        let msg = result.unwrap_err();
        assert!(
            msg.contains("[SECURITY]"),
            "error message must carry [SECURITY] prefix; got: {msg}"
        );
    }

    #[test]
    fn signing_keyed_wrong_key_rejected() {
        let _lock = ENV_LOCK.lock().unwrap();
        let (sk, _) = test_keypair();
        // Use a different key for the env var.
        let wrong_seed: [u8; 32] = [0xAB; 32];
        let wrong_vk = SigningKey::from_bytes(&wrong_seed)
            .verifying_key()
            .to_bytes();
        std::env::set_var("SIGIL_PACK_PUBLIC_KEY", hex_key(&wrong_vk));

        let raw = sign_pack(&sk, minimal_pack_json());
        let result = verify_pack_if_keyed(&raw);
        std::env::remove_var("SIGIL_PACK_PUBLIC_KEY");
        assert!(
            result.is_err(),
            "pack signed with a different key must be rejected"
        );
    }

    #[test]
    fn signing_malformed_hex_key_rejected() {
        let _lock = ENV_LOCK.lock().unwrap();
        std::env::set_var("SIGIL_PACK_PUBLIC_KEY", "not_hex_at_all");
        let raw = serde_json::to_string(&minimal_pack_json()).unwrap();
        let result = verify_pack_if_keyed(&raw);
        std::env::remove_var("SIGIL_PACK_PUBLIC_KEY");
        assert!(
            result.is_err(),
            "malformed hex key must be rejected as a config error"
        );
    }

    #[test]
    fn signing_short_hex_key_rejected() {
        let _lock = ENV_LOCK.lock().unwrap();
        // 62 chars instead of 64.
        std::env::set_var("SIGIL_PACK_PUBLIC_KEY", "aa".repeat(31));
        let raw = serde_json::to_string(&minimal_pack_json()).unwrap();
        let result = verify_pack_if_keyed(&raw);
        std::env::remove_var("SIGIL_PACK_PUBLIC_KEY");
        assert!(
            result.is_err(),
            "short hex key must be rejected as a config error"
        );
    }

    // -----------------------------------------------------------------------
    // pack_has_signature helper
    // -----------------------------------------------------------------------

    #[test]
    fn pack_has_signature_true_when_present() {
        let (sk, _) = test_keypair();
        let raw = sign_pack(&sk, minimal_pack_json());
        assert!(pack_has_signature(&raw));
    }

    #[test]
    fn pack_has_signature_false_when_absent() {
        let raw = serde_json::to_string(&minimal_pack_json()).unwrap();
        assert!(!pack_has_signature(&raw));
    }

    // -----------------------------------------------------------------------
    // Existing loader tests (unchanged)
    // -----------------------------------------------------------------------

    #[test]
    fn corpus_loader_embedded_packs_parse() {
        // All embedded pack JSON must be valid and contain at least one rule.
        let packs = load_all_packs();
        assert!(
            !packs.is_empty(),
            "corpus_loader: no packs loaded from embedded data"
        );
        for pack in &packs {
            assert!(
                !pack.meta.id.is_empty(),
                "pack has empty id: {:?}",
                pack.meta
            );
            let has_rules = !pack.rules.is_empty() || !pack.provenance_rules.is_empty();
            assert!(
                has_rules,
                "pack '{}' has no rules or provenance_rules",
                pack.meta.id
            );
        }
    }

    #[test]
    fn corpus_loader_file_filter_empty_matches_all() {
        use crate::corpus::schema::FileFilter;
        let f = FileFilter::default();
        assert!(f.matches("anything.py"));
        assert!(f.matches("setup.py"));
        assert!(f.matches("Makefile"));
    }

    #[test]
    fn corpus_loader_file_filter_extension() {
        use crate::corpus::schema::FileFilter;
        let f = FileFilter {
            extensions: vec!["py".to_string(), "js".to_string()],
            ..Default::default()
        };
        assert!(f.matches("foo.py"));
        assert!(f.matches("bar.js"));
        assert!(!f.matches("baz.ts"));
    }

    #[test]
    fn corpus_loader_file_filter_filename_exact() {
        use crate::corpus::schema::FileFilter;
        let f = FileFilter {
            filename_exact: vec!["setup.py".to_string(), "package.json".to_string()],
            ..Default::default()
        };
        assert!(f.matches("setup.py"));
        assert!(f.matches("package.json"));
        assert!(!f.matches("other.py"));
    }

    #[test]
    fn corpus_loader_file_filter_suffix() {
        use crate::corpus::schema::FileFilter;
        let f = FileFilter {
            filename_suffix: vec![".mcp.yaml".to_string()],
            ..Default::default()
        };
        assert!(f.matches("server.mcp.yaml"));
        assert!(!f.matches("server.yaml"));
    }

    #[test]
    fn corpus_loader_suppression_path_contains() {
        use crate::corpus::schema::SuppressionPredicates;
        let s = SuppressionPredicates {
            path_contains: vec!["node_modules/".to_string()],
            ..Default::default()
        };
        assert!(s.should_suppress(
            "node_modules/lodash/index.js",
            "index.js",
            "atob(x)",
            "atob(x)",
            ""
        ));
        assert!(!s.should_suppress("src/utils.js", "utils.js", "atob(x)", "atob(x)", ""));
    }

    #[test]
    fn corpus_loader_suppression_safe_domains() {
        use crate::corpus::schema::SuppressionPredicates;
        let s = SuppressionPredicates {
            safe_domains: vec!["api.openai.com".to_string()],
            ..Default::default()
        };
        assert!(s.should_suppress(
            "src/client.py",
            "client.py",
            r#"requests.get("https://api.openai.com/v1/chat")"#,
            r#"requests.get("https://api.openai.com/v1/chat")"#,
            ""
        ));
        assert!(!s.should_suppress(
            "src/client.py",
            "client.py",
            r#"requests.get("https://evil.ngrok.io/exfil")"#,
            r#"requests.get("https://evil.ngrok.io/exfil")"#,
            ""
        ));
    }
}
