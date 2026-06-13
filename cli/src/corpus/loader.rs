//! Pack loader: discovers and parses `SignaturePack` JSON files from the
//! embedded `packs/` directory (bundled at compile time) and from
//! `~/.sigil/packs/` for user-installed packs.

use std::path::{Path, PathBuf};

use super::schema::SignaturePack;

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
];

/// Load all packs: embedded core packs plus any user-installed packs.
///
/// Invalid or unreadable packs are silently skipped so offline / degraded
/// environments still work.
pub fn load_all_packs() -> Vec<SignaturePack> {
    let mut packs: Vec<SignaturePack> = Vec::new();

    // 1. Embedded packs (always available)
    for raw in EMBEDDED_PACKS {
        match serde_json::from_str::<SignaturePack>(raw) {
            Ok(pack) => packs.push(pack),
            Err(e) => {
                // In release builds this should never happen; during dev it
                // surfaces malformed JSON early.
                eprintln!("[corpus] failed to parse embedded pack: {e}");
            }
        }
    }

    // 2. User-installed packs from ~/.sigil/packs/
    if let Some(user_packs) = user_packs_dir() {
        packs.extend(load_packs_from_dir(&user_packs));
    }

    packs
}

/// Load packs from a directory.  Non-JSON files and parse failures are skipped.
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

/// Parse a single pack from a file path.
pub fn load_pack_from_file(path: &Path) -> Result<SignaturePack, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("read error: {e}"))?;
    serde_json::from_str::<SignaturePack>(&raw).map_err(|e| format!("parse error: {e}"))
}

/// Returns `~/.sigil/packs/` when the home directory can be determined.
pub fn user_packs_dir() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".sigil").join("packs"))
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(s.should_suppress("node_modules/lodash/index.js", "index.js", "atob(x)", ""));
        assert!(!s.should_suppress("src/utils.js", "utils.js", "atob(x)", ""));
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
            ""
        ));
        assert!(!s.should_suppress(
            "src/client.py",
            "client.py",
            r#"requests.get("https://evil.ngrok.io/exfil")"#,
            ""
        ));
    }
}
