/// Context classification that suppresses findings code cannot act on.
/// First slice of the Python scanner's proven FP filters (ADR-0008); the
/// remainder (UMD/polyfill/webpack preambles, safe domains) ports with the
/// corpus work in US-C3.

/// Type-declaration files describe APIs; nothing in them executes. `eval(` in
/// a `.d.ts` is a signature, not a call — the audit showed 4 of 7 test-repo
/// findings were this false-positive class.
pub fn is_declaration_file(rel_path: &str) -> bool {
    let lower = rel_path.to_lowercase();
    lower.ends_with(".d.ts")
        || lower.ends_with(".d.mts")
        || lower.ends_with(".d.cts")
        || lower.ends_with(".pyi")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_declaration_files() {
        assert!(is_declaration_file("types.d.ts"));
        assert!(is_declaration_file("lib/index.d.mts"));
        assert!(is_declaration_file("stubs/requests.pyi"));
        assert!(!is_declaration_file("malicious.js"));
        assert!(!is_declaration_file("setup.py"));
        // A directory named like a decl file must not suppress its children.
        assert!(!is_declaration_file("evil.d.ts/payload.js"));
    }
}
