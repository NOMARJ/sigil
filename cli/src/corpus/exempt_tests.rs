//! Tests for match-local suppression (`suppress.match_context`,
//! `suppress.value_matches`; see `corpus::exempt`).
//!
//! The engine-level tests use a small synthetic rule so each property is
//! checked in isolation: overlap safety, mixed lines, the fail-closed match
//! limit, UTF-8 windows, case handling of value predicates, loader
//! rejections, and agreement between the compiled and uncompiled engines.
//!
//! Listed in `.sigilignore` with the other detection-engine test inputs.

use serde_json::json;

use super::compiled::CompiledCorpus;
use super::engine::scan_file_with_packs;
use super::schema::SignaturePack;
use crate::scanner::{Finding, Phase};

fn pack(rules: serde_json::Value) -> SignaturePack {
    serde_json::from_value(json!({
        "meta": {"id": "exempt-test", "name": "t", "version": "0", "updated_at": "",
                 "author": "", "description": ""},
        "rules": rules
    }))
    .expect("test pack parses")
}

/// A rule that reports `run(...);`, exempt when the text before the call
/// ends with `safe `.
fn run_rule() -> SignaturePack {
    pack(json!([{
        "id": "TEST-RUN-001",
        "phase": "code_patterns",
        "severity": "high",
        "pattern": "(?P<anchor>run\\()[^;]*;",
        "description": "run",
        "suppress": {"match_context": [{"before": "safe\\s*"}]}
    }]))
}

/// Findings from both engines, which must agree.
fn scan_both(p: &SignaturePack, path: &str, text: &str) -> Vec<Finding> {
    let name = path.rsplit('/').next().unwrap_or(path);
    let uncompiled = scan_file_with_packs(std::slice::from_ref(p), path, name, text);
    let compiled = CompiledCorpus::from_packs(std::slice::from_ref(p)).scan_phase(
        Phase::CodePatterns,
        path,
        name,
        text,
    );
    let key = |f: &Finding| (f.rule.clone(), f.line);
    let mut a: Vec<_> = uncompiled.iter().map(key).collect();
    let mut b: Vec<_> = compiled.iter().map(key).collect();
    a.sort();
    b.sort();
    assert_eq!(a, b, "compiled and uncompiled engines disagree on {text:?}");
    compiled
}

#[test]
fn an_exempt_match_does_not_hide_an_overlapping_real_one() {
    let p = run_rule();
    // The first match (`run(a, run(b);`) is exempt and swallows the second
    // `run(` in a non-overlapping search; the restart finds it.
    assert_eq!(scan_both(&p, "a.js", "safe run(a, run(b);").len(), 1);
}

#[test]
fn a_line_is_dropped_only_when_every_match_is_exempt() {
    let p = run_rule();
    assert!(scan_both(&p, "a.js", "safe run(a);").is_empty());
    assert!(scan_both(&p, "a.js", "safe run(a); safe run(b);").is_empty());
    assert_eq!(scan_both(&p, "a.js", "safe run(a); run(b);").len(), 1);
    assert_eq!(scan_both(&p, "a.js", "run(b); safe run(a);").len(), 1);
    assert_eq!(scan_both(&p, "a.js", "run(b);").len(), 1);
}

#[test]
fn too_many_matches_on_one_line_keep_the_finding() {
    let p = run_rule();
    let many = "safe run(a); ".repeat(super::exempt::MAX_MATCHES_PER_LINE + 1);
    assert_eq!(scan_both(&p, "a.js", &many).len(), 1, "fails closed");
    let few = "safe run(a); ".repeat(super::exempt::MAX_MATCHES_PER_LINE);
    assert!(scan_both(&p, "a.js", &few).is_empty());
}

#[test]
fn windows_are_cut_on_character_boundaries() {
    let p = run_rule();
    for pad in 0..8 {
        // Multi-byte characters straddle the 120-byte window edge.
        let line = format!(
            "{}{}safe run(a);{}",
            "x".repeat(pad),
            "é".repeat(80),
            "é".repeat(80)
        );
        assert!(scan_both(&p, "a.js", &line).is_empty(), "pad {pad}");
        let line = format!(
            "{}{}run(a);{}",
            "x".repeat(pad),
            "é".repeat(80),
            "é".repeat(80)
        );
        assert_eq!(scan_both(&p, "a.js", &line).len(), 1, "pad {pad}");
    }
}

#[test]
fn a_context_can_be_limited_to_file_extensions() {
    let p = pack(json!([{
        "id": "TEST-RUN-002",
        "phase": "code_patterns",
        "severity": "high",
        "pattern": "(?P<anchor>run\\()[^;]*;",
        "description": "run",
        "suppress": {"match_context": [{"before": "safe\\s*", "extensions": ["js"]}]}
    }]));
    assert!(scan_both(&p, "a.js", "safe run(a);").is_empty());
    assert_eq!(scan_both(&p, "a.kt", "safe run(a);").len(), 1);
}

#[test]
fn value_predicates_are_case_sensitive_under_a_case_insensitive_rule() {
    let p = pack(json!([{
        "id": "TEST-TOKEN-001",
        "phase": "code_patterns",
        "severity": "high",
        "pattern": "(?i)token\\s*=\\s*\"(?P<value>[a-z0-9_-]+)\"",
        "description": "token",
        "suppress": {"value_matches": ["[a-z]+(?:[-_][a-z]+)+"]}
    }]));
    assert!(scan_both(&p, "a.py", "TOKEN = \"header-name\"").is_empty());
    assert_eq!(scan_both(&p, "a.py", "token = \"HEADER-NAME\"").len(), 1);
    assert_eq!(scan_both(&p, "a.py", "token = \"ab12-cd34\"").len(), 1);
}

#[test]
fn same_requires_equal_captures() {
    let p = pack(json!([{
        "id": "TEST-PAIR-001",
        "phase": "code_patterns",
        "severity": "high",
        "pattern": "(?P<anchor>use\\()[^)]*\\)",
        "description": "pair",
        "suppress": {"match_context": [{
            "before": "(?P<a>\\w+)\\.ok;\\s*",
            "after": "(?P<b>\\w+)\\)",
            "same": [["a", "b"]]
        }]}
    }]));
    assert!(scan_both(&p, "a.js", "x.ok; use(x)").is_empty());
    assert_eq!(scan_both(&p, "a.js", "x.ok; use(y)").len(), 1);
}

#[test]
fn packs_with_unusable_predicates_are_refused() {
    use super::exempt::validate;
    use super::schema::{MatchContext, SuppressionPredicates};
    let values = SuppressionPredicates {
        value_matches: vec!["[a-z]+".into()],
        ..Default::default()
    };
    assert!(
        validate("token=\"[a-z]+\"", &values).is_err(),
        "no value group"
    );
    assert!(validate("token=\"(?P<value>[a-z]+)\"", &values).is_ok());

    let ctx = |c: MatchContext| SuppressionPredicates {
        match_context: vec![c],
        ..Default::default()
    };
    assert!(
        validate("run", &ctx(MatchContext::default())).is_err(),
        "a context needs before or after"
    );
    assert!(validate(
        "run",
        &ctx(MatchContext {
            before: Some("(".into()),
            ..Default::default()
        })
    )
    .is_err());
    assert!(validate(
        "run",
        &ctx(MatchContext {
            before: Some("(?P<a>x)".into()),
            same: vec![["a".into(), "missing".into()]],
            ..Default::default()
        })
    )
    .is_err());

    // The custom-pack loader reports it against the rule.
    let _lock = super::custom::PACK_KEY_ENV_LOCK.lock().unwrap();
    std::env::remove_var("SIGIL_PACK_PUBLIC_KEY");
    let text = r#"{"meta": {"id": "x", "name": "x", "version": "1", "updated_at": "", "author": "", "description": ""},
      "rules": [{"id": "ACME-001", "phase": "code_patterns", "severity": "high", "pattern": "token=(\\w+)",
                 "description": "d", "remediation": "r",
                 "suppress": {"value_matches": ["[a-z]+"]}}]}"#;
    let errors = super::custom::parse_pack(text, std::path::Path::new("acme.json")).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| e.contains("ACME-001") && e.contains("value")),
        "{errors:?}"
    );
    // So does the ~/.sigil/packs loader.
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("acme.json");
    std::fs::write(&file, text).unwrap();
    let err = super::loader::load_pack_from_file(&file).unwrap_err();
    assert!(err.contains("ACME-001"), "{err}");
}

#[test]
fn the_embedded_packs_carry_valid_predicates() {
    let packs = super::loader::load_all_packs().unwrap();
    for p in &packs {
        super::loader::validate_exemptions(p).unwrap_or_else(|e| panic!("{}: {e}", p.meta.id));
    }
    let with: Vec<&str> = packs
        .iter()
        .flat_map(|p| p.rules.iter())
        .filter(|r| !r.suppress.match_context.is_empty() || !r.suppress.value_matches.is_empty())
        .map(|r| r.id.as_str())
        .collect();
    for id in [
        "CODE-001",
        "CODE-002",
        "CODE-003",
        "CRED-007",
        "CRED-008",
        "CRED-011",
        "OBFUSC-CHAIN-011",
    ] {
        assert!(with.contains(&id), "{id} lost its match-local predicates");
    }
}
