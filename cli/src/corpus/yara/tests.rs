//! Tests for the YARA subset: the parser (every supported construct and every
//! refused one), the evaluator (each condition form and string modifier), the
//! custom-pack loader and detached signing.
//!
//! Every rule here matches synthetic, inert markers (`SIGIL_YARA_TEST_MARKER`,
//! `example-canary-token`, the bytes of "SIGIL"). None describes real malware.

use std::path::Path;
use std::sync::Arc;

use super::eval::{MAX_MATCHES_PER_STRING, UNBOUNDED_MATCH_LIMIT};
use super::*;
use crate::corpus::custom::PACK_KEY_ENV_LOCK as ENV_LOCK;
use crate::scanner::budget::FileBudget;
use crate::scanner::Finding;

fn compile_ok(src: &str) -> YaraFile {
    match compile_rules(src, Path::new("test.yar")) {
        Ok((file, _)) => file,
        Err(errs) => panic!("expected {src:?} to compile, got {errs:?}"),
    }
}

fn warnings(src: &str) -> Vec<String> {
    compile_rules(src, Path::new("test.yar"))
        .map(|(_, w)| w)
        .unwrap_or_else(|e| panic!("expected to compile, got {e:?}"))
}

fn errors(src: &str) -> Vec<(usize, String)> {
    match compile_rules(src, Path::new("test.yar")) {
        Ok(_) => panic!("expected {src:?} to be refused"),
        Err(e) => e,
    }
}

/// The single error for a source, asserting its line and a fragment of it.
fn refused(src: &str, line: usize, fragment: &str) {
    let errs = errors(src);
    assert!(
        errs.iter().any(|(l, m)| *l == line && m.contains(fragment)),
        "expected an error at line {line} containing {fragment:?}, got {errs:?}"
    );
}

fn run(file: YaraFile, data: &[u8]) -> Vec<Finding> {
    let subject = Subject::whole(data, !data.contains(&0));
    scan(
        &[Arc::new(file)],
        &subject,
        "f.txt",
        &|_| true,
        &FileBudget::unbounded(),
    )
}

fn fired(src: &str, data: &[u8]) -> Vec<String> {
    run(compile_ok(src), data)
        .into_iter()
        .map(|f| f.rule)
        .collect()
}

/// Does the one-rule `condition` over `strings` match `data`?
fn matches(strings: &str, condition: &str, data: &[u8]) -> bool {
    let src = format!("rule t {{ strings: {strings} condition: {condition} }}");
    !fired(&src, data).is_empty()
}

fn cond(condition: &str, data: &[u8]) -> bool {
    let src = format!("rule t {{ condition: {condition} }}");
    !fired(&src, data).is_empty()
}

// ---------------------------------------------------------------------------
// Parser: supported constructs
// ---------------------------------------------------------------------------

const FULL: &str = r#"
// Synthetic rules for the parser: every supported construct once.
/* A block
   comment. */
private rule Helper_Marker : internal
{
    strings:
        $h = "example-canary-token"
    condition:
        $h
}

rule Example_Canary_Rule : acme canary
{
    meta:
        description = "Synthetic canary marker"
        author = "Security Team"
        reference = "https://example.invalid/canary"
        reference = "TICKET-1"
        severity = "High"
        phase = "network_exfil"
        remediation = "Remove the canary marker."
        date = "2026-01-01"
        score = 70
        active = true
        version = 1.5
    strings:
        $text = "SIGIL_YARA\x5FTEST\tMARK\"ER\\" nocase wide ascii fullword private
        $hex = { 53 49 ?? 4? ?C [2] 4C [1-3] ( 41 | 42 43 ) [0-] 58 }
        $re = /sigil[-_]yara\/[a-z]{2,4}/is
        $anon1 = "alpha"
        $ = "anonymous-one"
    condition:
        (Helper_Marker or $text) and #hex >= 0 and $re at 0 and $anon1 in (0..100)
        and any of them and all of ($anon*, $re) and none of ($hex) and 1 of ($*)
        and 50% of them and filesize < 1MB and filesize > 1KB - 1024 + 2 * 3 \ 3 % 5
        and not false and true and -1 < 0 and #text != 5
}
"#;

#[test]
fn every_supported_construct_parses() {
    let file = compile_ok(FULL);
    assert_eq!(file.rules.len(), 2);
    let helper = &file.rules[0];
    assert!(helper.private);
    assert_eq!(helper.id, "YARA-HELPER-MARKER");
    assert_eq!(helper.tags, vec!["internal"]);

    let r = &file.rules[1];
    assert_eq!(r.id, "YARA-EXAMPLE-CANARY-RULE");
    assert_eq!(r.name, "Example_Canary_Rule");
    assert_eq!(r.tags, vec!["acme", "canary"]);
    assert_eq!(r.description, "Synthetic canary marker");
    assert_eq!(r.author.as_deref(), Some("Security Team"));
    assert_eq!(
        r.references,
        vec!["https://example.invalid/canary", "TICKET-1"]
    );
    assert_eq!(r.severity, Severity::High);
    assert_eq!(r.phase, Phase::NetworkExfil);
    assert_eq!(r.remediation.as_deref(), Some("Remove the canary marker."));
    assert_eq!(r.strings.len(), 5);
    let text = &r.strings[0];
    assert!(text.private && text.fullword);
    assert_eq!(text.variants.len(), 2, "ascii + wide are two forms");
    assert_eq!(r.strings[4].name, "$");
    assert!(r.source.starts_with("rule Example_Canary_Rule"));
    assert!(r.source.trim_end().ends_with('}'));
}

#[test]
fn defaults_apply_when_meta_is_silent() {
    let file = compile_ok(r#"rule bare { strings: $a = "SIGIL_YARA_TEST_MARKER" condition: $a }"#);
    let r = &file.rules[0];
    assert_eq!(r.severity, DEFAULT_SEVERITY);
    assert_eq!(r.phase, DEFAULT_PHASE);
    assert_eq!(r.description, "YARA rule bare");
    assert!(r.remediation.is_none());
    assert!(r
        .remediation_or_default(Path::new("/x/acme.yar"))
        .contains("acme.yar"));
}

#[test]
fn global_rules_are_supported() {
    let file = compile_ok(
        r#"global private rule small { condition: filesize < 100 }
           rule marker { strings: $a = "SIGIL" condition: $a }"#,
    );
    assert!(file.rules[0].global && file.rules[0].private);
}

#[test]
fn rule_ids_are_upper_cased_with_dashes() {
    assert_eq!(
        sigil_id("Example_Rule").as_deref(),
        Some("YARA-EXAMPLE-RULE")
    );
    assert_eq!(sigil_id("a__b_").as_deref(), Some("YARA-A-B"));
    assert_eq!(sigil_id("_x1").as_deref(), Some("YARA-X1"));
    assert_eq!(sigil_id("___"), None);
    for id in ["YARA-EXAMPLE-RULE", "YARA-A-B", "YARA-X1"] {
        assert!(crate::corpus::custom::id_shape().is_match(id), "{id}");
    }
}

#[test]
fn near_miss_meta_keys_warn_and_private_orphans_warn() {
    let w = warnings(
        r#"private rule unused { condition: true }
           rule r { meta: sevrity = "high" hash = "abc" strings: $a = "SIGIL" condition: $a }"#,
    );
    assert!(
        w.iter().any(|m| m.contains("did you mean `severity`")),
        "{w:?}"
    );
    assert!(!w.iter().any(|m| m.contains("hash")), "{w:?}");
    assert!(
        w.iter()
            .any(|m| m.contains("private rule `unused` is not referenced")),
        "{w:?}"
    );
}

// ---------------------------------------------------------------------------
// Parser: refused constructs, each with its line
// ---------------------------------------------------------------------------

#[test]
fn imports_and_includes_are_refused() {
    refused(
        "import \"pe\"\nrule r { condition: true }",
        1,
        "import \"pe\"",
    );
    refused(
        "rule r { condition: true }\ninclude \"other.yar\"",
        2,
        "`include` is not supported",
    );
}

#[test]
fn modules_and_functions_are_refused() {
    refused(
        "rule r {\n condition:\n  pe.number_of_sections == 1\n}",
        3,
        "modules are not supported",
    );
    refused(
        "rule r {\n condition:\n  math.entropy(0, filesize) > 7\n}",
        3,
        "`math.`",
    );
    refused(
        "rule r {\n condition:\n  uint32(0) == 1\n}",
        3,
        "`uint32()` (reading integers from the file)",
    );
    refused(
        "rule r {\n condition:\n  int16be(4) == 1\n}",
        3,
        "`int16be()`",
    );
    refused(
        "rule r { condition: helper(1) }",
        1,
        "function call `helper(...)`",
    );
}

#[test]
fn loops_offsets_lengths_and_string_operators_are_refused() {
    let s = "strings:\n $a = \"SIGIL\"\n";
    refused(
        &format!("rule r {{\n{s} condition:\n  for any of them : ( $ at 0 )\n}}"),
        5,
        "`for` loops",
    );
    refused(
        &format!("rule r {{\n{s} condition:\n  @a[1] == 0\n}}"),
        5,
        "`@a` (match offsets)",
    );
    refused(
        &format!("rule r {{\n{s} condition:\n  !a[1] == 5\n}}"),
        5,
        "`!a` (match lengths)",
    );
    refused(
        &format!("rule r {{\n{s} condition:\n  #a in (0..10) == 1\n}}"),
        5,
        "`#a in (range)`",
    );
    refused(
        &format!("rule r {{\n{s} condition:\n  $a and filesize contains \"x\"\n}}"),
        5,
        "string operator `contains`",
    );
    refused(
        &format!("rule r {{\n{s} condition:\n  $a and ext_var matches /x/\n}}"),
        5,
        "unknown identifier `ext_var`",
    );
    refused(
        &format!("rule r {{\n{s} condition:\n  $a and entrypoint == 0\n}}"),
        5,
        "`entrypoint`",
    );
    refused(
        &format!("rule r {{\n{s} condition:\n  $a and defined filesize\n}}"),
        5,
        "`defined`",
    );
    refused(
        &format!("rule r {{\n{s} condition:\n  $a and filesize & 1 == 1\n}}"),
        5,
        "bitwise operator `&`",
    );
    refused(
        &format!("rule r {{\n{s} condition:\n  $a and filesize > 1.5\n}}"),
        5,
        "floating-point",
    );
    refused(
        &format!("rule r {{\n{s} condition:\n  any of ($a) in (0..10)\n}}"),
        5,
        "`of ... at N` and `of ... in (range)`",
    );
    refused(
        &format!("rule r {{\n{s} condition:\n  $a and $ at 0\n}}"),
        5,
        "anonymous `$`",
    );
    refused(
        &format!("rule r {{\n{s} condition:\n  $a and \"text\"\n}}"),
        5,
        "text values are not supported",
    );
}

#[test]
fn refused_string_modifiers_and_forms() {
    refused(
        "rule r {\n strings:\n  $a = \"SIGIL\" xor(0x01-0xff)\n condition: $a }",
        3,
        "`xor` modifier is not supported",
    );
    refused(
        "rule r {\n strings:\n  $a = \"SIGIL\" base64\n condition: $a }",
        3,
        "`base64` modifier",
    );
    refused(
        "rule r {\n strings:\n  $a = \"SIGIL\" base64wide(\"abc\")\n condition: $a }",
        3,
        "`base64wide` modifier",
    );
    refused(
        "rule r {\n strings:\n  $a = \"SIGIL\" nocas\n condition: $a }",
        3,
        "unknown modifier `nocas` (did you mean `nocase`?)",
    );
    refused(
        "rule r {\n strings:\n  $a = { 53 49 } nocase\n condition: $a }",
        3,
        "only takes the `private` modifier",
    );
    refused(
        "rule r {\n strings:\n  $a = /sigil/ wide\n condition: $a }",
        3,
        "`wide`, which is not supported",
    );
    refused(
        "rule r {\n strings:\n  $a = \"SIGIL\" nocase nocase\n condition: $a }",
        3,
        "`nocase` is repeated",
    );
}

#[test]
fn refused_hex_forms() {
    refused(
        "rule r {\n strings:\n  $a = { 53 ~49 }\n condition: $a }",
        3,
        "`~` (not) operator",
    );
    refused(
        "rule r {\n strings:\n  $a = { 53 ( 49 [2-] | 4C ) 47 }\n condition: $a }",
        3,
        "unbounded jumps are not allowed inside a hex alternative",
    );
    refused(
        "rule r {\n strings:\n  $a = { 53 [0-9999] 49 }\n condition: $a }",
        3,
        "wider than Sigil's limit of 512 bytes",
    );
    refused(
        "rule r {\n strings:\n  $a = { [2] 53 49 }\n condition: $a }",
        3,
        "cannot start or end with a jump",
    );
    refused(
        "rule r {\n strings:\n  $a = { 53 [4-2] 49 }\n condition: $a }",
        3,
        "bounds reversed",
    );
    refused(
        "rule r {\n strings:\n  $a = { 53 4 }\n condition: $a }",
        3,
        "two digits",
    );
    refused(
        "rule r {\n strings:\n  $a = { }\n condition: $a }",
        3,
        "empty hex string",
    );
    refused(
        "rule r {\n strings:\n  $a = { 53 49\n condition: $a }",
        4,
        "is the hex string opened on line 3 missing its `}`?",
    );
}

#[test]
fn counted_repetition_is_capped_across_hex_and_regex() {
    // At the limit: accepted.
    compile_ok("rule r { strings: $a = { 53 [0-512] 49 } condition: $a }");
    compile_ok(r"rule r { strings: $a = /S[a-z]{0,512}I/ condition: $a }");
    compile_ok("rule r { strings: $a = { 53 [0-256] 49 [0-256] 47 } condition: $a }");
    // Unbounded forms unroll only their minimum.
    compile_ok(r"rule r { strings: $a = { 53 [16-] 49 [-] 47 } condition: $a }");
    compile_ok(r"rule r { strings: $a = /S[a-z]+I.*G/ condition: $a }");
    refused(
        "rule r {\n strings:\n  $a = { 53 [600-] 49 }\n condition: $a }",
        3,
        "starts past Sigil's limit of 512 bytes",
    );
    // Past it, one jump, a sum of jumps, or a regex count.
    refused(
        "rule r {\n strings:\n  $a = { 53 [0-513] 49 }\n condition: $a }",
        3,
        "limit of 512 bytes",
    );
    refused(
        "rule r {\n strings:\n  $a = { 53 [0-300] 49 [0-300] 47 }\n condition: $a }",
        3,
        "unrolls to 600 positions",
    );
    refused(
        "rule r {\n strings:\n  $a = /S[a-z]{2,4096}I/\n condition: $a }",
        3,
        "unrolls to 4096 positions",
    );
    refused(
        "rule r {\n strings:\n  $a = /(?:ab){300}/\n condition: $a }",
        3,
        "unrolls to 600 positions",
    );
}

#[test]
fn pathological_conditions_are_refused_not_a_stack_overflow() {
    let deep = format!(
        "rule r {{ condition: {}true{} }}",
        "(".repeat(100_000),
        ")".repeat(100_000)
    );
    refused(&deep, 1, "nested deeper than 64 levels");
    let nots = format!("rule r {{ condition: {}true }}", "not ".repeat(100_000));
    refused(&nots, 1, "nested deeper than 64 levels");
    let long = format!(
        "rule r {{ condition: true{} }}",
        " and true".repeat(100_000)
    );
    refused(&long, 1, "more than 1000 terms");
    let hex = format!(
        "rule r {{ strings: $a = {{ 41 {}42{} }} condition: $a }}",
        "( ".repeat(40),
        " )".repeat(40)
    );
    refused(&hex, 1, "nested deeper than 16");
    // A byte-order mark at the start of the file is not an error.
    compile_ok("\u{feff}rule bom { condition: true }");
}

#[test]
fn semantic_errors_name_the_line() {
    refused(
        "rule r {\n strings:\n  $a = \"SIGIL\"\n  $b = \"unused\"\n condition: $a }",
        4,
        "string $b is not used in the condition",
    );
    refused(
        "rule r {\n condition:\n  $missing\n}",
        3,
        "string $missing is not defined",
    );
    refused("rule r { condition: r }", 1, "cannot refer to itself");
    refused(
        "rule a { condition: b }\nrule b { condition: true }",
        1,
        "unknown identifier `b`",
    );
    refused("rule rule { condition: true }", 1, "reserved word");
    refused(
        "rule dup { condition: true }\nrule dup { condition: true }",
        2,
        "defined more than once",
    );
    refused(
        "rule Same_Name { condition: true }\nrule SAME_NAME { condition: true }",
        2,
        "both become Sigil id YARA-SAME-NAME",
    );
    refused(
        "rule r {\n meta:\n  severity = \"severe\"\n condition: true }",
        3,
        "severity \"severe\" is not one of",
    );
    refused(
        "rule r {\n meta:\n  severity = 5\n condition: true }",
        3,
        "severity must be a text value",
    );
    refused(
        "rule r {\n meta:\n  phase = \"networking\"\n condition: true }",
        3,
        "phase must be one of",
    );
    refused(
        "rule r {\n strings:\n  $a = \"\"\n condition: $a }",
        3,
        "empty text string",
    );
    refused(
        "rule r {\n strings:\n  $a = /x*/\n condition: $a }",
        3,
        "can match zero bytes",
    );
    refused(
        "rule r {\n strings:\n  $a = /(unclosed/\n condition: $a }",
        3,
        "string $a:",
    );
    refused(
        "rule r {\n strings:\n  $a = \"bad \\q escape\"\n condition: $a }",
        3,
        "unknown escape `\\q`",
    );
    refused(
        "rule r {\n strings:\n  $a = \"unterminated\n condition: $a }",
        3,
        "not closed before the end of the line",
    );
    refused(
        "rule r {\n strings:\n  $a = \"SIGIL\"\n condition:\n  3 of them\n}",
        5,
        "more strings than the set has",
    );
    refused(
        "rule r {\n strings:\n  $a = \"SIGIL\"\n condition:\n  0 of them\n}",
        5,
        "write `none of`",
    );
    refused(
        "rule r {\n strings:\n  $a = \"SIGIL\"\n condition:\n  any of ($z*)\n}",
        5,
        "`$z*` matches no string",
    );
    refused(
        "rule r {\n condition:\n  1 < 2 < 3\n}",
        3,
        "cannot be chained",
    );
    refused(
        "rule r {\n condition:\n  (1 == 1) + 2 == 3\n}",
        3,
        "needs a number",
    );
    refused(
        "rule r { strings: $a = \"x\" }",
        1,
        "no `condition:` section",
    );
    refused(
        "/* never closed\nrule r { condition: true }",
        1,
        "comment is not closed",
    );
    refused("rule r { condition: true }\nstray", 2, "expected `rule`");
    refused("", 1, "no rules in this file");
}

#[test]
fn every_problem_in_a_file_is_reported_not_just_the_first() {
    let src = "import \"pe\"\n\
               rule one {\n condition:\n  uint8(0) == 1\n}\n\
               rule two {\n strings:\n  $a = \"SIGIL\" xor\n condition: $a\n}\n\
               rule three {\n condition:\n  for all i in (1..2) : (true)\n}\n\
               rule four { condition: true }\n";
    let errs = errors(src);
    let lines: Vec<usize> = errs.iter().map(|(l, _)| *l).collect();
    assert_eq!(lines, vec![1, 4, 8, 13], "{errs:?}");
}

// ---------------------------------------------------------------------------
// Evaluator
// ---------------------------------------------------------------------------

#[test]
fn text_strings_match_raw_bytes_across_lines_and_in_binary() {
    let s = r#"$a = "SIGIL_YARA_TEST_MARKER""#;
    assert!(matches(s, "$a", b"x = 'SIGIL_YARA_TEST_MARKER'\n"));
    assert!(!matches(s, "$a", b"SIGIL_YARA_TEST_MARKE"));
    // Binary content, and a marker split across a line break by a regex.
    assert!(matches(s, "$a", b"\x00\x01SIGIL_YARA_TEST_MARKER\xff\x00"));
    assert!(matches(
        r#"$a = /first[\s]+second/"#,
        "$a",
        b"first\nsecond"
    ));
}

#[test]
fn nocase_wide_ascii_and_fullword() {
    let data_wide: Vec<u8> = "xx SIGIL yy".bytes().flat_map(|b| [b, 0]).collect();
    assert!(matches(r#"$a = "sigil" nocase"#, "$a", b"a SiGiL b"));
    assert!(!matches(r#"$a = "sigil""#, "$a", b"a SiGiL b"));
    assert!(matches(r#"$a = "SIGIL" wide"#, "$a", &data_wide));
    assert!(!matches(r#"$a = "SIGIL" wide"#, "$a", b"SIGIL"));
    assert!(matches(r#"$a = "SIGIL" wide ascii"#, "$a", b"SIGIL"));
    assert!(matches(r#"$a = "SIGIL" wide ascii"#, "$a", &data_wide));
    assert!(matches(r#"$a = "sigil" wide nocase"#, "$a", &data_wide));
    assert!(matches(
        r#"$a = "canary" fullword"#,
        "$a",
        b"an example-canary-token"
    ));
    assert!(!matches(r#"$a = "canary" fullword"#, "$a", b"canarytoken"));
    assert!(!matches(r#"$a = "canary" fullword"#, "$a", b"xcanary"));
    assert!(matches(r#"$a = "canary" fullword"#, "$a", b"canary"));
    // A non-fullword first occurrence must not hide a fullword later one.
    assert!(matches(
        r#"$a = "canary" fullword"#,
        "$a",
        b"canaryx canary."
    ));
    let wide_word: Vec<u8> = "a canary b".bytes().flat_map(|b| [b, 0]).collect();
    let wide_joined: Vec<u8> = "acanaryb".bytes().flat_map(|b| [b, 0]).collect();
    assert!(matches(r#"$a = "canary" wide fullword"#, "$a", &wide_word));
    assert!(!matches(
        r#"$a = "canary" wide fullword"#,
        "$a",
        &wide_joined
    ));
    // Escapes in text strings are the bytes they name.
    assert!(matches(r#"$a = "S\x49G\tL\"\\""#, "$a", b"SIG\tL\"\\"));
}

#[test]
fn hex_wildcards_nibbles_jumps_and_alternatives() {
    // "SIGIL" is 53 49 47 49 4C.
    let d = b"..SIGIL..";
    assert!(matches("$h = { 53 49 47 49 4C }", "$h", d));
    assert!(matches("$h = { 53 ?? 47 ?? 4C }", "$h", d));
    assert!(matches("$h = { 5? 49 4? 49 ?C }", "$h", d));
    assert!(!matches("$h = { 6? 49 }", "$h", d));
    assert!(!matches("$h = { 53 ?A }", "$h", d));
    assert!(matches("$h = { 53 [3] 4C }", "$h", d));
    assert!(!matches("$h = { 53 [2] 4C }", "$h", d));
    assert!(matches("$h = { 53 [1-3] 4C }", "$h", d));
    assert!(!matches("$h = { 53 [0-2] 4C }", "$h", d));
    assert!(matches("$h = { 53 [2-] 4C }", "$h", d));
    assert!(matches("$h = { 53 [-] 4C }", "$h", d));
    assert!(matches("$h = { 53 ( 58 | 49 47 ) 49 }", "$h", d));
    assert!(matches("$h = { 53 ( 58 | 49 ( 47 | 00 ) ) 49 }", "$h", d));
    assert!(!matches("$h = { 53 ( 58 | 59 ) 49 }", "$h", d));
    // Hex matches newlines and NUL bytes like any other byte.
    assert!(matches("$h = { 0A 00 ?? 0A }", "$h", b"a\n\x00\xff\nb"));
}

#[test]
fn regex_flags_i_and_s() {
    assert!(matches(r"$r = /sigil-[0-9]+/", "$r", b"x sigil-42 y"));
    assert!(!matches(r"$r = /sigil-[0-9]+/", "$r", b"x SIGIL-42 y"));
    assert!(matches(r"$r = /sigil-[0-9]+/i", "$r", b"x SIGIL-42 y"));
    assert!(matches(
        r#"$r = /sigil-[0-9]+/ nocase"#,
        "$r",
        b"x SIGIL-42 y"
    ));
    assert!(!matches(r"$r = /a.b/", "$r", b"a\nb"));
    assert!(matches(r"$r = /a.b/s", "$r", b"a\nb"));
    assert!(matches(r"$r = /path\/to/", "$r", b"a path/to b"));
    assert!(matches(r"$r = /\xff\x00/", "$r", b"\x01\xff\x00"));
}

#[test]
fn counts_include_overlapping_matches() {
    let s = r#"$a = "aa""#;
    assert!(matches(s, "#a == 3", b"aaaa"));
    assert!(matches(s, "#a > 2 and #a < 4", b"aaaa"));
    assert!(matches(r#"$a = "SIGIL" wide ascii"#, "#a == 2", &{
        let mut v = b"SIGIL ".to_vec();
        v.extend("SIGIL".bytes().flat_map(|b| [b, 0]));
        v
    }));
    assert!(matches(r"$r = /b+/", "#r == 3", b"abbb"));
}

#[test]
fn at_and_in_ranges_use_file_offsets() {
    let s = r#"$a = "SIGIL""#;
    let d = b"0123SIGIL";
    assert!(matches(s, "$a at 4", d));
    assert!(!matches(s, "$a at 3", d));
    assert!(matches(s, "$a at 2 + 2", d));
    assert!(matches(s, "$a in (0..4)", d));
    assert!(matches(s, "$a in (4..4)", d));
    assert!(!matches(s, "$a in (0..3)", d));
    assert!(!matches(s, "$a in (5..100)", d));
    assert!(!matches(s, "$a at -1", d));
    assert!(matches(
        r#"$a = "canary" fullword"#,
        "$a in (0..8)",
        b"canaryx canary"
    ));
    assert!(!matches(
        r#"$a = "canary" fullword"#,
        "$a at 0",
        b"canaryx canary"
    ));
}

#[test]
fn sets_quantifiers_and_boolean_operators() {
    let s = r#"$a1 = "alpha" $a2 = "beta" $b = "gamma""#;
    let d = b"alpha beta";
    // YARA refuses a string the condition never uses, so each condition
    // also mentions every count (always true).
    let m = |c: &str| matches(s, &format!("({c}) and #a1 + #a2 + #b >= 0"), d);
    assert!(m("any of them"));
    assert!(!m("all of them"));
    assert!(m("all of ($a*)"));
    assert!(m("2 of them"));
    assert!(!m("3 of them"));
    assert!(m("none of ($b)"));
    assert!(!m("none of ($a1, $b)"));
    assert!(m("1 of ($a1, $b)"));
    assert!(m("66% of them"));
    assert!(!m("67% of them"));
    assert!(m("(1 + 1) of them"));
    assert!(m("$a1 and ($a2 or $b) and not $b"));
    assert!(!m("$a1 and not ($a2 or $b)"));
    assert!(m("#a1 + #a2 == 2 and #b == 0 and all of ($*) or $a1"));
}

#[test]
fn filesize_numbers_and_undefined_values() {
    let kb = vec![b'x'; 2048];
    assert!(cond("filesize == 2KB", &kb));
    assert!(cond("filesize < 1MB and filesize > 1KB", &kb));
    assert!(cond("filesize \\ 2 == 1024 and filesize % 1000 == 48", &kb));
    assert!(cond("0x10 == 16 and 0o10 == 8 and -(3) == 0 - 3", &kb));
    assert!(
        cond("filesize", &kb),
        "a number in a boolean position is != 0"
    );
    assert!(!cond("filesize", b""));
    // Division by zero and overflow are undefined, and undefined is false —
    // negated or not.
    assert!(!cond("filesize \\ 0 == 0", &kb));
    assert!(!cond("not (filesize \\ 0 == 0)", &kb));
    assert!(!cond("9223372036854775807 + 1 > 0", &kb));
    assert!(cond("filesize \\ 0 == 0 or true", &kb));
}

#[test]
fn private_and_global_rules_and_references() {
    let src = r#"
        private rule has_marker { strings: $m = "example-canary-token" condition: $m }
        rule uses_helper { condition: has_marker and filesize < 1000 }
        rule not_helper { condition: not has_marker }
    "#;
    assert_eq!(
        fired(src, b"an example-canary-token"),
        vec!["YARA-USES-HELPER"]
    );
    assert_eq!(fired(src, b"nothing"), vec!["YARA-NOT-HELPER"]);

    let global = r#"
        global private rule small { condition: filesize < 20 }
        rule marker { strings: $a = "SIGIL" condition: $a }
    "#;
    assert_eq!(fired(global, b"SIGIL"), vec!["YARA-MARKER"]);
    assert!(
        fired(global, b"SIGIL and then a lot more text").is_empty(),
        "a failing global rule switches the file's other rules off"
    );
    let public_global = r#"global rule tiny { condition: filesize < 10 }"#;
    assert_eq!(fired(public_global, b"x"), vec!["YARA-TINY"]);
}

#[test]
fn findings_carry_severity_phase_line_and_an_escaped_snippet() {
    let src = r#"
        rule Canary {
          meta:
            description = "Synthetic canary"
            severity = "critical"
            phase = "prompt_injection"
          strings:
            $a = "SIGIL_YARA_TEST_MARKER"
            $p = "secret-part" private
            $q = { 22 5C 01 }
          condition:
            all of them
        }"#;
    let data = b"line one\nline two SIGIL_YARA_TEST_MARKER\n\"\\\x01 secret-part\n";
    let f = &run(compile_ok(src), data)[0];
    assert_eq!(f.rule, "YARA-CANARY");
    assert_eq!(f.severity, Severity::Critical);
    assert_eq!(f.phase, Phase::PromptInjection);
    assert_eq!(f.weight, Phase::PromptInjection.default_weight());
    assert_eq!(f.line, Some(2), "line of the earliest matching string");
    assert!(
        f.snippet
            .starts_with("Synthetic canary: YARA rule Canary matched"),
        "{}",
        f.snippet
    );
    assert!(
        f.snippet.contains(r#"$a="SIGIL_YARA_TEST_MARKER""#),
        "{}",
        f.snippet
    );
    assert!(f.snippet.contains(r#"$q="\"\\\x01""#), "{}", f.snippet);
    assert!(
        !f.snippet.contains("secret-part"),
        "private strings are never shown"
    );

    // Binary content: no line number. Long matches are cut.
    let src = r#"rule Long { strings: $a = /Z{60}/ condition: $a }"#;
    let mut data = b"\x00".to_vec();
    data.extend([b'Z'; 60]);
    let f = &run(compile_ok(src), &data)[0];
    assert_eq!(f.line, None);
    assert!(
        f.snippet.contains(&format!("{}...", "Z".repeat(48))),
        "{}",
        f.snippet
    );

    let wide: Vec<u8> = "SIGIL".bytes().flat_map(|b| [b, 0]).collect();
    let f = &run(
        compile_ok(r#"rule W { strings: $a = "SIGIL" wide condition: $a }"#),
        &wide,
    )[0];
    assert!(f.snippet.contains(r#"$a="SIGIL" (wide)"#), "{}", f.snippet);

    let f = &run(compile_ok("rule C { condition: filesize > 0 }"), b"x")[0];
    assert!(f.snippet.contains("with no string match"), "{}", f.snippet);
}

#[test]
fn phase_filter_suppresses_findings_of_disabled_phases() {
    let file =
        compile_ok(r#"rule r { meta: phase = "credentials" strings: $a = "SIGIL" condition: $a }"#);
    let subject = Subject::whole(b"SIGIL", true);
    let only_code = |p: Phase| p == Phase::CodePatterns;
    let out = scan(
        &[Arc::new(file)],
        &subject,
        "f",
        &only_code,
        &FileBudget::unbounded(),
    );
    assert!(out.is_empty());
}

#[test]
fn head_and_tail_segments_keep_file_offsets_and_lines() {
    let file = compile_ok(
        r#"rule t { strings: $a = "SIGIL" $b = "canary" condition: $a at 1000 and $b and filesize == 5000 }"#,
    );
    let head = b"canary\n".to_vec();
    let mut tail = b"x".repeat(10);
    tail.extend_from_slice(b"SIGIL");
    let subject = Subject {
        segments: vec![
            Segment {
                base: 0,
                data: &head,
                newlines_before: Some(0),
            },
            Segment {
                base: 990,
                data: &tail,
                newlines_before: Some(40),
            },
        ],
        filesize: 5000,
        partial: true,
    };
    let out = scan(
        &[Arc::new(file)],
        &subject,
        "big.txt",
        &|_| true,
        &FileBudget::unbounded(),
    );
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].line, Some(1));
    assert!(out[0].snippet.starts_with("[head/tail of oversized file]"));

    // A match only in the tail is numbered from the newlines before it.
    let file = compile_ok(r#"rule t { strings: $a = "SIGIL" condition: $a }"#);
    let out = scan(
        &[Arc::new(file)],
        &subject,
        "big.txt",
        &|_| true,
        &FileBudget::unbounded(),
    );
    assert_eq!(out[0].line, Some(41));
}

#[test]
fn unbounded_strings_are_windowed_and_stay_fast() {
    // A greedy `.*` with the s flag over 200 KB holding 20,000 starts: each
    // match is bounded to UNBOUNDED_MATCH_LIMIT bytes rather than rescanning
    // to the end of the data once per match.
    let mut data = Vec::new();
    for _ in 0..20_000 {
        data.extend_from_slice(b"A123456789");
    }
    let start = std::time::Instant::now();
    assert!(matches(r"$r = /A.*9/s", "#r == 20000", &data));
    assert!(
        start.elapsed() < std::time::Duration::from_secs(20),
        "took {:?}",
        start.elapsed()
    );

    // A match longer than the limit is not reported; one within it is.
    let long = format!("A{}B", "x".repeat(UNBOUNDED_MATCH_LIMIT + 10));
    assert!(!matches(r"$r = /A[x]+B/", "$r", long.as_bytes()));
    let short = format!("A{}B", "x".repeat(100));
    assert!(matches(r"$r = /A[x]+B/", "$r", short.as_bytes()));
    // Look-around at a window edge sees the real bytes beyond it: the only
    // word boundary after this `A` is past the limit, so there is no match,
    // where cutting the data at the limit would invent one.
    let edge = format!("A{} end", "b".repeat(UNBOUNDED_MATCH_LIMIT + 100));
    assert!(!matches(r"$r = /A[a-z]+\b/", "$r", edge.as_bytes()));
    let near = format!("A{} end", "b".repeat(100));
    assert!(matches(r"$r = /A[a-z]+\b/", "#r == 1", near.as_bytes()));
}

#[test]
fn a_spent_budget_stops_evaluation() {
    let file = compile_ok(r#"rule r { strings: $a = "SIGIL" condition: $a }"#);
    let subject = Subject::whole(b"SIGIL", true);
    let out = scan(
        &[Arc::new(file)],
        &subject,
        "f",
        &|_| true,
        &FileBudget::spent(),
    );
    assert!(out.is_empty());
    assert_eq!(MAX_MATCHES_PER_STRING, 1_000_000);
}

// ---------------------------------------------------------------------------
// Loading as a custom pack, collisions, signing
// ---------------------------------------------------------------------------

const MARKER_RULE: &str = r#"
rule Sigil_Test_Marker : test
{
    meta:
        description = "Synthetic test marker"
        severity = "high"
    strings:
        $a = "SIGIL_YARA_TEST_MARKER"
    condition:
        $a
}
"#;

#[test]
fn a_yara_file_loads_as_a_custom_pack() {
    let _g = ENV_LOCK.lock().unwrap();
    std::env::remove_var("SIGIL_PACK_PUBLIC_KEY");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("acme.yar");
    std::fs::write(&path, MARKER_RULE).unwrap();
    let p = crate::corpus::custom::load_file(&path).expect("loads");
    assert_eq!(p.form, crate::corpus::custom::PackForm::Yara);
    assert_eq!(p.pack.meta.id, "yara.acme");
    assert_eq!(p.pack.rule_ids(), vec!["YARA-SIGIL-TEST-MARKER"]);
    assert_eq!(
        p.signature,
        crate::corpus::custom::SignatureStatus::Unsigned
    );

    // In a compiled corpus: listed, described, digested, evaluated.
    let corpus = crate::corpus::compiled::CompiledCorpus::from_packs(std::slice::from_ref(&p.pack));
    assert_eq!(corpus.rule_ids(), vec!["YARA-SIGIL-TEST-MARKER"]);
    assert_eq!(corpus.rule_count(), 1);
    let meta = corpus.rule_meta("YARA-SIGIL-TEST-MARKER").expect("meta");
    assert_eq!(meta.title, "Synthetic test marker");
    assert!(meta
        .remediation
        .as_deref()
        .unwrap_or("")
        .contains("acme.yar"));
    assert_eq!(corpus.yara().len(), 1);

    // The digest moves when the rule text does.
    let edited = dir.path().join("acme2.yar");
    std::fs::write(&edited, MARKER_RULE.replace("\"high\"", "\"low\"")).unwrap();
    let q = crate::corpus::custom::load_file(&edited).unwrap();
    let other = crate::corpus::compiled::CompiledCorpus::from_packs(&[q.pack]);
    assert_ne!(corpus.digest(), other.digest());
}

#[test]
fn a_directory_mixes_yara_and_yaml_packs_and_ignores_signatures() {
    let _g = ENV_LOCK.lock().unwrap();
    std::env::remove_var("SIGIL_PACK_PUBLIC_KEY");
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("b.yar"), MARKER_RULE).unwrap();
    std::fs::write(dir.path().join("b.yar.sig"), "not a pack\n").unwrap();
    std::fs::write(
        dir.path().join("c.yara"),
        r#"rule Other { strings: $a = "example-canary-token" condition: $a }"#,
    )
    .unwrap();
    std::fs::write(
        dir.path().join("a.yaml"),
        "rules:\n  - {id: ACME-1, pattern: 'q\\d', severity: low, description: d}\n",
    )
    .unwrap();
    let packs = crate::corpus::custom::load_path(dir.path()).expect("dir loads");
    let ids: Vec<String> = packs.iter().flat_map(|p| p.pack.rule_ids()).collect();
    assert_eq!(ids, vec!["ACME-1", "YARA-SIGIL-TEST-MARKER", "YARA-OTHER"]);
    // An unverifiable signature beside a file is reported, not required.
    assert_eq!(
        packs[1].signature,
        crate::corpus::custom::SignatureStatus::SignedUnverified
    );
}

#[test]
fn invalid_yara_is_refused_with_file_and_line() {
    let _g = ENV_LOCK.lock().unwrap();
    std::env::remove_var("SIGIL_PACK_PUBLIC_KEY");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.yar");
    std::fs::write(
        &path,
        "rule ok { condition: true }\nrule bad {\n condition:\n  uint16(0) == 1\n}\n",
    )
    .unwrap();
    let err = crate::corpus::custom::load_file(&path).unwrap_err();
    assert!(
        err.contains(&format!("{}:4: `uint16()`", path.display())),
        "{err}"
    );
}

#[test]
fn yara_ids_cannot_collide_with_any_loaded_rule() {
    let _g = ENV_LOCK.lock().unwrap();
    std::env::remove_var("SIGIL_PACK_PUBLIC_KEY");
    let base = crate::corpus::loader::load_base_packs().expect("base packs");
    let dir = tempfile::tempdir().unwrap();
    let yar = dir.path().join("one.yar");
    std::fs::write(&yar, MARKER_RULE).unwrap();
    let again = dir.path().join("two.yar");
    std::fs::write(&again, MARKER_RULE).unwrap();
    let json = dir.path().join("clash.yaml");
    std::fs::write(
        &json,
        "rules:\n  - {id: YARA-SIGIL-TEST-MARKER, pattern: 'q\\d', severity: low, description: d}\n",
    )
    .unwrap();
    let a = crate::corpus::custom::load_file(&yar).unwrap();
    let b = crate::corpus::custom::load_file(&again).unwrap();
    let c = crate::corpus::custom::load_file(&json).unwrap();
    let errs = crate::corpus::custom::check_against(&base, &[a.clone(), b]);
    assert!(
        errs.iter()
            .any(|e| e.contains("YARA-SIGIL-TEST-MARKER") && e.contains("already defined")),
        "{errs:?}"
    );
    let errs = crate::corpus::custom::check_against(&base, &[c, a]);
    assert!(!errs.is_empty(), "a YAML rule and a YARA rule share an id");

    // Engine rules (implemented in Rust, documented in a pack) are ids too.
    let engine_id = base
        .iter()
        .flat_map(|p| p.engine_rules.iter())
        .next()
        .expect("an engine rule")
        .id
        .clone();
    let clash = dir.path().join("engine.yaml");
    std::fs::write(
        &clash,
        format!(
            "rules:\n  - {{id: {engine_id}, pattern: 'q\\d', severity: low, description: d}}\n"
        ),
    )
    .unwrap();
    let e = crate::corpus::custom::load_file(&clash).unwrap();
    let errs = crate::corpus::custom::check_against(&base, &[e]);
    assert!(errs.iter().any(|m| m.contains(&engine_id)), "{errs:?}");
}

fn keypair(seed: u8) -> (ed25519_dalek::SigningKey, String) {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let vk = hex::encode(sk.verifying_key().to_bytes());
    (sk, vk)
}

#[test]
fn detached_signatures_are_required_and_verified_when_keyed() {
    let _g = ENV_LOCK.lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("signed.yar");
    std::fs::write(&path, MARKER_RULE).unwrap();
    let (sk, vk) = keypair(7);
    let (other_sk, _) = keypair(9);

    std::env::remove_var("SIGIL_PACK_PUBLIC_KEY");
    let sig = sign_detached(&path, &sk).expect("signs");
    assert_eq!(sig.trim().len(), 88, "64 bytes of base64");
    let unsigned = dir.path().join("unsigned.yar");
    std::fs::write(&unsigned, MARKER_RULE).unwrap();
    let tampered = dir.path().join("tampered.yar");
    std::fs::write(&tampered, MARKER_RULE.replace("high", "low")).unwrap();
    std::fs::write(signature_path(&tampered), &sig).unwrap();
    let wrong_key = dir.path().join("wrongkey.yar");
    std::fs::write(&wrong_key, MARKER_RULE).unwrap();
    std::fs::write(
        signature_path(&wrong_key),
        sign_detached(&wrong_key, &other_sk).unwrap(),
    )
    .unwrap();
    let garbage = dir.path().join("garbage.yar");
    std::fs::write(&garbage, MARKER_RULE).unwrap();
    std::fs::write(signature_path(&garbage), "!!!\n").unwrap();
    std::fs::write(signature_path(&path), &sig).unwrap();
    // Unkeyed: a signature present is noted, not verified.
    let before = crate::corpus::custom::load_file(&path).unwrap();
    assert_eq!(
        before.signature,
        crate::corpus::custom::SignatureStatus::SignedUnverified
    );

    std::env::set_var("SIGIL_PACK_PUBLIC_KEY", &vk);
    let verified = crate::corpus::custom::load_file(&path);
    let unsigned = crate::corpus::custom::load_file(&unsigned);
    let tampered = crate::corpus::custom::load_file(&tampered);
    let wrong_key = crate::corpus::custom::load_file(&wrong_key);
    let garbage = crate::corpus::custom::load_file(&garbage);
    std::env::remove_var("SIGIL_PACK_PUBLIC_KEY");

    assert_eq!(
        verified.expect("verifies").signature,
        crate::corpus::custom::SignatureStatus::Verified
    );
    for (what, r) in [
        ("unsigned", unsigned),
        ("tampered", tampered),
        ("wrong key", wrong_key),
        ("garbage", garbage),
    ] {
        let e = r.expect_err(what);
        assert!(e.contains("[SECURITY]"), "{what}: {e}");
    }
}

#[test]
fn an_invalid_file_is_not_signed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.yar");
    std::fs::write(&path, "rule r {\n condition:\n  uint8(0) == 1\n}\n").unwrap();
    let (sk, _) = keypair(3);
    let e = sign_detached(&path, &sk).unwrap_err();
    assert!(e.contains(":3: `uint8()`"), "{e}");
}
