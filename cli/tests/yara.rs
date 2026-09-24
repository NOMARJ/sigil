//! End-to-end tests of YARA rule files as custom rules: loading (`--rules`,
//! directories, the organisation policy's `rule_packs`), the exit-code
//! contract, fail-closed refusal, collisions and detached signatures.
//!
//! Every test runs the real binary against a temporary tree with an isolated
//! HOME. The rules match inert synthetic markers (`SIGIL_YARA_TEST_MARKER`,
//! the bytes of "SIGIL"); nothing here describes real malware.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const MARKER: &str = "SIGIL_YARA_TEST_MARKER";

/// A High text rule and a Medium byte rule.
const RULES: &str = r#"
rule Sigil_Test_Marker : test
{
    meta:
        description = "Synthetic test marker"
        severity = "high"
        remediation = "Remove the synthetic marker."
    strings:
        $a = "SIGIL_YARA_TEST_MARKER"
    condition:
        $a
}

rule Sigil_Test_Bytes
{
    meta:
        description = "Synthetic byte marker"
        severity = "medium"
    strings:
        $h = { 53 49 47 49 4C 00 }
    condition:
        $h
}
"#;

/// Only the Medium byte rule.
const MEDIUM_ONLY: &str = r#"
rule Sigil_Medium_Bytes
{
    meta:
        severity = "medium"
    strings:
        $h = { 53 49 47 49 4C 00 }
    condition:
        $h
}
"#;

struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
    home: PathBuf,
    proj: PathBuf,
    rules: PathBuf,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().to_path_buf();
    let home = root.join("home");
    let proj = root.join("proj");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(proj.join("src")).unwrap();
    // Under bin/, where a shipped binary is expected (no PROV-002), so the
    // only thing that can flag it is the YARA byte rule.
    std::fs::create_dir_all(proj.join("bin")).unwrap();
    std::fs::write(
        proj.join("src/app.txt"),
        format!("first line\nvalue = {MARKER}\n"),
    )
    .unwrap();
    std::fs::write(proj.join("bin/blob.dat"), b"\x00\x01SIGIL\x00\xff").unwrap();
    std::fs::write(proj.join("src/readme.txt"), "nothing to see\n").unwrap();
    let rules = root.join("rules.yar");
    std::fs::write(&rules, RULES).unwrap();
    Fixture {
        _dir: dir,
        root,
        home,
        proj,
        rules,
    }
}

fn sigil(fx: &Fixture, cwd: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sigil"));
    cmd.args(args)
        .current_dir(cwd)
        .env("HOME", &fx.home)
        .env_remove("SIGIL_POLICY_FILE")
        .env_remove("SIGIL_PACK_PUBLIC_KEY")
        .env_remove("SIGIL_NO_PROJECT_CONFIG");
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().expect("run sigil")
}

fn code(o: &Output) -> i32 {
    o.status.code().expect("exit code")
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).to_string()
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).to_string()
}

fn json(o: &Output) -> serde_json::Value {
    serde_json::from_slice(&o.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout is not one JSON document: {e}\n{}",
            String::from_utf8_lossy(&o.stdout)
        )
    })
}

fn findings(o: &Output, rule: &str) -> Vec<serde_json::Value> {
    json(o)["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .filter(|f| f["rule"] == rule)
        .cloned()
        .collect()
}

#[test]
fn a_yara_rule_fires_and_gates_on_its_severity() {
    let fx = fixture();
    let rules = fx.rules.to_str().unwrap();

    let clean = sigil(&fx, &fx.proj, &["scan", ".", "--no-cache"], &[]);
    assert_eq!(code(&clean), 0, "{}", stderr(&clean));

    let flagged = sigil(
        &fx,
        &fx.proj,
        &["--rules", rules, "scan", ".", "--no-cache"],
        &[],
    );
    assert_eq!(
        code(&flagged),
        1,
        "a HIGH YARA finding fails the default gate"
    );

    let raised = sigil(
        &fx,
        &fx.proj,
        &[
            "--rules",
            rules,
            "scan",
            ".",
            "--no-cache",
            "--fail-on",
            "critical",
        ],
        &[],
    );
    assert_eq!(code(&raised), 0);

    let o = sigil(
        &fx,
        &fx.proj,
        &["--rules", rules, "scan", ".", "--no-cache", "-f", "json"],
        &[],
    );
    let text = findings(&o, "YARA-SIGIL-TEST-MARKER");
    assert_eq!(text.len(), 1, "{}", stdout(&o));
    assert_eq!(text[0]["severity"], "High");
    assert_eq!(text[0]["line"], 2);
    assert!(text[0]["file"].as_str().unwrap().ends_with("app.txt"));
    assert!(text[0]["snippet"].as_str().unwrap().contains(MARKER));
    assert_eq!(text[0]["remediation"], "Remove the synthetic marker.");
    // The byte rule matches a binary file, which has no line number.
    let bytes = findings(&o, "YARA-SIGIL-TEST-BYTES");
    assert_eq!(bytes.len(), 1, "{}", stdout(&o));
    assert!(bytes[0]["file"].as_str().unwrap().ends_with("blob.dat"));
    assert!(bytes[0]["line"].is_null());

    // A MEDIUM rule passes the default gate and fails --fail-on medium.
    let medium = fx.root.join("medium.yara");
    std::fs::write(&medium, MEDIUM_ONLY).unwrap();
    let medium = medium.to_str().unwrap();
    let o = sigil(
        &fx,
        &fx.proj,
        &["scan", ".", "--no-cache", "--fail-on", "medium"],
        &[],
    );
    assert_eq!(
        code(&o),
        0,
        "nothing else in the tree is MEDIUM: {}",
        stderr(&o)
    );
    let o = sigil(
        &fx,
        &fx.proj,
        &["--rules", medium, "scan", ".", "--no-cache"],
        &[],
    );
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let o = sigil(
        &fx,
        &fx.proj,
        &[
            "--rules",
            medium,
            "scan",
            ".",
            "--no-cache",
            "--fail-on",
            "medium",
        ],
        &[],
    );
    assert_eq!(code(&o), 1);
}

#[test]
fn directories_policies_and_inline_markers_treat_yara_like_any_rule() {
    let fx = fixture();
    let dir = fx.root.join("ruledir");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("acme.yar"), RULES).unwrap();
    std::fs::write(dir.join("notes.txt"), "not a rule file").unwrap();
    let o = sigil(
        &fx,
        &fx.proj,
        &[
            "--rules",
            dir.to_str().unwrap(),
            "scan",
            ".",
            "--no-cache",
            "-f",
            "json",
        ],
        &[],
    );
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    assert_eq!(findings(&o, "YARA-SIGIL-TEST-MARKER").len(), 1);

    // The organisation policy's rule_packs, resolved against its directory.
    let org = fx.root.join("org.yml");
    std::fs::write(&org, "rule_packs: [rules.yar]\n").unwrap();
    let o = sigil(
        &fx,
        &fx.proj,
        &["scan", ".", "--no-cache", "-f", "json"],
        &[("SIGIL_POLICY_FILE", org.to_str().unwrap())],
    );
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    assert_eq!(findings(&o, "YARA-SIGIL-TEST-MARKER").len(), 1);

    // Policy globs and severity overrides address YARA ids.
    std::fs::write(
        fx.proj.join(".sigil.yml"),
        "disable_rules: [YARA-SIGIL-TEST-MARKER]\n",
    )
    .unwrap();
    let o = sigil(
        &fx,
        &fx.proj,
        &[
            "--rules",
            fx.rules.to_str().unwrap(),
            "scan",
            ".",
            "--no-cache",
            "-f",
            "json",
        ],
        &[],
    );
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(findings(&o, "YARA-SIGIL-TEST-MARKER").is_empty());
    std::fs::remove_file(fx.proj.join(".sigil.yml")).unwrap();

    // An inline marker on the matched line silences the finding, with its
    // reason kept in the report.
    std::fs::write(
        fx.proj.join("src/app.txt"),
        format!("first line\nvalue = {MARKER}  # sigil:ignore YARA-SIGIL-TEST-MARKER -- fixture\n"),
    )
    .unwrap();
    let o = sigil(
        &fx,
        &fx.proj,
        &[
            "--rules",
            fx.rules.to_str().unwrap(),
            "scan",
            ".",
            "--no-cache",
            "-f",
            "json",
        ],
        &[],
    );
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(findings(&o, "YARA-SIGIL-TEST-MARKER").is_empty());
    assert!(stdout(&o).contains("fixture"));
}

#[test]
fn the_edges_of_an_oversized_files_head_and_tail_are_not_the_files_edges() {
    let fx = fixture();
    // 12 MB of text. The scanned head (the first 2,000,000 bytes) ends in the
    // middle of the word "SIGILab", and the scanned tail (the last 2,000,000)
    // starts in the middle of "zzMARK": neither is a whole word, and neither
    // edge is the start or end of the file.
    let mut data = vec![b'x'; 12 * 1024 * 1024];
    for (i, b) in data.iter_mut().enumerate() {
        if i % 64 == 63 {
            *b = b'\n';
        }
    }
    let n = data.len();
    let head_end = 2_000_000;
    data[head_end - 6..head_end + 2].copy_from_slice(b" SIGILab");
    let tail_start = n - 2_000_000;
    data[tail_start - 2..tail_start + 4].copy_from_slice(b"zzMARK");
    std::fs::write(fx.proj.join("big.txt"), &data).unwrap();
    let rule = fx.root.join("edges.yar");
    std::fs::write(
        &rule,
        "rule Edge_Word { strings: $a = \"SIGIL\" fullword condition: $a }\n\
         rule Edge_End { strings: $a = /SIGIL$/ condition: $a }\n\
         rule Edge_Start { strings: $a = /^MARK/ condition: $a }\n\
         rule Edge_Tail_Word { strings: $a = /\\bMARK/ condition: $a }\n\
         rule Edge_Plain { strings: $a = \"SIGIL\" $b = \"MARK\" condition: $a and $b }\n",
    )
    .unwrap();
    let o = sigil(
        &fx,
        &fx.proj,
        &[
            "--rules",
            rule.to_str().unwrap(),
            "scan",
            ".",
            "--no-cache",
            "-f",
            "json",
        ],
        &[],
    );
    // (The fixture's other files carry the markers too; only big.txt counts.)
    let on_big = |id: &str| {
        findings(&o, id)
            .into_iter()
            .filter(|f| f["file"].as_str().unwrap_or("").ends_with("big.txt"))
            .count()
    };
    for id in [
        "YARA-EDGE-WORD",
        "YARA-EDGE-END",
        "YARA-EDGE-START",
        "YARA-EDGE-TAIL-WORD",
    ] {
        assert_eq!(on_big(id), 0, "{id}: {}", stdout(&o));
    }
    // Both markers are in the scanned parts, so the plain rule fires.
    assert_eq!(on_big("YARA-EDGE-PLAIN"), 1, "{}", stdout(&o));
}

#[test]
fn an_oversized_binary_is_evaluated_on_its_head_and_tail_and_says_so() {
    let fx = fixture();
    // 12 MB of zeros with the marker bytes in the head, the middle and the
    // tail: only the head and tail (2 MB each) are read.
    let mut data = vec![0u8; 12 * 1024 * 1024];
    let n = data.len();
    let mid = n / 2;
    data[100..106].copy_from_slice(b"SIGIL\0");
    data[mid..mid + 6].copy_from_slice(b"SIGIL\0");
    data[n - 50..n - 44].copy_from_slice(b"SIGIL\0");
    std::fs::write(fx.proj.join("bin/big.dat"), &data).unwrap();
    let rule = fx.root.join("count.yar");
    std::fs::write(
        &rule,
        "rule Sigil_Count { meta: severity = \"low\" \
         strings: $h = { 53 49 47 49 4C 00 } \
         condition: #h == 2 and filesize > 10MB and $h at 100 }\n",
    )
    .unwrap();
    let o = sigil(
        &fx,
        &fx.proj,
        &[
            "--rules",
            rule.to_str().unwrap(),
            "scan",
            ".",
            "--no-cache",
            "-f",
            "json",
        ],
        &[],
    );
    let hits = findings(&o, "YARA-SIGIL-COUNT");
    assert_eq!(hits.len(), 1, "{}", stdout(&o));
    assert!(hits[0]["file"].as_str().unwrap().ends_with("big.dat"));
    assert!(hits[0]["snippet"]
        .as_str()
        .unwrap()
        .starts_with("[head/tail of oversized file]"));
    let gap = findings(&o, "PROV-INCOMPLETE-001");
    assert!(
        gap.iter()
            .any(|f| f["file"].as_str().unwrap().ends_with("big.dat")
                && f["snippet"].as_str().unwrap().contains("by the YARA rules")),
        "{}",
        stdout(&o)
    );
}

#[test]
fn invalid_yara_fails_closed_with_every_problem_and_its_line() {
    let fx = fixture();
    let bad = fx.root.join("bad.yar");
    std::fs::write(
        &bad,
        "import \"pe\"\n\
         rule Bad_One\n{\n    strings:\n        $a = \"SIGIL\" xor\n    condition:\n        $a and uint16(0) == 1\n}\n",
    )
    .unwrap();
    let bad = bad.to_str().unwrap();

    let o = sigil(
        &fx,
        &fx.proj,
        &["--rules", bad, "scan", ".", "--no-cache"],
        &[],
    );
    assert_eq!(code(&o), 2, "an invalid rule file stops the scan");
    let err = stderr(&o);
    for want in [
        format!("{bad}:1: `import \"pe\"`"),
        format!("{bad}:5: string $a: the `xor` modifier"),
        format!("{bad}:7: `uint16()`"),
    ] {
        assert!(err.contains(&want), "missing {want:?} in {err}");
    }

    let o = sigil(&fx, &fx.root, &["rules", "validate", bad], &[]);
    assert_eq!(code(&o), 1);
    assert_eq!(stdout(&o).matches('✗').count(), 3, "{}", stdout(&o));
    let o = sigil(
        &fx,
        &fx.root,
        &["rules", "validate", fx.rules.to_str().unwrap()],
        &[],
    );
    assert_eq!(code(&o), 0, "{}", stdout(&o));
    assert!(stdout(&o).contains("2 rule(s), yara form"));
    let o = sigil(&fx, &fx.root, &["rules", "validate", "missing.yar"], &[]);
    assert_eq!(code(&o), 2);
}

#[test]
fn a_yara_rule_cannot_redefine_an_existing_rule_id() {
    let fx = fixture();
    let copy = fx.root.join("again.yar");
    std::fs::write(&copy, RULES).unwrap();
    let o = sigil(
        &fx,
        &fx.proj,
        &[
            "--rules",
            fx.rules.to_str().unwrap(),
            "--rules",
            copy.to_str().unwrap(),
            "scan",
            ".",
            "--no-cache",
        ],
        &[],
    );
    assert_eq!(code(&o), 2);
    assert!(
        stderr(&o).contains("YARA-SIGIL-TEST-MARKER is already defined"),
        "{}",
        stderr(&o)
    );
}

#[test]
fn rules_list_show_and_test_include_yara_rules() {
    let fx = fixture();
    let rules = fx.rules.to_str().unwrap();
    let o = sigil(
        &fx,
        &fx.root,
        &["--rules", rules, "rules", "list", "--json"],
        &[],
    );
    assert_eq!(code(&o), 0);
    let doc = json(&o);
    let row = doc["rules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == "YARA-SIGIL-TEST-MARKER")
        .cloned()
        .expect("listed");
    assert_eq!(row["kind"], "yara");
    assert_eq!(row["origin"], "custom");
    assert_eq!(row["severity"], "HIGH");

    let o = sigil(
        &fx,
        &fx.root,
        &["--rules", rules, "rules", "show", "yara-sigil-test-marker"],
        &[],
    );
    assert_eq!(code(&o), 0);
    assert!(stdout(&o).contains("rule Sigil_Test_Marker"));

    let o = sigil(
        &fx,
        &fx.root,
        &["rules", "test", rules, fx.proj.to_str().unwrap()],
        &[],
    );
    assert_eq!(code(&o), 0);
    let out = stdout(&o);
    assert!(out.contains("[YARA-SIGIL-TEST-MARKER]"), "{out}");
    assert!(out.contains("[YARA-SIGIL-TEST-BYTES]"), "{out}");
}

#[test]
fn signed_yara_files_verify_and_unsigned_ones_are_refused_when_keyed() {
    let fx = fixture();
    let key = fx.root.join("signing.hex");
    std::fs::write(&key, "07".repeat(32)).unwrap();
    let rules = fx.rules.to_str().unwrap();
    let sig = format!("{rules}.sig");

    let o = sigil(
        &fx,
        &fx.root,
        &[
            "rules",
            "sign",
            rules,
            "--key",
            key.to_str().unwrap(),
            "-o",
            &sig,
        ],
        &[],
    );
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let public = stderr(&o)
        .split("SIGIL_PACK_PUBLIC_KEY=")
        .nth(1)
        .map(|s| s.trim().to_string())
        .expect("public key printed");
    let keyed = [("SIGIL_PACK_PUBLIC_KEY", public.as_str())];

    let o = sigil(
        &fx,
        &fx.proj,
        &["--rules", rules, "scan", ".", "--no-cache"],
        &keyed,
    );
    assert_eq!(code(&o), 1, "signed rules load and fire: {}", stderr(&o));

    let unsigned = fx.root.join("unsigned.yar");
    std::fs::write(&unsigned, RULES).unwrap();
    let o = sigil(
        &fx,
        &fx.proj,
        &[
            "--rules",
            unsigned.to_str().unwrap(),
            "scan",
            ".",
            "--no-cache",
        ],
        &keyed,
    );
    assert_eq!(code(&o), 2);
    assert!(stderr(&o).contains("[SECURITY]"), "{}", stderr(&o));

    // Editing a signed file breaks its signature.
    std::fs::write(&fx.rules, RULES.replace("\"high\"", "\"low\"")).unwrap();
    let o = sigil(
        &fx,
        &fx.proj,
        &["--rules", rules, "scan", ".", "--no-cache"],
        &keyed,
    );
    assert_eq!(code(&o), 2);
    assert!(
        stderr(&o).contains("signature verification failed"),
        "{}",
        stderr(&o)
    );
}
