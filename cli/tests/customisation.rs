//! End-to-end tests of the customisation surface: scan policies, custom rule
//! packs, baselines, report formats and the exit-code contract (ADR-0010).
//!
//! Every test runs the real binary against a temporary tree with an isolated
//! HOME. Findings come from a custom rule matching an inert marker string, so
//! this file contains no attack patterns and the fixtures are harmless.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const MARKER: &str = "ACME_TEST_MARKER_42";

const PACK: &str = r#"
pack: {id: e2e-rules, name: e2e}
rules:
  - id: E2E-001
    pattern: 'ACME_TEST_MARKER_\d+'
    severity: high
    description: Test marker
    remediation: Remove the test marker.
"#;

struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
    home: PathBuf,
    proj: PathBuf,
    pack: PathBuf,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().to_path_buf();
    let home = root.join("home");
    let proj = root.join("proj");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(proj.join("src")).unwrap();
    std::fs::write(proj.join("src/app.txt"), format!("value = {MARKER}\n")).unwrap();
    std::fs::write(proj.join("src/readme.txt"), "nothing to see\n").unwrap();
    let pack = root.join("pack.yaml");
    std::fs::write(&pack, PACK).unwrap();
    Fixture {
        _dir: dir,
        root,
        home,
        proj,
        pack,
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

fn json(o: &Output) -> serde_json::Value {
    serde_json::from_slice(&o.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout is not one JSON document: {e}\n{}",
            String::from_utf8_lossy(&o.stdout)
        )
    })
}

#[test]
fn scan_exit_codes_follow_adr_0010() {
    let fx = fixture();
    let pack = fx.pack.to_str().unwrap();

    let clean = sigil(&fx, &fx.proj, &["scan", ".", "--no-cache"], &[]);
    assert_eq!(code(&clean), 0, "{}", stderr(&clean));

    let flagged = sigil(
        &fx,
        &fx.proj,
        &["--rules", pack, "scan", ".", "--no-cache"],
        &[],
    );
    assert_eq!(
        code(&flagged),
        1,
        "a HIGH finding must fail the default gate"
    );

    let raised = sigil(
        &fx,
        &fx.proj,
        &[
            "--rules",
            pack,
            "scan",
            ".",
            "--no-cache",
            "--fail-on",
            "critical",
        ],
        &[],
    );
    assert_eq!(code(&raised), 0);

    let verdict_gate = sigil(
        &fx,
        &fx.proj,
        &[
            "--rules",
            pack,
            "scan",
            ".",
            "--no-cache",
            "--fail-on",
            "critical",
            "--fail-on-verdict",
            "low",
        ],
        &[],
    );
    assert_eq!(
        code(&verdict_gate),
        1,
        "fail_on_verdict LOW fails any verdict"
    );

    for args in [
        vec!["scan", "does-not-exist"],
        vec!["scan", ".", "--fail-on", "severe"],
        vec!["scan", ".", "--fail-on-verdict", "bad"],
        vec!["scan", ".", "-f", "xml"],
        vec!["--rules", "missing-pack.yaml", "scan", "."],
        vec!["scan", ".", "--baseline", "missing-baseline.json"],
    ] {
        let o = sigil(&fx, &fx.proj, &args, &[]);
        assert_eq!(
            code(&o),
            2,
            "{args:?} must be an error, not a verdict: {}",
            stderr(&o)
        );
    }
}

#[test]
fn project_policy_suppresses_with_attribution_and_the_guard_protects_foreign_trees() {
    let fx = fixture();
    let pack = fx.pack.to_str().unwrap();
    std::fs::write(
        fx.proj.join(".sigil.yml"),
        "disable_rules: [E2E-*]\nfail_on: high\n",
    )
    .unwrap();

    // Working inside the tree: the policy is trusted.
    let inside = sigil(
        &fx,
        &fx.proj,
        &["--rules", pack, "scan", ".", "--no-cache", "-f", "json"],
        &[],
    );
    assert_eq!(code(&inside), 0, "{}", stderr(&inside));
    let doc = json(&inside);
    assert!(
        doc["findings"].as_array().unwrap().is_empty(),
        "{}",
        doc["findings"]
    );
    let suppressed = doc["policy"]["suppressed"].as_array().unwrap();
    let e2e = suppressed
        .iter()
        .find(|s| s["rule"] == "E2E-001")
        .expect("the disabled rule's finding is kept, attributed");
    assert_eq!(e2e["suppression"], "disabled_rule");
    assert!(e2e["suppressed_by"]
        .as_str()
        .unwrap()
        .contains(".sigil.yml"));
    // The policy file itself is configuration, not a finding (it is a
    // dotfile, which the hidden-file rule reports elsewhere).
    assert!(suppressed
        .iter()
        .filter(|s| s["rule"] != "E2E-001")
        .all(|s| s["suppression"] == "config_file"));

    // Auditing the same tree from outside: its policy cannot switch the rule off.
    let outside = sigil(
        &fx,
        &fx.root,
        &["--rules", pack, "scan", "proj", "--no-cache", "-f", "json"],
        &[],
    );
    assert_eq!(code(&outside), 1, "{}", stderr(&outside));
    assert!(stderr(&outside).contains("refused"));
    let doc = json(&outside);
    assert!(doc["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["rule"] == "E2E-001"));
    assert!(!doc["policy"]["refused"].as_array().unwrap().is_empty());

    // Vouching for it explicitly applies it.
    let vouched = sigil(
        &fx,
        &fx.root,
        &[
            "--rules",
            pack,
            "--config",
            "proj/.sigil.yml",
            "scan",
            "proj",
            "--no-cache",
        ],
        &[],
    );
    assert_eq!(code(&vouched), 0, "{}", stderr(&vouched));

    // And discovery can be switched off.
    let off = sigil(
        &fx,
        &fx.proj,
        &[
            "--rules",
            pack,
            "scan",
            ".",
            "--no-cache",
            "--no-project-config",
        ],
        &[],
    );
    assert_eq!(code(&off), 1);
}

#[test]
fn organisation_policy_locks_keys_and_fails_closed() {
    let fx = fixture();
    let pack = fx.pack.to_str().unwrap();
    let org = fx.root.join("org.yml");
    std::fs::write(&org, "fail_on: high\nlocked: [fail_on, disable_rules]\n").unwrap();
    std::fs::write(
        fx.proj.join(".sigil.yml"),
        "disable_rules: [E2E-001]\nfail_on: critical\n",
    )
    .unwrap();
    let org_env = [("SIGIL_POLICY_FILE", org.to_str().unwrap())];

    let o = sigil(
        &fx,
        &fx.proj,
        &["--rules", pack, "scan", ".", "--no-cache", "-f", "json"],
        &org_env,
    );
    assert_eq!(
        code(&o),
        1,
        "locked keys cannot be loosened: {}",
        stderr(&o)
    );
    let refused = json(&o)["policy"]["refused"].as_array().unwrap().len();
    assert_eq!(refused, 2);

    // A flag cannot loosen a locked key either.
    let o = sigil(
        &fx,
        &fx.proj,
        &[
            "--rules",
            pack,
            "scan",
            ".",
            "--no-cache",
            "--fail-on",
            "critical",
        ],
        &org_env,
    );
    assert_eq!(code(&o), 1);

    let missing = fx.root.join("nope.yml");
    let o = sigil(
        &fx,
        &fx.proj,
        &["scan", ".", "--no-cache"],
        &[("SIGIL_POLICY_FILE", missing.to_str().unwrap())],
    );
    assert_eq!(code(&o), 2, "an unreadable organisation policy is an error");
}

#[test]
fn baseline_accepts_todays_findings_and_fails_on_new_ones() {
    let fx = fixture();
    let pack = fx.pack.to_str().unwrap();

    let o = sigil(
        &fx,
        &fx.proj,
        &["--rules", pack, "baseline", ".", "--reason", "adopted"],
        &[],
    );
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let written = fx.proj.join(".sigil-baseline.json");
    let text = std::fs::read_to_string(&written).unwrap();
    assert!(
        !text.contains(MARKER),
        "the baseline stores hashes, not matched text"
    );

    let o = sigil(
        &fx,
        &fx.proj,
        &[
            "--rules",
            pack,
            "scan",
            ".",
            "--no-cache",
            "--baseline",
            ".sigil-baseline.json",
            "-f",
            "json",
        ],
        &[],
    );
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let doc = json(&o);
    assert_eq!(doc["summary"]["baseline_suppressed_count"], 1);
    assert!(
        doc["findings"].as_array().unwrap().is_empty(),
        "the baseline file itself must not become a finding: {}",
        doc["findings"]
    );

    // Code moves down the file: still accepted.
    std::fs::write(
        fx.proj.join("src/app.txt"),
        format!("\n\n\nvalue = {MARKER}\n"),
    )
    .unwrap();
    let o = sigil(
        &fx,
        &fx.proj,
        &[
            "--rules",
            pack,
            "scan",
            ".",
            "--no-cache",
            "--baseline",
            ".sigil-baseline.json",
        ],
        &[],
    );
    assert_eq!(code(&o), 0, "line drift must not revive a finding");

    // A new occurrence fails.
    std::fs::write(fx.proj.join("src/new.txt"), format!("{MARKER}\n")).unwrap();
    let o = sigil(
        &fx,
        &fx.proj,
        &[
            "--rules",
            pack,
            "scan",
            ".",
            "--no-cache",
            "--baseline",
            ".sigil-baseline.json",
        ],
        &[],
    );
    assert_eq!(code(&o), 1);
}

#[test]
fn report_formats_and_output_file() {
    let fx = fixture();
    let pack = fx.pack.to_str().unwrap();
    for (format, needle) in [
        ("junit", "<testsuites"),
        ("markdown", "Sigil scan"),
        ("sarif", "\"version\": \"2.1.0\""),
        ("json", "\"findings\""),
        ("text", "E2E-001"),
    ] {
        let dest = fx.root.join(format!("report.{format}"));
        let o = sigil(
            &fx,
            &fx.proj,
            &[
                "--rules",
                pack,
                "scan",
                ".",
                "--no-cache",
                "-f",
                format,
                "-o",
                dest.to_str().unwrap(),
            ],
            &[],
        );
        assert_eq!(code(&o), 1, "{format}: the gate still applies with -o");
        let text = std::fs::read_to_string(&dest).unwrap();
        assert!(
            text.contains(needle),
            "{format} report lacks {needle}:\n{text}"
        );
        if format != "text" {
            assert!(
                o.stdout.is_empty(),
                "{format}: with -o nothing but progress belongs on stdout"
            );
        }
        if format == "junit" {
            assert!(text.contains("<failure type=\"E2E-001\""));
        }
    }

    // A command that does not write a report refuses -o instead of ignoring
    // it and leaving a CI step to read a file that was never written.
    let dest = fx.root.join("corpus.txt");
    let o = sigil(
        &fx,
        &fx.proj,
        &["corpus", "-o", dest.to_str().unwrap()],
        &[],
    );
    assert_eq!(code(&o), 2, "{}", stderr(&o));
    assert!(stderr(&o).contains("--output is not supported"));
    assert!(!dest.exists());
}

/// A custom correlation rule with a key this version does not know (a note
/// for the owning team) loaded before correlation-rule keys were checked. A
/// scan still runs with the pack, ignores the key and says so on stderr;
/// `sigil rules validate` and `sigil config --validate` reject it.
#[test]
fn an_unknown_correlation_key_warns_in_a_scan_and_fails_validation() {
    let fx = fixture();
    let extra = fx.root.join("pack_extra.json");
    std::fs::write(
        &extra,
        r#"{"meta":{"id":"acme","name":"acme","version":"1","updated_at":"2026-01-01","author":"a","description":"d"},
 "correlation_rules":[{"id":"ACME-CHAIN-001","phase":"network_exfil","severity":"high","description":"acme chain",
   "source":{"rule_prefixes":["CRED-"],"rule_ids":[]},"sink":{"rule_prefixes":[],"rule_ids":["NET-001"]},
   "window_lines":20,"sink_excludes":[],"notes":"owned by the platform team"}]}"#,
    )
    .unwrap();
    let extra = extra.to_str().unwrap();
    let proj = fx.proj.to_str().unwrap();
    let o = sigil(
        &fx,
        &fx.root,
        &[
            "--rules",
            extra,
            "--format",
            "json",
            "scan",
            proj,
            "--no-cache",
        ],
        &[],
    );
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(json(&o)["findings"].is_array());
    let err = stderr(&o);
    assert!(
        err.contains("correlation_rules[0] (ACME-CHAIN-001): unknown key 'notes'")
            && err.contains("ignored"),
        "{err}"
    );

    let o = sigil(&fx, &fx.root, &["rules", "validate", extra], &[]);
    assert_eq!(code(&o), 1);
    assert!(String::from_utf8_lossy(&o.stdout).contains("unknown key 'notes'"));

    let policy = fx.root.join("policy.yml");
    std::fs::write(&policy, format!("rule_packs:\n  - {extra}\n")).unwrap();
    let o = sigil(
        &fx,
        &fx.root,
        &["config", "--validate", policy.to_str().unwrap()],
        &[],
    );
    assert_eq!(code(&o), 1, "{}", String::from_utf8_lossy(&o.stdout));
    assert!(String::from_utf8_lossy(&o.stdout).contains("unknown key 'notes'"));
}

#[test]
fn rules_and_config_commands_follow_the_contract() {
    let fx = fixture();
    let pack = fx.pack.to_str().unwrap();

    let o = sigil(&fx, &fx.root, &["rules", "validate", pack], &[]);
    assert_eq!(code(&o), 0, "{}", String::from_utf8_lossy(&o.stdout));
    let bad = fx.root.join("bad.yaml");
    std::fs::write(
        &bad,
        "rules:\n  - {id: bad_id, pattern: '(', severity: huge, description: d}\n",
    )
    .unwrap();
    let o = sigil(
        &fx,
        &fx.root,
        &["rules", "validate", bad.to_str().unwrap()],
        &[],
    );
    assert_eq!(code(&o), 1);
    let o = sigil(&fx, &fx.root, &["rules", "validate", "missing.yaml"], &[]);
    assert_eq!(code(&o), 2);

    let o = sigil(
        &fx,
        &fx.root,
        &["--rules", pack, "rules", "list", "--json"],
        &[],
    );
    assert_eq!(code(&o), 0);
    let doc = json(&o);
    assert!(doc["rules"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["id"] == "E2E-001" && r["origin"] == "custom"));

    let o = sigil(
        &fx,
        &fx.root,
        &["--rules", pack, "rules", "show", "e2e-001"],
        &[],
    );
    assert_eq!(code(&o), 0);
    assert!(String::from_utf8_lossy(&o.stdout).contains("Remove the test marker."));
    let o = sigil(&fx, &fx.root, &["rules", "show", "NOPE-999"], &[]);
    assert_eq!(code(&o), 2);

    let good = fx.root.join("good.yml");
    std::fs::write(&good, "fail_on: medium\n").unwrap();
    let broken = fx.root.join("broken.yml");
    std::fs::write(&broken, "fail_onn: medium\n").unwrap();
    let o = sigil(
        &fx,
        &fx.root,
        &["config", "--validate", good.to_str().unwrap()],
        &[],
    );
    assert_eq!(code(&o), 0);
    let o = sigil(
        &fx,
        &fx.root,
        &["config", "--validate", broken.to_str().unwrap()],
        &[],
    );
    assert_eq!(code(&o), 1);
    assert!(String::from_utf8_lossy(&o.stdout).contains("did you mean 'fail_on'"));
    let o = sigil(&fx, &fx.root, &["config", "--validate", "missing.yml"], &[]);
    assert_eq!(code(&o), 2);
}

#[test]
fn diff_reports_new_findings_as_one_not_two() {
    let fx = fixture();
    let pack = fx.pack.to_str().unwrap();
    std::fs::remove_file(fx.proj.join("src/app.txt")).unwrap();
    let base = fx.root.join("base.json");
    let o = sigil(
        &fx,
        &fx.proj,
        &[
            "--rules",
            pack,
            "scan",
            ".",
            "--no-cache",
            "-f",
            "json",
            "-o",
            base.to_str().unwrap(),
        ],
        &[],
    );
    assert_eq!(code(&o), 0);
    std::fs::write(fx.proj.join("src/app.txt"), format!("{MARKER}\n")).unwrap();
    let o = sigil(
        &fx,
        &fx.proj,
        &[
            "--rules",
            pack,
            "diff",
            "--baseline",
            base.to_str().unwrap(),
            ".",
        ],
        &[],
    );
    assert_eq!(code(&o), 1, "new findings are a gate failure, not an error");
    let o = sigil(
        &fx,
        &fx.proj,
        &["diff", "--baseline", "missing.json", "."],
        &[],
    );
    assert_eq!(code(&o), 2);
}

#[test]
fn skills_refuses_a_project_that_is_not_a_directory() {
    // An inventory of a mistyped --project would find nothing and pass.
    let fx = fixture();
    let missing = fx.root.join("no-such-project");
    let file = fx.root.join("pack.yaml");
    for bad in [&missing, &file] {
        let o = sigil(
            &fx,
            &fx.root,
            &[
                "skills",
                "scan",
                "--no-user",
                "--project",
                bad.to_str().unwrap(),
            ],
            &[],
        );
        assert_eq!(code(&o), 2, "{}: {}", bad.display(), stderr(&o));
        assert!(stderr(&o).contains("--project is not a directory"));
    }
    let o = sigil(
        &fx,
        &fx.root,
        &[
            "skills",
            "scan",
            "--no-user",
            "--project",
            fx.proj.to_str().unwrap(),
        ],
        &[],
    );
    assert_ne!(code(&o), 2, "{}", stderr(&o));
}
