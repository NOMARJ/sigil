//! End-to-end tests of `sigil scan --llm-review` against a local mock of the
//! Anthropic Messages API (a `TcpListener` on 127.0.0.1). No test reaches a
//! real provider.
//!
//! Findings come from a custom rule matching an inert marker string, so this
//! file contains no attack patterns.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};

const PACK: &str = r#"
pack: {id: e2e-llm, name: e2e}
rules:
  - id: E2E-LLM-001
    pattern: 'ACME_LLM_MARKER_\d+'
    severity: high
    description: Test marker
    remediation: Remove the test marker.
"#;

struct Fixture {
    _dir: tempfile::TempDir,
    home: PathBuf,
    proj: PathBuf,
    pack: PathBuf,
    root: PathBuf,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().to_path_buf();
    let home = root.join("home");
    let proj = root.join("proj");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(proj.join("src")).unwrap();
    let mut app = String::new();
    for i in 1..=12 {
        app.push_str(&format!("line_{i} = {i}\n"));
    }
    app.push_str("value = ACME_LLM_MARKER_42\n");
    std::fs::write(proj.join("src/app.txt"), app).unwrap();
    let pack = root.join("pack.yaml");
    std::fs::write(&pack, PACK).unwrap();
    Fixture {
        _dir: dir,
        home,
        proj,
        pack,
        root,
    }
}

/// A mock Messages API that answers every finding with `verdict` and
/// records each request body.
struct Mock {
    base: String,
    bodies: Arc<Mutex<Vec<String>>>,
}

fn mock(verdict: &'static str) -> Mock {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let bodies: Arc<Mutex<Vec<String>>> = Arc::default();
    let seen = bodies.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            let mut headers = HashMap::new();
            let _ = reader.read_line(&mut line);
            loop {
                line.clear();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line.trim().is_empty() {
                    break;
                }
                if let Some((k, v)) = line.split_once(':') {
                    headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
                }
            }
            let len: usize = headers
                .get("content-length")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            let mut body = vec![0u8; len];
            let _ = reader.read_exact(&mut body);
            let body = String::from_utf8_lossy(&body).to_string();
            seen.lock().unwrap().push(body.clone());

            let req: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
            let user = req["messages"][0]["content"].as_str().unwrap_or_default();
            let doc: serde_json::Value = user
                .split_once('\n')
                .and_then(|(_, d)| serde_json::from_str(d).ok())
                .unwrap_or_default();
            let reviews: Vec<serde_json::Value> = doc["findings"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .iter()
                .map(|f| {
                    serde_json::json!({"id": f["id"], "verdict": verdict, "rationale": "inert test marker"})
                })
                .collect();
            let text = serde_json::json!({ "reviews": reviews }).to_string();
            let reply = serde_json::json!({
                "type": "message", "role": "assistant", "model": "claude-opus-5",
                "content": [{"type": "text", "text": text}],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 500, "output_tokens": 40}
            })
            .to_string();
            let mut out = stream;
            let _ = write!(
                out,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                reply.len(),
                reply
            );
        }
    });
    Mock { base, bodies }
}

fn sigil(fx: &Fixture, cwd: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sigil"));
    cmd.args(args)
        .current_dir(cwd)
        .env("HOME", &fx.home)
        .env_remove("SIGIL_POLICY_FILE")
        .env_remove("SIGIL_PACK_PUBLIC_KEY")
        .env_remove("SIGIL_NO_PROJECT_CONFIG")
        .env_remove("ANTHROPIC_API_KEY")
        .env_remove("ANTHROPIC_BASE_URL")
        .env_remove("SIGIL_LLM_ENDPOINT")
        .env_remove("SIGIL_LLM_API_KEY")
        .env_remove("SIGIL_LLM_MODEL")
        .env_remove("SIGIL_LLM_TIMEOUT_SECS");
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().expect("run sigil")
}

fn json(o: &Output) -> serde_json::Value {
    serde_json::from_slice(&o.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout is not one JSON document: {e}\n{}\n{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        )
    })
}

fn scan_args<'a>(fx: &'a Fixture, extra: &[&'a str]) -> Vec<&'a str> {
    let mut a = vec![
        "--rules",
        fx.pack.to_str().unwrap(),
        "scan",
        fx.proj.to_str().unwrap(),
        "--no-cache",
    ];
    a.extend_from_slice(extra);
    a
}

#[test]
fn without_the_flag_nothing_is_sent() {
    let fx = fixture();
    let m = mock("confirm");
    let env = [
        ("ANTHROPIC_API_KEY", "test-key"),
        ("ANTHROPIC_BASE_URL", m.base.as_str()),
    ];
    let out = sigil(&fx, &fx.root, &scan_args(&fx, &["--format", "json"]), &env);
    assert_eq!(out.status.code(), Some(1), "the High marker fails the gate");
    let doc = json(&out);
    assert!(doc.get("llm_review").is_none());
    assert!(
        m.bodies.lock().unwrap().is_empty(),
        "the scan stayed offline"
    );
}

#[test]
fn advisory_review_annotates_json_sarif_and_markdown_without_changing_the_gate() {
    let fx = fixture();
    let m = mock("dismiss");
    let env = [
        ("ANTHROPIC_API_KEY", "test-key"),
        ("ANTHROPIC_BASE_URL", m.base.as_str()),
    ];
    let out = sigil(
        &fx,
        &fx.root,
        &scan_args(&fx, &["--llm-review", "--format", "json"]),
        &env,
    );
    assert_eq!(
        out.status.code(),
        Some(1),
        "a dismissal is advice: the gate still fails"
    );
    let doc = json(&out);
    let block = &doc["llm_review"];
    assert_eq!(block["status"], "complete", "{block}");
    assert_eq!(block["mode"], "advisory");
    assert_eq!(block["model"], "claude-opus-5");
    assert_eq!(block["dismissed"], 1);
    assert_eq!(block["downgraded"], 0);
    let f = doc["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["rule"] == "E2E-LLM-001")
        .unwrap();
    assert_eq!(f["severity"], "High");
    assert_eq!(f["llm_review"]["verdict"], "dismiss");
    assert_eq!(f["llm_review"]["action"], "not_applied");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.find('[').unwrap() < stdout.find("llm_review").unwrap(),
        "the findings array is still the first array"
    );
    let bodies = m.bodies.lock().unwrap().clone();
    assert_eq!(bodies.len(), 1);
    assert!(bodies[0].contains("ACME_LLM_MARKER_42"));
    assert!(
        bodies[0].contains("line_7 = 7"),
        "surrounding lines are sent"
    );
    assert!(!bodies[0].contains("line_2 = 2"), "only a bounded window");

    let sarif = sigil(
        &fx,
        &fx.root,
        &scan_args(&fx, &["--llm-review", "--format", "sarif"]),
        &env,
    );
    let doc = json(&sarif);
    let run = &doc["runs"][0];
    let result = run["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["ruleId"] == "E2E-LLM-001")
        .unwrap();
    assert_eq!(result["properties"]["llmReview"]["verdict"], "dismiss");
    assert_eq!(result["level"], "error");
    assert_eq!(
        run["invocations"][0]["properties"]["llmReview"]["status"],
        "complete"
    );

    let md = sigil(
        &fx,
        &fx.root,
        &scan_args(&fx, &["--llm-review", "--format", "markdown"]),
        &env,
    );
    let md = String::from_utf8_lossy(&md.stdout);
    assert!(md.contains("### LLM review"), "{md}");
    assert!(md.contains("not applied"), "{md}");
}

#[test]
fn a_trusted_policy_can_allow_downgrades() {
    let fx = fixture();
    let m = mock("dismiss");
    let policy = fx.root.join("policy.yml");
    std::fs::write(&policy, "llm_review: true\nllm_may_downgrade: true\n").unwrap();
    let env = [
        ("ANTHROPIC_API_KEY", "test-key"),
        ("ANTHROPIC_BASE_URL", m.base.as_str()),
    ];
    let mut args = vec!["--config", policy.to_str().unwrap()];
    args.extend(scan_args(&fx, &["--format", "json"]));
    let out = sigil(&fx, &fx.root, &args, &env);
    let doc = json(&out);
    assert_eq!(doc["llm_review"]["mode"], "downgrade_allowed");
    assert_eq!(doc["llm_review"]["downgraded"], 1);
    let f = doc["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["rule"] == "E2E-LLM-001")
        .unwrap();
    assert_eq!(f["severity"], "Medium");
    assert_eq!(f["llm_review"]["original_severity"], "HIGH");
    assert_eq!(
        out.status.code(),
        Some(0),
        "the policy allowed the downgrade, so the High gate passes"
    );
}

#[test]
fn a_missing_key_is_reported_and_never_changes_the_exit_code() {
    let fx = fixture();
    let out = sigil(
        &fx,
        &fx.root,
        &scan_args(&fx, &["--llm-review", "--format", "json"]),
        &[],
    );
    assert_eq!(out.status.code(), Some(1));
    let doc = json(&out);
    assert_eq!(doc["llm_review"]["status"], "not_run");
    assert!(doc["llm_review"]["incomplete_reasons"][0]
        .as_str()
        .unwrap()
        .contains("ANTHROPIC_API_KEY"));
    assert!(String::from_utf8_lossy(&out.stderr).contains("LLM review did not run"));
}

#[test]
fn the_organisation_can_forbid_the_stage_and_scanned_trees_cannot_enable_it() {
    let fx = fixture();
    let m = mock("confirm");
    let env_base = [
        ("ANTHROPIC_API_KEY", "test-key"),
        ("ANTHROPIC_BASE_URL", m.base.as_str()),
    ];

    // The organisation locks the stage off: the flag is refused.
    let org = fx.root.join("org.yml");
    std::fs::write(&org, "llm_review: false\nlocked: [llm_review]\n").unwrap();
    let mut env = env_base.to_vec();
    env.push(("SIGIL_POLICY_FILE", org.to_str().unwrap()));
    let out = sigil(
        &fx,
        &fx.root,
        &scan_args(&fx, &["--llm-review", "--format", "json"]),
        &env,
    );
    let doc = json(&out);
    assert!(doc.get("llm_review").is_none());
    assert!(String::from_utf8_lossy(&out.stderr).contains("llm_review: command line"));

    // A .sigil.yml inside a tree scanned from outside cannot switch it on.
    std::fs::write(fx.proj.join(".sigil.yml"), "llm_review: true\n").unwrap();
    let out = sigil(
        &fx,
        &fx.root,
        &scan_args(&fx, &["--format", "json"]),
        &env_base,
    );
    let doc = json(&out);
    assert!(doc.get("llm_review").is_none());
    assert!(String::from_utf8_lossy(&out.stderr).contains("llm_review"));
    assert!(
        m.bodies.lock().unwrap().is_empty(),
        "nothing was sent in either case"
    );
}
