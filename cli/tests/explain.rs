//! US-111: `sigil explain` — integration tests against a stdlib mock API server.
//!
//! The CLI must post the finding to the Sigil API (no client-side LLM call) and
//! render the adjudication verdict; 402 maps to a clear upgrade message.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;

/// A canned HTTP response for one (method, path-prefix) route.
struct Route {
    method: &'static str,
    path_prefix: String,
    status: &'static str,
    body: String,
}

/// Spawn a minimal HTTP server answering `routes` for up to `max_conns`
/// connections. Returns the base URL.
fn spawn_mock_api(routes: Vec<Route>, max_conns: usize) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock api");
    let addr = listener.local_addr().unwrap();

    std::thread::spawn(move || {
        for _ in 0..max_conns {
            let (mut stream, _) = match listener.accept() {
                Ok(c) => c,
                Err(_) => return,
            };
            let mut buf = Vec::new();
            let mut tmp = [0u8; 4096];
            // Read until end of headers, then honour Content-Length.
            let (mut header_end, mut content_len) = (0usize, 0usize);
            loop {
                let n = match stream.read(&mut tmp) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                buf.extend_from_slice(&tmp[..n]);
                if header_end == 0 {
                    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        header_end = pos + 4;
                        let headers = String::from_utf8_lossy(&buf[..header_end]);
                        for line in headers.lines() {
                            let lower = line.to_ascii_lowercase();
                            if let Some(v) = lower.strip_prefix("content-length:") {
                                content_len = v.trim().parse().unwrap_or(0);
                            }
                        }
                    }
                }
                if header_end > 0 && buf.len() >= header_end + content_len {
                    break;
                }
            }
            let request = String::from_utf8_lossy(&buf).to_string();
            let request_line = request.lines().next().unwrap_or("").to_string();

            let matched = routes.iter().find(|r| {
                request_line.starts_with(r.method)
                    && request_line.contains(&r.path_prefix)
            });
            let (status, body) = match matched {
                Some(r) => (r.status, r.body.clone()),
                None => ("404 Not Found", r#"{"detail":"mock: no route"}"#.into()),
            };
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status,
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });

    format!("http://{}", addr)
}

/// A scan-JSON file shaped like real `sigil scan -f json` output:
/// banner line, summary object, findings array, verdict object.
fn write_scan_json(dir: &std::path::Path) -> std::path::PathBuf {
    let content = r#"sigil: scanning /tmp/pkg...
{
  "duration_ms": 10,
  "files_scanned": 3,
  "findings_count": 2,
  "score": 12,
  "suppressed_count": 0,
  "verdict": "HIGH RISK"
}
[
  {"phase":"NetworkExfil","rule":"NET-006","severity":"High","file":"package/index.js","line":7,"snippet":"fetch('https://example.com/hook')","weight":3},
  {"phase":"CodePatterns","rule":"code-eval","severity":"High","file":"package/lib.js","line":42,"snippet":"eval(payload)","weight":5}
]
{"verdict":"HIGH RISK"}
"#;
    let path = dir.join("scan.json");
    std::fs::write(&path, content).unwrap();
    path
}

/// Home dir containing a stored API token, so the CLI authenticates.
fn write_home_with_token(dir: &std::path::Path) -> std::path::PathBuf {
    let home = dir.join("home");
    std::fs::create_dir_all(home.join(".sigil")).unwrap();
    std::fs::write(home.join(".sigil").join("token"), "test-token-abc").unwrap();
    home
}

fn run_explain(
    scan_json: &std::path::Path,
    home: &std::path::Path,
    endpoint: &str,
    finding: usize,
) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sigil"))
        .args([
            "explain",
            scan_json.to_str().unwrap(),
            "--finding",
            &finding.to_string(),
            "--endpoint",
            endpoint,
        ])
        .env("HOME", home)
        .output()
        .expect("run sigil explain")
}

#[test]
fn explain_renders_verdict_on_success() {
    let tmp = tempfile::tempdir().unwrap();
    let scan_json = write_scan_json(tmp.path());
    let home = write_home_with_token(tmp.path());

    let endpoint = spawn_mock_api(
        vec![
            Route {
                method: "POST",
                path_prefix: "/v1/scans/s-123/findings/0/adjudicate".into(),
                status: "200 OK",
                body: r#"{"scan_id":"s-123","finding_index":0,"adjudication":{"classification":"benign_dual_use","confidence":0.91,"rationale":"Config-literal webhook URL in changelog text; no taint path.","model":"claude-fable-5","adjudicated_at":"2026-06-11T00:00:00"}}"#.into(),
            },
            Route {
                method: "POST",
                path_prefix: "/v1/scan".into(),
                status: "200 OK",
                body: r#"{"scan_id":"s-123","target":"pkg","target_type":"directory","files_scanned":3,"findings":[],"risk_score":12.0,"verdict":"HIGH_RISK"}"#.into(),
            },
        ],
        4,
    );

    let out = run_explain(&scan_json, &home, &endpoint, 0);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "expected success, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("benign_dual_use"), "stdout: {stdout}");
    assert!(stdout.contains("no taint path"), "stdout: {stdout}");
    assert!(stdout.contains("claude-fable-5"), "stdout: {stdout}");
}

#[test]
fn explain_maps_402_to_upgrade_message() {
    let tmp = tempfile::tempdir().unwrap();
    let scan_json = write_scan_json(tmp.path());
    let home = write_home_with_token(tmp.path());

    let endpoint = spawn_mock_api(
        vec![
            Route {
                method: "POST",
                path_prefix: "/adjudicate".into(),
                status: "402 Payment Required",
                body: r#"{"detail":{"detail":"LLM analysis allowance exhausted for your plan. Upgrade to Pro for unmetered AI analysis.","reason":"allowance_exhausted","balance":0,"credits_required":4,"reset_date":"2026-07-01T00:00:00","upgrade_url":"https://www.sigilsec.ai/pricing"}}"#.into(),
            },
            Route {
                method: "POST",
                path_prefix: "/v1/scan".into(),
                status: "200 OK",
                body: r#"{"scan_id":"s-123","target":"pkg","target_type":"directory","files_scanned":3,"findings":[],"risk_score":12.0,"verdict":"HIGH_RISK"}"#.into(),
            },
        ],
        4,
    );

    let out = run_explain(&scan_json, &home, &endpoint, 0);
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!out.status.success());
    assert!(
        combined.to_lowercase().contains("upgrade"),
        "expected upgrade message, got: {combined}"
    );
    assert!(
        combined.contains("https://www.sigilsec.ai/pricing"),
        "expected upgrade url, got: {combined}"
    );
}

#[test]
fn explain_finding_index_out_of_range_fails_clearly() {
    let tmp = tempfile::tempdir().unwrap();
    let scan_json = write_scan_json(tmp.path());
    let home = write_home_with_token(tmp.path());

    // No API needed — the index check happens before any network call.
    let out = run_explain(&scan_json, &home, "http://127.0.0.1:9", 99);
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!out.status.success());
    assert!(
        combined.contains("99") && combined.to_lowercase().contains("finding"),
        "expected out-of-range message, got: {combined}"
    );
}

#[test]
fn explain_without_token_asks_for_login() {
    let tmp = tempfile::tempdir().unwrap();
    let scan_json = write_scan_json(tmp.path());
    let home = tmp.path().join("empty-home");
    std::fs::create_dir_all(&home).unwrap();

    let out = run_explain(&scan_json, &home, "http://127.0.0.1:9", 0);
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!out.status.success());
    assert!(
        combined.to_lowercase().contains("login"),
        "expected login hint, got: {combined}"
    );
}
