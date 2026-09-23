//! Built-in MCP server: `sigil mcp` speaks the Model Context Protocol over
//! stdio, so any MCP-capable agent can gate installs on a Sigil verdict with
//! nothing to install beyond the `sigil` binary itself:
//!
//! ```text
//! claude mcp add sigil -- sigil mcp
//! ```
//!
//! The transport is newline-delimited JSON-RPC 2.0 on stdin/stdout (the MCP
//! stdio transport). Diagnostics go to stderr only; stdout carries protocol
//! messages and nothing else.
//!
//! Tools run the same code paths as the CLI by re-invoking this binary with
//! `--format json`, rather than calling the scanner in-process: a scan that
//! panics or exits takes down one child process, not the server the agent is
//! talking to, and every CLI behaviour (quarantine, trust ledger, cache,
//! policy) applies unchanged.

use std::io::{BufRead, Write};
use std::process::Command;

use serde_json::{json, Value};

use crate::hook;

/// Protocol revisions this server implements, newest first. The server
/// answers `initialize` with the client's requested revision when it is one
/// of these, and with the newest otherwise, as the specification requires.
const PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];

/// How many findings a tool result carries inline. The full list is in the
/// CLI's JSON report; an agent deciding whether to install needs the verdict
/// and the worst few findings, not a 2,000-entry array in its context.
const MAX_FINDINGS_INLINE: usize = 25;

/// Longest snippet returned per finding, in characters.
const MAX_SNIPPET_CHARS: usize = 240;

const INSTRUCTIONS: &str =
    "Sigil scans code BEFORE it runs. Call `scan` on any skill, MCP server, \
plugin, repository or archive before installing or executing it, and `scan_package` before \
installing an npm or PyPI package. Treat `safe_to_install: false` as a block. Call `check_command` \
before running a shell command that downloads, installs or clones something; follow its decision.";

pub fn cmd_mcp() -> i32 {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        if let Some(response) = handle_line(&line, &run_self) {
            if writeln!(stdout, "{response}").is_err() || stdout.flush().is_err() {
                // The client went away: nothing left to serve.
                break;
            }
        }
    }
    0
}

/// Runs this binary with `args` and returns (exit code, stdout, stderr).
/// Injected so tests can exercise tool dispatch without spawning scans.
type Runner = dyn Fn(&[String]) -> Result<(i32, String, String), String>;

fn run_self(args: &[String]) -> Result<(i32, String, String), String> {
    let exe = std::env::current_exe().map_err(|e| format!("cannot locate sigil binary: {e}"))?;
    let out = Command::new(exe)
        .args(args)
        .output()
        .map_err(|e| format!("failed to run sigil: {e}"))?;
    Ok((
        out.status.code().unwrap_or(2),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    ))
}

/// Handle one line of input. Returns the response to write, or `None` for a
/// notification (which gets no response).
fn handle_line(line: &str, runner: &Runner) -> Option<Value> {
    let request: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => {
            return Some(error_response(
                Value::Null,
                -32700,
                &format!("parse error: {e}"),
            ))
        }
    };
    if !request.is_object() {
        return Some(error_response(
            Value::Null,
            -32600,
            "invalid request: expected a JSON-RPC object",
        ));
    }
    // A message without an id is a notification: act on it, never answer.
    let id = request.get("id").cloned()?;
    let method = request.get("method").and_then(Value::as_str).unwrap_or("");
    let params = request.get("params").cloned().unwrap_or(Value::Null);

    let result = match method {
        "initialize" => Ok(initialize(&params)),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({ "tools": tool_definitions() })),
        "tools/call" => Ok(call_tool(&params, runner)),
        _ => Err((-32601, format!("method not found: {method}"))),
    };
    Some(match result {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Err((code, message)) => error_response(id, code, &message),
    })
}

fn error_response(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

fn initialize(params: &Value) -> Value {
    let requested = params.get("protocolVersion").and_then(Value::as_str);
    let version = requested
        .filter(|v| PROTOCOL_VERSIONS.contains(v))
        .unwrap_or(PROTOCOL_VERSIONS[0]);
    json!({
        "protocolVersion": version,
        "capabilities": { "tools": { "listChanged": false } },
        "serverInfo": { "name": "sigil", "version": env!("CARGO_PKG_VERSION") },
        "instructions": INSTRUCTIONS,
    })
}

fn tool_definitions() -> Value {
    json!([
        {
            "name": "scan",
            "title": "Scan before install",
            "description": "Scan a local directory or file, or a git URL (cloned into quarantine first), \
    for malicious and risky patterns across install hooks, code execution, exfiltration, credentials, \
    obfuscation, prompt injection and skill/MCP security. Returns the verdict, score, grade, \
    safe_to_install and the most severe findings.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "Path or git URL to scan" },
                    "min_severity": {
                        "type": "string",
                        "enum": ["low", "medium", "high", "critical"],
                        "description": "Only report findings at or above this severity (default low)"
                    }
                },
                "required": ["target"]
            },
            "annotations": { "readOnlyHint": true, "openWorldHint": true }
        },
        {
            "name": "scan_package",
            "title": "Scan a package before install",
            "description": "Download an npm or PyPI package into quarantine (without running any of its \
    install scripts) and scan it. Returns the verdict and safe_to_install.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "ecosystem": { "type": "string", "enum": ["npm", "pypi"] },
                    "name": { "type": "string", "description": "Package name" },
                    "version": { "type": "string", "description": "Exact version (default: latest)" }
                },
                "required": ["ecosystem", "name"]
            },
            "annotations": { "readOnlyHint": false, "openWorldHint": true }
        },
        {
            "name": "check_command",
            "title": "Check a shell command before running it",
            "description": "Classify a shell command under Sigil's quarantine-first acquisition policy \
    (the same policy the Claude Code PreToolUse hook enforces). Returns allow, ask or deny with the \
    reason and the Sigil command to use instead.",
            "inputSchema": {
                "type": "object",
                "properties": { "command": { "type": "string" } },
                "required": ["command"]
            },
            "annotations": { "readOnlyHint": true, "openWorldHint": false }
        }
    ])
}

fn call_tool(params: &Value, runner: &Runner) -> Value {
    let name = params.get("name").and_then(Value::as_str).unwrap_or("");
    let args = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let outcome = match name {
        "scan" => tool_scan(&args, runner),
        "scan_package" => tool_scan_package(&args, runner),
        "check_command" => tool_check_command(&args),
        _ => Err(format!("unknown tool: {name}")),
    };
    match outcome {
        Ok(structured) => json!({
            "content": [{ "type": "text", "text": structured.to_string() }],
            "structuredContent": structured,
            "isError": false,
        }),
        Err(message) => json!({
            "content": [{ "type": "text", "text": message }],
            "isError": true,
        }),
    }
}

fn string_arg<'a>(args: &'a Value, key: &str) -> Result<&'a str, String> {
    args.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("missing required argument: {key}"))
}

fn tool_scan(args: &Value, runner: &Runner) -> Result<Value, String> {
    let target = string_arg(args, "target")?;
    let mut argv = vec![
        "--format".to_string(),
        "json".to_string(),
        "scan".to_string(),
        target.to_string(),
    ];
    if let Some(sev) = args.get("min_severity").and_then(Value::as_str) {
        if !["low", "medium", "high", "critical"].contains(&sev) {
            return Err(format!("invalid min_severity: {sev}"));
        }
        argv.push("--severity".into());
        argv.push(sev.into());
    }
    let (code, stdout, stderr) = runner(&argv)?;
    summarise_report(target, code, &stdout, &stderr)
}

fn tool_scan_package(args: &Value, runner: &Runner) -> Result<Value, String> {
    let ecosystem = string_arg(args, "ecosystem")?;
    let name = string_arg(args, "name")?;
    let subcommand = match ecosystem {
        "npm" => "npm",
        "pypi" | "pip" => "pip",
        other => return Err(format!("unsupported ecosystem: {other} (use npm or pypi)")),
    };
    // A leading '-' would be read as a flag by the child's argument parser.
    if name.starts_with('-') {
        return Err(format!("invalid package name: {name}"));
    }
    let mut argv = vec![
        "--format".to_string(),
        "json".to_string(),
        subcommand.to_string(),
        name.to_string(),
    ];
    if let Some(version) = args
        .get("version")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
    {
        if version.starts_with('-') {
            return Err(format!("invalid version: {version}"));
        }
        argv.push("--version".into());
        argv.push(version.into());
    }
    let (code, stdout, stderr) = runner(&argv)?;
    summarise_report(&format!("{ecosystem}:{name}"), code, &stdout, &stderr)
}

fn tool_check_command(args: &Value) -> Result<Value, String> {
    let command = string_arg(args, "command")?;
    let (decision, reason) = match hook::classify(command) {
        hook::Decision::Allow(r) => ("allow", r),
        hook::Decision::Ask(r) => ("ask", r),
        hook::Decision::Deny(r) => ("deny", r),
    };
    Ok(json!({ "command": command, "decision": decision, "reason": reason }))
}

/// Reduce a CLI JSON report to what an agent needs to decide.
///
/// The report is the last JSON object on stdout: commands that clone or
/// download print progress before it in text mode, and in JSON mode the
/// document is the whole of stdout, so taking the first `{` that parses to
/// the end covers both.
fn summarise_report(target: &str, code: i32, stdout: &str, stderr: &str) -> Result<Value, String> {
    let report = stdout
        .char_indices()
        .filter(|&(_, c)| c == '{')
        .find_map(|(i, _)| serde_json::from_str::<Value>(&stdout[i..]).ok())
        .ok_or_else(|| {
            let detail = stderr.trim();
            let detail = if detail.is_empty() {
                stdout.trim()
            } else {
                detail
            };
            format!(
                "sigil exited {code} without a JSON report for {target}: {}",
                truncate(detail, 600)
            )
        })?;

    let summary = report.get("summary").cloned().unwrap_or_else(|| json!({}));
    let verdict = summary
        .get("verdict")
        .and_then(Value::as_str)
        .unwrap_or("UNKNOWN")
        .to_string();
    let safe_to_install = matches!(verdict.as_str(), "LOW RISK");
    let decision = match verdict.as_str() {
        "LOW RISK" => "allow",
        "MEDIUM RISK" => "review",
        _ => "block",
    };

    let mut findings: Vec<Value> = report
        .get("findings")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    findings.sort_by_key(|f| std::cmp::Reverse(severity_rank(f)));
    let total = findings.len();
    let top: Vec<Value> = findings
        .iter()
        .take(MAX_FINDINGS_INLINE)
        .map(|f| {
            json!({
                "rule": f.get("rule"),
                "severity": f.get("severity"),
                "title": f.get("title"),
                "file": f.get("file"),
                "line": f.get("line"),
                "snippet": f.get("snippet").and_then(Value::as_str).map(|s| truncate(s, MAX_SNIPPET_CHARS)),
                "remediation": f.get("remediation"),
            })
        })
        .collect();

    Ok(json!({
        "target": target,
        "verdict": verdict,
        "decision": decision,
        "safe_to_install": safe_to_install,
        "score": summary.get("score"),
        "grade": summary.get("grade"),
        "platform": summary.get("platform"),
        "recommendation": summary.get("recommendation"),
        "behaviors": report.pointer("/profile/behaviors"),
        "findings_count": total,
        "findings_truncated": total > MAX_FINDINGS_INLINE,
        "findings": top,
        "quarantine_id": report.get("quarantine_id"),
    }))
}

fn severity_rank(finding: &Value) -> u8 {
    match finding.get("severity").and_then(Value::as_str) {
        Some("Critical") => 4,
        Some("High") => 3,
        Some("Medium") => 2,
        Some("Low") => 1,
        _ => 0,
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let cut: String = s.chars().take(max).collect();
    format!("{cut}…")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_runner(_: &[String]) -> Result<(i32, String, String), String> {
        panic!("runner must not be called")
    }

    fn call(line: &str) -> Option<Value> {
        handle_line(line, &no_runner)
    }

    #[test]
    fn initialize_negotiates_a_supported_version() {
        let r = call(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}"#).unwrap();
        assert_eq!(r["result"]["protocolVersion"], "2025-03-26");
        assert_eq!(r["result"]["serverInfo"]["name"], "sigil");
        assert!(r["result"]["capabilities"]["tools"].is_object());

        let r = call(r#"{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}"#).unwrap();
        assert_eq!(r["result"]["protocolVersion"], PROTOCOL_VERSIONS[0]);
    }

    #[test]
    fn notifications_get_no_response() {
        assert!(call(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#).is_none());
    }

    #[test]
    fn malformed_and_unknown_requests_are_errors() {
        assert_eq!(call("{not json").unwrap()["error"]["code"], -32700);
        assert_eq!(call("[1,2]").unwrap()["error"]["code"], -32600);
        let r = call(r#"{"jsonrpc":"2.0","id":"a","method":"resources/list"}"#).unwrap();
        assert_eq!(r["error"]["code"], -32601);
        assert_eq!(r["id"], "a");
    }

    #[test]
    fn tools_list_names_every_tool_with_a_schema() {
        let r = call(r#"{"jsonrpc":"2.0","id":3,"method":"tools/list"}"#).unwrap();
        let tools = r["result"]["tools"].as_array().unwrap();
        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["scan", "scan_package", "check_command"]);
        for t in tools {
            assert_eq!(t["inputSchema"]["type"], "object");
        }
    }

    #[test]
    fn check_command_uses_the_hook_policy() {
        let r = call(r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"check_command","arguments":{"command":"npm install left-pad"}}}"#).unwrap();
        assert_eq!(r["result"]["isError"], false);
        assert_eq!(r["result"]["structuredContent"]["decision"], "deny");

        let r = call(r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"check_command","arguments":{"command":"ls -la"}}}"#).unwrap();
        assert_eq!(r["result"]["structuredContent"]["decision"], "allow");
    }

    #[test]
    fn tool_errors_are_reported_in_band() {
        let r = call(r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"scan","arguments":{}}}"#).unwrap();
        assert_eq!(r["result"]["isError"], true);
        let r = call(r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"nope","arguments":{}}}"#).unwrap();
        assert_eq!(r["result"]["isError"], true);
        let r = call(r#"{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"scan_package","arguments":{"ecosystem":"npm","name":"--help"}}}"#).unwrap();
        assert_eq!(r["result"]["isError"], true);
    }

    #[test]
    fn scan_summarises_the_cli_report() {
        let report = json!({
            "findings": [
                {"rule": "NET-001", "severity": "Medium", "file": "a.py", "line": 3, "snippet": "x"},
                {"rule": "CRED-033", "severity": "High", "file": "a.py", "line": 1, "snippet": "y"}
            ],
            "profile": {"behaviors": ["exfiltration"]},
            "summary": {"verdict": "HIGH RISK", "score": 30, "grade": "D", "platform": "agent-skill"}
        });
        let runner = move |argv: &[String]| -> Result<(i32, String, String), String> {
            assert_eq!(
                argv,
                ["--format", "json", "scan", "./skill", "--severity", "high"]
            );
            Ok((1, report.to_string(), String::new()))
        };
        let r = handle_line(
            r#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"scan","arguments":{"target":"./skill","min_severity":"high"}}}"#,
            &runner,
        )
        .unwrap();
        let s = &r["result"]["structuredContent"];
        assert_eq!(s["verdict"], "HIGH RISK");
        assert_eq!(s["decision"], "block");
        assert_eq!(s["safe_to_install"], false);
        assert_eq!(s["findings_count"], 2);
        // Most severe first.
        assert_eq!(s["findings"][0]["rule"], "CRED-033");
        assert_eq!(s["behaviors"][0], "exfiltration");
    }

    #[test]
    fn scan_without_a_report_is_an_error_with_the_reason() {
        let runner = |_: &[String]| -> Result<(i32, String, String), String> {
            Ok((2, String::new(), "path does not exist".into()))
        };
        let r = handle_line(
            r#"{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"scan","arguments":{"target":"/nope"}}}"#,
            &runner,
        )
        .unwrap();
        assert_eq!(r["result"]["isError"], true);
        assert!(r["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("path does not exist"));
    }

    #[test]
    fn report_after_progress_text_is_still_found() {
        let stdout =
            "cloning into quarantine...\n{\"summary\":{\"verdict\":\"LOW RISK\"},\"findings\":[]}";
        let s = summarise_report("x", 0, stdout, "").unwrap();
        assert_eq!(s["safe_to_install"], true);
        assert_eq!(s["decision"], "allow");
    }
}
