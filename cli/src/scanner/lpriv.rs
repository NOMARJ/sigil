//! Least privilege: what a skill declares against what its code does
//! (`LPRIV-001` .. `LPRIV-003`).
//!
//! A `SKILL.md` can declare the tools it needs (`allowed-tools`) and a skill
//! or MCP manifest can declare `permissions`. A reviewer who reads "this skill
//! only reads files" and approves it has been told something by the author.
//! This pass checks that statement against the capabilities the skill's own
//! scripts were *observed* using — from the findings the content phases
//! already produced — so it adds no new pattern matching and no new noise
//! source of its own.
//!
//! | Rule | Severity | Shape |
//! |---|---|---|
//! | `LPRIV-001` | Medium | Scripts use a capability (shell, network, credentials/env, file writes) the declaration does not cover |
//! | `LPRIV-002` | Low | A wildcard grant (`*`, `all`, `full`, `any`) that `SKILL-008` did not already report |
//! | `LPRIV-003` | Low | An explicit `permissions` entry no script uses |
//!
//! Every finding here has weight 1: the most this pass can add for one
//! declaration is 2 + 1 points (LPRIV-002 and LPRIV-003 are exclusive), below
//! the MEDIUM verdict threshold of 10 and below the density threshold of any
//! skill that has a script at all (7 points for two files). These findings
//! inform a reviewer; they never decide a verdict on their own.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use super::bytecode::finding;
use super::{Evidence, Finding, Phase, Severity};

pub const RULE_UNDERDECLARED: &str = "LPRIV-001";
pub const RULE_WILDCARD: &str = "LPRIV-002";
pub const RULE_OVERDECLARED: &str = "LPRIV-003";

/// Capability categories, in report order.
const SHELL: &str = "shell";
const NETWORK: &str = "network";
const ENV: &str = "credentials/env";
const WRITE: &str = "file writes";
const READ: &str = "file reads";
const ALL: &[&str] = &[SHELL, NETWORK, ENV, WRITE, READ];
/// Capabilities whose use the content phases reliably report.
const OBSERVED: &[&str] = &[SHELL, NETWORK, ENV];

/// JSON manifests that may carry a `permissions` declaration.
const JSON_MANIFESTS: &[&str] = &[
    "manifest.json",
    "plugin.json",
    "skill.json",
    "tool.json",
    "server.json",
];

/// Extensions of files that run, as opposed to files that describe.
fn is_script(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let ext = lower.rsplit_once('.').map(|(_, e)| e).unwrap_or("");
    matches!(
        ext,
        "py" | "js"
            | "mjs"
            | "cjs"
            | "ts"
            | "tsx"
            | "jsx"
            | "sh"
            | "bash"
            | "zsh"
            | "ps1"
            | "bat"
            | "cmd"
            | "rb"
            | "pl"
            | "php"
            | "go"
            | "rs"
            | "lua"
    )
}

/// Test and example code is not what the skill runs.
fn is_auxiliary(path: &str) -> bool {
    path.to_ascii_lowercase().split('/').any(|seg| {
        matches!(
            seg,
            "test" | "tests" | "__tests__" | "spec" | "examples" | "example" | "fixtures" | "docs"
        )
    }) || path
        .rsplit('/')
        .next()
        .is_some_and(|n| n.starts_with("test_") || n.contains("_test."))
}

/// The capability a finding evidences, if any.
fn capability(rule: &str) -> Option<&'static str> {
    let behavior = super::profile::behavior_for(rule)?;
    Some(match behavior {
        "executes_shell" | "reverse_shell" => SHELL,
        "network_outbound"
        | "downloads_remote_content"
        | "exfiltration_endpoint"
        | "raw_sockets"
        | "dns_lookup"
        | "encodes_before_send"
        | "c2_tunnel_host"
        | "dns_exfiltration"
        | "exfiltrates_data"
        | "targets_metadata_endpoint"
        | "targets_internal_network" => NETWORK,
        "reads_credentials" | "harvests_credentials" => ENV,
        "installs_persistence" => WRITE,
        _ => return None,
    })
}

/// A parsed declaration.
#[derive(Debug, Default)]
struct Declaration {
    /// Where it is, relative to the scan root.
    file: String,
    /// The directory it governs (`""` for the root).
    dir: String,
    line: Option<usize>,
    /// Raw declared entries, for the report.
    entries: Vec<String>,
    /// Categories the declaration covers.
    covers: BTreeSet<&'static str>,
    /// Categories named explicitly in a `permissions` list (for LPRIV-003).
    explicit: BTreeSet<&'static str>,
    wildcard: bool,
}

/// What one `allowed-tools` entry grants.
fn tool_grants(entry: &str) -> (Vec<&'static str>, bool) {
    let e = entry.trim().trim_matches(|c| c == '"' || c == '\'');
    let (name, args) = match e.split_once('(') {
        Some((n, rest)) => (n.trim(), Some(rest.trim_end_matches(')').trim())),
        None => (e, None),
    };
    let lname = name.to_ascii_lowercase();
    if lname == "*" {
        return (ALL.to_vec(), true);
    }
    let grants = match lname.as_str() {
        "bash" | "shell" | "terminal" | "execute" | "powershell" => match args {
            None | Some("") | Some("*") | Some("*:*") => ALL.to_vec(),
            Some(a) => {
                let cmd = a
                    .split([':', ' '])
                    .next()
                    .unwrap_or("")
                    .to_ascii_lowercase();
                let cmd = cmd.rsplit('/').next().unwrap_or(&cmd).to_string();
                // A command allowance that runs an interpreter runs the
                // skill's scripts, and so grants whatever they do.
                if matches!(
                    cmd.as_str(),
                    "python"
                        | "python3"
                        | "node"
                        | "uv"
                        | "uvx"
                        | "bun"
                        | "deno"
                        | "bash"
                        | "sh"
                        | "zsh"
                        | "npx"
                        | "npm"
                        | "pnpm"
                        | "ruby"
                        | "perl"
                        | "pwsh"
                ) || cmd.ends_with(".py")
                    || cmd.ends_with(".sh")
                    || cmd.ends_with(".js")
                {
                    ALL.to_vec()
                } else if matches!(cmd.as_str(), "curl" | "wget" | "gh" | "git" | "http") {
                    vec![SHELL, NETWORK]
                } else {
                    vec![SHELL]
                }
            }
        },
        "read" | "glob" | "grep" | "ls" | "notebookread" => vec![READ],
        "write" | "edit" | "multiedit" | "notebookedit" => vec![WRITE, READ],
        "webfetch" | "websearch" | "fetch" => vec![NETWORK],
        "env" | "environment" => vec![ENV],
        _ => vec![],
    };
    (grants, false)
}

/// What one `permissions` entry grants, by keyword.
fn permission_grants(entry: &str) -> (Vec<&'static str>, bool) {
    let e = entry
        .trim()
        .trim_matches(|c| c == '"' || c == '\'')
        .to_ascii_lowercase();
    if matches!(e.as_str(), "*" | "all" | "full" | "any") {
        return (ALL.to_vec(), true);
    }
    let words: Vec<&str> = e
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty())
        .collect();
    let has = |ks: &[&str]| words.iter().any(|w| ks.contains(w));
    let mut out = Vec::new();
    if has(&[
        "shell",
        "bash",
        "terminal",
        "command",
        "commands",
        "exec",
        "execute",
        "process",
        "subprocess",
    ]) {
        out.push(SHELL);
    }
    if has(&[
        "network", "net", "http", "https", "fetch", "internet", "web", "api", "socket",
    ]) {
        out.push(NETWORK);
    }
    if has(&[
        "env",
        "environment",
        "secrets",
        "secret",
        "credentials",
        "credential",
        "keychain",
    ]) {
        out.push(ENV);
    }
    if has(&["write", "fs_write", "file_write"]) || e.contains("write") {
        out.push(WRITE);
    }
    if has(&["read", "fs_read", "file_read", "filesystem"]) || e.contains("read") {
        out.push(READ);
    }
    (out, false)
}

/// Flatten a YAML value into declaration entries.
fn yaml_entries(v: &serde_yaml::Value) -> Vec<String> {
    match v {
        serde_yaml::Value::String(s) => {
            // `Read, Grep, Bash(git:*)` or `Read Grep Bash` — parentheses may
            // contain spaces, so split outside them only.
            let mut out = Vec::new();
            let mut cur = String::new();
            let mut depth = 0i32;
            for c in s.chars() {
                match c {
                    '(' => {
                        depth += 1;
                        cur.push(c);
                    }
                    ')' => {
                        depth -= 1;
                        cur.push(c);
                    }
                    ',' | ' ' | '\t' if depth <= 0 => {
                        if !cur.trim().is_empty() {
                            out.push(cur.trim().to_string());
                        }
                        cur.clear();
                    }
                    _ => cur.push(c),
                }
            }
            if !cur.trim().is_empty() {
                out.push(cur.trim().to_string());
            }
            out
        }
        serde_yaml::Value::Sequence(items) => items.iter().flat_map(yaml_entries).collect(),
        serde_yaml::Value::Mapping(m) => m
            .iter()
            .filter(|(_, v)| !matches!(v, serde_yaml::Value::Bool(false)))
            .filter_map(|(k, v)| {
                let k = k.as_str()?;
                Some(match v.as_str() {
                    Some(s) => format!("{k}:{s}"),
                    None => k.to_string(),
                })
            })
            .collect(),
        serde_yaml::Value::Bool(_) | serde_yaml::Value::Number(_) | serde_yaml::Value::Null => {
            Vec::new()
        }
        serde_yaml::Value::Tagged(t) => yaml_entries(&t.value),
    }
}

fn line_of_key(text: &str, keys: &[&str]) -> Option<usize> {
    text.lines()
        .position(|l| {
            let t = l.trim_start().trim_start_matches('"');
            keys.iter().any(|k| t.starts_with(k))
        })
        .map(|i| i + 1)
}

/// Parse the frontmatter of a `SKILL.md`, or the top level of a JSON manifest.
fn parse_declaration(rel: &str, text: &str) -> Option<Declaration> {
    let name = rel.rsplit('/').next().unwrap_or(rel).to_ascii_lowercase();
    let doc: serde_yaml::Value = if name == "skill.md" {
        let body = text.strip_prefix("\u{feff}").unwrap_or(text);
        let rest = body.strip_prefix("---")?;
        let end = rest.find("\n---")?;
        serde_yaml::from_str(&rest[..end]).ok()?
    } else {
        let json: serde_json::Value = serde_json::from_str(text).ok()?;
        serde_yaml::to_value(json).ok()?
    };
    let map = doc.as_mapping()?;
    let get = |k: &str| map.get(serde_yaml::Value::String(k.to_string()));
    let tools = get("allowed-tools")
        .or_else(|| get("allowed_tools"))
        .or_else(|| get("allowedTools"));
    let perms = get("permissions");
    if tools.is_none() && perms.is_none() {
        return None;
    }
    let mut d = Declaration {
        file: rel.to_string(),
        dir: rel
            .rsplit_once('/')
            .map(|(d, _)| d.to_string())
            .unwrap_or_default(),
        line: line_of_key(
            text,
            &[
                "allowed-tools",
                "allowed_tools",
                "allowedTools",
                "permissions",
            ],
        ),
        ..Default::default()
    };
    if let Some(t) = tools {
        for e in yaml_entries(t) {
            let (g, wild) = tool_grants(&e);
            d.covers.extend(g);
            d.wildcard |= wild;
            d.entries.push(e);
        }
    }
    if let Some(p) = perms {
        for e in yaml_entries(p) {
            let (g, wild) = permission_grants(&e);
            d.covers.extend(g.iter().copied());
            d.explicit.extend(g);
            d.wildcard |= wild;
            d.entries.push(e);
        }
    }
    if d.entries.is_empty() {
        return None;
    }
    Some(d)
}

/// Compare every declaration in the tree with what its scripts do.
pub fn check(strip_base: &Path, files: &[PathBuf], findings: &[Finding]) -> Vec<Finding> {
    let mut decls: Vec<Declaration> = Vec::new();
    for f in files {
        let rel = f
            .strip_prefix(strip_base)
            .unwrap_or(f)
            .to_string_lossy()
            .replace('\\', "/");
        let name = rel.rsplit('/').next().unwrap_or(&rel).to_ascii_lowercase();
        if name != "skill.md" && !JSON_MANIFESTS.contains(&name.as_str()) {
            continue;
        }
        let Ok(meta) = std::fs::metadata(f) else {
            continue;
        };
        if meta.len() > 1024 * 1024 {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(f) else {
            continue;
        };
        if let Some(d) = parse_declaration(&rel, &text) {
            decls.push(d);
        }
    }
    if decls.is_empty() {
        return Vec::new();
    }
    // Deepest declaration first, so a nested skill owns its own scripts.
    decls.sort_by_key(|d| {
        std::cmp::Reverse(d.dir.matches('/').count() + (!d.dir.is_empty()) as usize)
    });

    let owner = |file: &str| -> Option<usize> {
        decls
            .iter()
            .position(|d| d.dir.is_empty() || file.starts_with(&format!("{}/", d.dir)))
    };
    let script_files: Vec<String> = files
        .iter()
        .map(|f| {
            f.strip_prefix(strip_base)
                .unwrap_or(f)
                .to_string_lossy()
                .replace('\\', "/")
        })
        .filter(|r| is_script(r) && !is_auxiliary(r))
        .collect();

    // capability -> first evidence, per declaration.
    let mut used: Vec<BTreeMap<&'static str, String>> = vec![BTreeMap::new(); decls.len()];
    for f in findings {
        let file = f.file.split("!/").next().unwrap_or(&f.file);
        if !is_script(&f.file) || is_auxiliary(&f.file) {
            continue;
        }
        let Some(cap) = capability(&f.rule) else {
            continue;
        };
        let Some(i) = owner(file) else { continue };
        used[i].entry(cap).or_insert_with(|| match f.line {
            Some(l) => format!("{} {}:{}", f.rule, f.file, l),
            None => format!("{} {}", f.rule, f.file),
        });
    }
    let has_scripts: Vec<bool> = decls
        .iter()
        .enumerate()
        .map(|(i, _)| script_files.iter().any(|s| owner(s) == Some(i)))
        .collect();

    let mut out = Vec::new();
    for (i, d) in decls.iter().enumerate() {
        let mk = |rule: &str, severity: Severity, snippet: String| {
            let mut f = finding(
                Phase::SkillSecurity,
                rule,
                severity,
                &d.file,
                snippet,
                1,
                Evidence::Standalone,
            );
            f.line = d.line;
            f
        };
        let declared = d.entries.join(", ");
        let missing: Vec<String> = used[i]
            .iter()
            .filter(|(cap, _)| !d.covers.contains(*cap))
            .map(|(cap, ev)| format!("{cap} ({ev})"))
            .collect();
        if !missing.is_empty() {
            out.push(mk(
                RULE_UNDERDECLARED,
                Severity::Medium,
                format!(
                    "Declares [{declared}] but its scripts use capabilities the declaration \
                     does not cover: {}",
                    missing.join("; ")
                ),
            ));
        }
        let skill008 = findings
            .iter()
            .any(|f| f.rule == "SKILL-008" && f.file == d.file);
        if d.wildcard && !skill008 {
            out.push(mk(
                RULE_WILDCARD,
                Severity::Low,
                format!("Wildcard grant in [{declared}] — no least-privilege boundary"),
            ));
        }
        if !d.wildcard && has_scripts[i] {
            // Absence of evidence only means something for capabilities the
            // phases reliably observe. Ordinary file reads and writes
            // (`open(p, "w")`, `write_text`) are not findings, so a declared
            // write permission is never called idle.
            let idle: Vec<&str> = d
                .explicit
                .iter()
                .filter(|c| OBSERVED.contains(*c) && !used[i].contains_key(*c))
                .copied()
                .collect();
            if !idle.is_empty() {
                out.push(mk(
                    RULE_OVERDECLARED,
                    Severity::Low,
                    format!(
                        "Declares permission(s) no script was seen using: {} — remove them, \
                         or they are pre-staged for code that is not here yet",
                        idle.join(", ")
                    ),
                ));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(entries: &[(&str, &str)]) -> (tempfile::TempDir, Vec<PathBuf>) {
        let d = tempfile::tempdir().unwrap();
        let mut files = Vec::new();
        for (rel, body) in entries {
            let p = d.path().join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, body).unwrap();
            files.push(p);
        }
        files.sort();
        (d, files)
    }

    fn f(rule: &str, file: &str) -> Finding {
        let mut x = finding(
            Phase::NetworkExfil,
            rule,
            Severity::Medium,
            file,
            "x".into(),
            1,
            Evidence::Standalone,
        );
        x.line = Some(3);
        x
    }

    fn rules(out: &[Finding]) -> Vec<(&str, Severity)> {
        out.iter().map(|f| (f.rule.as_str(), f.severity)).collect()
    }

    #[test]
    fn read_only_skill_whose_script_posts_env_is_underdeclared() {
        let (d, files) = tree(&[
            (
                "s/SKILL.md",
                "---\nname: greeter\nallowed-tools: Read, Grep\n---\n# Greeter\n",
            ),
            ("s/scripts/greet.py", "import os, httpx\n"),
        ]);
        let found = vec![
            f("NET-001", "s/scripts/greet.py"),
            f("CRED-001", "s/scripts/greet.py"),
        ];
        let out = check(d.path(), &files, &found);
        assert_eq!(rules(&out), vec![(RULE_UNDERDECLARED, Severity::Medium)]);
        assert!(out[0].snippet.contains("network"), "{}", out[0].snippet);
        assert!(
            out[0].snippet.contains("credentials/env"),
            "{}",
            out[0].snippet
        );
        assert_eq!(out[0].line, Some(3));
        assert_eq!(out[0].weight, 1);
    }

    #[test]
    fn unrestricted_bash_covers_what_scripts_do() {
        let (d, files) = tree(&[
            (
                "s/SKILL.md",
                "---\nname: x\nallowed-tools:\n  - Read\n  - Bash\n---\n",
            ),
            ("s/run.py", "import subprocess\n"),
        ]);
        let found = vec![f("NET-001", "s/run.py"), f("CODE-013", "s/run.py")];
        assert!(check(d.path(), &files, &found).is_empty());
        // A command allowance that runs the interpreter runs the scripts too.
        let (d, files) = tree(&[
            (
                "s/SKILL.md",
                "---\nallowed-tools: Read Bash(python3 scripts/run.py:*)\n---\n",
            ),
            ("s/scripts/run.py", ""),
        ]);
        let found = vec![f("NET-001", "s/scripts/run.py")];
        assert!(check(d.path(), &files, &found).is_empty());
        // `Bash(git:*)` does not cover a script opening sockets to post data.
        let (d, files) = tree(&[
            (
                "s/SKILL.md",
                "---\nallowed-tools: Bash(git status:*)\n---\n",
            ),
            ("s/x.js", ""),
        ]);
        let found = vec![f("CRED-031", "s/x.js")];
        assert_eq!(
            rules(&check(d.path(), &files, &found)),
            vec![(RULE_UNDERDECLARED, Severity::Medium)]
        );
    }

    #[test]
    fn wildcard_and_overdeclared_permissions() {
        let (d, files) = tree(&[
            (
                "s/SKILL.md",
                "---\nname: helper\npermissions:\n  - bash\n  - network\n  - \"*\"\n---\n",
            ),
            ("s/helper.py", "open(p).read()\n"),
        ]);
        let out = check(d.path(), &files, &[]);
        assert_eq!(rules(&out), vec![(RULE_WILDCARD, Severity::Low)]);
        // Already reported by SKILL-008: not repeated.
        let skill008 = f("SKILL-008", "s/SKILL.md");
        assert!(check(d.path(), &files, &[skill008]).is_empty());

        let (d, files) = tree(&[
            (
                "s/SKILL.md",
                "---\npermissions: [env, file_read, network, shell]\n---\n",
            ),
            ("s/run.py", ""),
        ]);
        let out = check(d.path(), &files, &[f("NET-001", "s/run.py")]);
        assert_eq!(rules(&out), vec![(RULE_OVERDECLARED, Severity::Low)]);
        assert!(out[0].snippet.contains("shell"));
        assert!(out[0].snippet.contains("credentials/env"));
    }

    #[test]
    fn unobservable_writes_are_never_called_idle() {
        // SkillSpector's mcp_clean_skill shape: bash/read/write declared, the
        // script runs a formatter and writes the file back.
        let (d, files) = tree(&[
            (
                "s/SKILL.md",
                "---\npermissions:\n  - bash\n  - read\n  - write\n---\n",
            ),
            ("s/scripts/format.py", ""),
        ]);
        assert!(check(d.path(), &files, &[f("CODE-013", "s/scripts/format.py")]).is_empty());
    }

    #[test]
    fn no_declaration_no_scripts_no_findings() {
        // Undeclared: nothing to compare against, so nothing is claimed.
        let (d, files) = tree(&[("s/SKILL.md", "---\nname: x\n---\n"), ("s/a.py", "")]);
        assert!(check(d.path(), &files, &[f("NET-001", "s/a.py")]).is_empty());
        // Findings in docs and tests are not the skill's behaviour.
        let (d, files) = tree(&[
            ("s/SKILL.md", "---\nallowed-tools: Read\n---\n"),
            ("s/tests/test_a.py", ""),
            ("s/README.md", ""),
        ]);
        let found = vec![
            f("NET-001", "s/tests/test_a.py"),
            f("NET-001", "s/README.md"),
        ];
        assert!(check(d.path(), &files, &found).is_empty());
    }

    #[test]
    fn json_manifest_permissions_are_read() {
        let (d, files) = tree(&[
            (
                "m/manifest.json",
                "{\"name\":\"m\",\"permissions\":[\"read\"]}",
            ),
            ("m/server.js", ""),
        ]);
        let out = check(d.path(), &files, &[f("CODE-013", "m/server.js")]);
        assert_eq!(rules(&out), vec![(RULE_UNDERDECLARED, Severity::Medium)]);
    }
}
