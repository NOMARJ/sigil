//! What the manifests in a tree say about it.
//!
//! Three questions, each answered from package metadata rather than from
//! code, and each declarative enough to stay out of the rule packs:
//!
//! 1. Which platform the artifact targets (`summary.platform`): an npm
//!    package, a PyPI distribution, an agent skill, an MCP server, a Claude
//!    Code plugin, an editor extension, a set of agent instruction files.
//!    One scalar, chosen from the shallowest manifest in the tree.
//! 2. Which local files its install scripts run. A finding in a file that a
//!    `postinstall` or `prepare` script executes is worse than the same
//!    finding in a module nobody imports, because it runs on `npm install`
//!    whether or not the package is ever used. That link is reported as its
//!    own finding (`INSTALL-REF-001`) one level above the worst finding in
//!    the file; the file's own findings are left untouched.
//! 3. Whether an agent-skill manifest even parses. A manifest that is not
//!    JSON is at best broken and at worst a way to make a reviewer's tooling
//!    skip the file.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use super::{Finding, Phase, Severity};

/// Manifests deeper than this are not consulted: extracted archives nest a
/// few directories (`tmp/x/pkg/package/package.json`), vendored trees are
/// already excluded, and anything deeper is not the artifact under review.
const MANIFEST_DEPTH: usize = 4;

/// npm lifecycle scripts that run without the user asking for them.
const LIFECYCLE_SCRIPTS: &[&str] = &[
    "preinstall",
    "install",
    "postinstall",
    "prepare",
    "prepublish",
    "prepublishOnly",
    "preuninstall",
    "postuninstall",
];

/// Extensions that mark a command token as a local script or binary.
const SCRIPT_EXTENSIONS: &[&str] = &[
    ".js", ".cjs", ".mjs", ".ts", ".sh", ".bash", ".zsh", ".py", ".rb", ".pl", ".ps1", ".bat",
    ".cmd", ".exe", ".bin", ".node",
];

/// Agent-skill and MCP manifests that must be JSON.
const SKILL_MANIFESTS: &[&str] = &[
    "manifest.json",
    "plugin.json",
    "mcp.json",
    ".mcp.json",
    "tool.json",
    "skill.json",
    "server.json",
    "claude_desktop_config.json",
];

fn rel(base: &Path, path: &Path) -> String {
    path.strip_prefix(base)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn depth(rel: &str) -> usize {
    rel.matches('/').count()
}

fn split_rel(rel: &str) -> (&str, &str) {
    match rel.rsplit_once('/') {
        Some((dir, name)) => (dir, name),
        None => ("", rel),
    }
}

// ---------------------------------------------------------------------------
// Platform
// ---------------------------------------------------------------------------

/// A Python dependency line naming the `mcp` or `fastmcp` distribution
/// itself (`mcp>=1.2`, `"fastmcp[cli]",`, `mcp`), not a package whose name
/// merely starts with those letters.
fn is_mcp_dependency_line(line: &str) -> bool {
    let line = line.trim().trim_start_matches(['"', '\'', '-', ' ']);
    for name in ["fastmcp", "mcp"] {
        if let Some(rest) = line.strip_prefix(name) {
            let next = rest.chars().next();
            if next.is_none_or(|c| {
                matches!(
                    c,
                    '[' | '=' | '<' | '>' | '~' | '!' | ';' | '"' | '\'' | ' ' | ','
                )
            }) {
                return true;
            }
        }
    }
    false
}

/// Classify the tree by its shallowest manifest. Ties at one depth resolve
/// toward the more specific platform (an MCP server before the npm package
/// that ships it), so the answer is one word a consumer can switch on.
pub fn detect_platform(base: &Path, files: &[PathBuf]) -> &'static str {
    // (depth of the project root the marker implies, priority, platform)
    let mut candidates: Vec<(usize, u8, &'static str)> = Vec::new();
    for path in files {
        let r = rel(base, path);
        let d = depth(&r);
        if d > MANIFEST_DEPTH {
            continue;
        }
        let (dir, name) = split_rel(&r);
        let read = || std::fs::read_to_string(path).unwrap_or_default();
        let found = match name {
            "package.json" => {
                let doc: serde_json::Value = serde_json::from_str(&read()).unwrap_or_default();
                let depends_on = |pkg: &str| {
                    ["dependencies", "devDependencies", "peerDependencies"]
                        .iter()
                        .any(|section| doc.get(section).and_then(|s| s.get(pkg)).is_some())
                };
                if doc.get("mcpName").is_some() || depends_on("@modelcontextprotocol/sdk") {
                    Some((d, 0, "mcp-server"))
                } else if doc.get("engines").and_then(|e| e.get("vscode")).is_some() {
                    Some((d, 3, "vscode-extension"))
                } else {
                    Some((d, 4, "npm"))
                }
            }
            "server.json" => {
                read()
                    .contains("modelcontextprotocol")
                    .then_some((d, 0, "mcp-server"))
            }
            "pyproject.toml" | "setup.py" | "setup.cfg" | "requirements.txt" | "PKG-INFO" => {
                let text = read();
                let mcp = text.lines().any(is_mcp_dependency_line);
                if mcp {
                    Some((d, 0, "mcp-server"))
                } else if name == "requirements.txt" {
                    None
                } else {
                    Some((d, 5, "pypi"))
                }
            }
            "plugin.json" if dir.ends_with(".claude-plugin") => {
                Some((d.saturating_sub(1), 1, "claude-plugin"))
            }
            "SKILL.md" | "skill.json" => Some((d, 2, "agent-skill")),
            "Cargo.toml" => Some((d, 6, "cargo")),
            "go.mod" => Some((d, 7, "go")),
            "pom.xml" | "build.gradle" | "build.gradle.kts" => Some((d, 8, "maven")),
            ".cursorrules" | ".windsurfrules" | ".clinerules" | "AGENTS.md" | "CLAUDE.md" => {
                Some((d, 9, "agent-instructions"))
            }
            _ if name.ends_with(".gemspec") => Some((d, 8, "rubygems")),
            _ if dir.ends_with(".cursor/rules") => {
                Some((d.saturating_sub(2), 9, "agent-instructions"))
            }
            _ => None,
        };
        if let Some(c) = found {
            candidates.push(c);
        }
    }
    candidates
        .into_iter()
        .min()
        .map(|(_, _, platform)| platform)
        .unwrap_or("generic")
}

// ---------------------------------------------------------------------------
// Install-time references
// ---------------------------------------------------------------------------

fn command_tokens(cmd: &str) -> impl Iterator<Item = &str> {
    cmd.split(|c: char| c.is_whitespace() || matches!(c, ';' | '|' | '&' | '(' | ')'))
        .map(|t| t.trim_matches(|c| matches!(c, '"' | '\'' | '`')))
        .filter(|t| !t.is_empty())
}

/// Resolve a command token to a file in the tree, if it names one.
fn resolve_local(dir: &str, token: &str, present: &HashSet<String>) -> Option<String> {
    if token.contains("://") || token.starts_with('-') || token.starts_with('$') {
        return None;
    }
    let looks_like_file = SCRIPT_EXTENSIONS
        .iter()
        .any(|ext| token.to_ascii_lowercase().ends_with(ext))
        || token.starts_with("./");
    if !looks_like_file {
        return None;
    }
    let cleaned = token.trim_start_matches("./");
    if cleaned.starts_with("../") || cleaned.starts_with('/') {
        return None;
    }
    let candidate = if dir.is_empty() {
        cleaned.to_string()
    } else {
        format!("{dir}/{cleaned}")
    };
    present.contains(&candidate).then_some(candidate)
}

/// Files in the tree that a manifest runs at install time, keyed by their
/// path relative to `base`, with how they are invoked.
pub fn install_referenced(base: &Path, files: &[PathBuf]) -> BTreeMap<String, String> {
    let present: HashSet<String> = files.iter().map(|p| rel(base, p)).collect();
    let mut out: BTreeMap<String, String> = BTreeMap::new();

    for path in files {
        let r = rel(base, path);
        if depth(&r) > MANIFEST_DEPTH {
            continue;
        }
        let (dir, name) = split_rel(&r);
        match name {
            "package.json" => {
                let Ok(text) = std::fs::read_to_string(path) else {
                    continue;
                };
                let Ok(doc) = serde_json::from_str::<serde_json::Value>(&text) else {
                    continue;
                };
                let Some(scripts) = doc.get("scripts").and_then(|s| s.as_object()) else {
                    continue;
                };
                for key in LIFECYCLE_SCRIPTS {
                    let Some(cmd) = scripts.get(*key).and_then(|c| c.as_str()) else {
                        continue;
                    };
                    for token in command_tokens(cmd) {
                        if let Some(target) = resolve_local(dir, token, &present) {
                            out.entry(target)
                                .or_insert_with(|| format!("package.json {key}"));
                        }
                    }
                }
            }
            "setup.py" => {
                let Ok(text) = std::fs::read_to_string(path) else {
                    continue;
                };
                // Quoted relative paths to scripts or binaries: what a
                // custom install command opens, executes or copies.
                for token in text.split(['"', '\'']).skip(1).step_by(2) {
                    if token.contains(char::is_whitespace) {
                        continue;
                    }
                    if let Some(target) = resolve_local(dir, token, &present) {
                        out.entry(target).or_insert_with(|| "setup.py".to_string());
                    }
                }
            }
            _ => {}
        }
    }
    out
}

fn one_above(severity: Severity) -> Severity {
    match severity {
        Severity::Low => Severity::Medium,
        Severity::Medium => Severity::High,
        Severity::High | Severity::Critical => Severity::Critical,
    }
}

/// Line of the lifecycle script's key in the manifest, for the finding.
fn script_line(manifest_text: &str, key: &str) -> Option<usize> {
    let needle = format!("\"{key}\"");
    manifest_text
        .lines()
        .position(|l| l.contains(&needle))
        .map(|i| i + 1)
}

/// `INSTALL-REF-001`: a lifecycle script runs a local file that has
/// findings of its own. One explicit finding per referenced file, on the
/// manifest, one level above the worst finding in that file: what runs on
/// `npm install` is worse than the same code in a module nobody imports.
/// The referenced file's own findings are left exactly as they are, so
/// their fingerprints and severities stay stable.
pub fn link_install_referenced(
    base: &Path,
    files: &[PathBuf],
    findings: &[Finding],
) -> Vec<Finding> {
    let referenced = install_referenced(base, files);
    if referenced.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (target, via) in &referenced {
        let inside: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.phase != Phase::InstallHooks && f.file.replace('\\', "/") == *target)
            .collect();
        let Some(worst) = inside.iter().map(|f| f.severity).max() else {
            continue;
        };
        if worst < Severity::Medium {
            continue;
        }
        let mut rules: Vec<&str> = inside.iter().map(|f| f.rule.as_str()).collect();
        rules.sort_unstable();
        rules.dedup();
        let (manifest, key) = via.split_once(' ').unwrap_or((via.as_str(), ""));
        let manifest_dir = target.rsplit_once('/').map(|(d, _)| d);
        // The manifest that named the file lives at its own depth; find it
        // by walking the referenced file's ancestors.
        let manifest_rel = files
            .iter()
            .map(|p| rel(base, p))
            .filter(|r| split_rel(r).1 == manifest)
            .find(|r| {
                let dir = split_rel(r).0;
                manifest_dir.is_some_and(|d| d.starts_with(dir)) || dir.is_empty()
            })
            .unwrap_or_else(|| manifest.to_string());
        let line = files
            .iter()
            .find(|p| rel(base, p) == manifest_rel)
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|text| {
                if key.is_empty() {
                    None
                } else {
                    script_line(&text, key)
                }
            });
        out.push(Finding {
            phase: Phase::InstallHooks,
            rule: "INSTALL-REF-001".to_string(),
            severity: one_above(worst),
            file: manifest_rel,
            line,
            snippet: format!(
                "Lifecycle script runs a file with findings: {via} -> {target} ({} finding(s), worst {worst}: {})",
                inside.len(),
                rules.join(", ")
            ),
            weight: 10,
            kev: false,
            epss: 0.0,
            fingerprint: String::new(),
            locator: None,
            evidence: Default::default(),
        });
    }
    out
}

// ---------------------------------------------------------------------------
// Malformed skill manifests
// ---------------------------------------------------------------------------

/// Strip `//` and `/* */` comments outside strings and trailing commas, so a
/// JSONC manifest (editor MCP configs allow them) is not reported as broken.
fn lenient_json(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut in_string = false;
    let mut escaped = false;
    while let Some(c) = chars.next() {
        if in_string {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        match c {
            '"' => {
                in_string = true;
                out.push(c);
            }
            '/' if chars.peek() == Some(&'/') => {
                for next in chars.by_ref() {
                    if next == '\n' {
                        out.push('\n');
                        break;
                    }
                }
            }
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                let mut prev = ' ';
                for next in chars.by_ref() {
                    if prev == '*' && next == '/' {
                        break;
                    }
                    prev = next;
                }
            }
            _ => out.push(c),
        }
    }
    // Trailing commas before a closing bracket.
    let mut cleaned = String::with_capacity(out.len());
    let bytes: Vec<char> = out.chars().collect();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == ',' {
            let mut j = i + 1;
            while j < bytes.len() && bytes[j].is_whitespace() {
                j += 1;
            }
            if j < bytes.len() && (bytes[j] == '}' || bytes[j] == ']') {
                i += 1;
                continue;
            }
        }
        cleaned.push(bytes[i]);
        i += 1;
    }
    cleaned
}

/// `SKILL-007`: an agent-skill or MCP manifest that is not valid JSON.
pub fn malformed_manifest(rel_path: &str, contents: &str) -> Option<Finding> {
    let (_, name) = split_rel(rel_path);
    if !SKILL_MANIFESTS.contains(&name) {
        return None;
    }
    let err = match serde_json::from_str::<serde_json::Value>(contents) {
        Ok(_) => return None,
        Err(e) => e,
    };
    if serde_json::from_str::<serde_json::Value>(&lenient_json(contents)).is_ok() {
        return None;
    }
    Some(Finding {
        phase: Phase::SkillSecurity,
        rule: "SKILL-007".to_string(),
        severity: Severity::Low,
        file: rel_path.to_string(),
        line: Some(err.line().max(1)),
        snippet: format!("Skill manifest is not valid JSON: {err}"),
        weight: 5,
        kev: false,
        epss: 0.0,
        fingerprint: String::new(),
        locator: None,
        evidence: Default::default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(entries: &[(&str, &str)]) -> (tempfile::TempDir, Vec<PathBuf>) {
        let dir = tempfile::tempdir().unwrap();
        let mut files = Vec::new();
        for (rel, body) in entries {
            let p = dir.path().join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, body).unwrap();
            files.push(p);
        }
        files.sort();
        (dir, files)
    }

    #[test]
    fn platform_prefers_the_shallowest_then_the_most_specific_manifest() {
        let (d, files) = tree(&[
            ("package.json", "{\"name\":\"x\"}"),
            (
                "plugins/mcp/package.json",
                "{\"dependencies\":{\"@modelcontextprotocol/sdk\":\"1\"}}",
            ),
        ]);
        assert_eq!(detect_platform(d.path(), &files), "npm");

        let (d, files) = tree(&[
            (
                "package.json",
                "{\"dependencies\":{\"@modelcontextprotocol/sdk\":\"1\"}}",
            ),
            ("SKILL.md", "---\nname: x\n---\n"),
        ]);
        assert_eq!(detect_platform(d.path(), &files), "mcp-server");

        let (d, files) = tree(&[
            ("tmp/a/pkg/package/package.json", "{}"),
            ("tmp/a/pkg/package/index.js", ""),
        ]);
        assert_eq!(detect_platform(d.path(), &files), "npm");

        let (d, files) = tree(&[("skill/SKILL.md", "# hi"), ("skill/run.py", "")]);
        assert_eq!(detect_platform(d.path(), &files), "agent-skill");

        let (d, files) = tree(&[("my-plugin/.claude-plugin/plugin.json", "{}")]);
        assert_eq!(detect_platform(d.path(), &files), "claude-plugin");

        let (d, files) = tree(&[("setup.py", "from setuptools import setup")]);
        assert_eq!(detect_platform(d.path(), &files), "pypi");

        let (d, files) = tree(&[(".cursorrules", "be nice"), ("src/a.ts", "")]);
        assert_eq!(detect_platform(d.path(), &files), "agent-instructions");

        let (d, files) = tree(&[("README", "x")]);
        assert_eq!(detect_platform(d.path(), &files), "generic");
    }

    #[test]
    fn mcp_dependency_lines_are_recognised_precisely() {
        assert!(is_mcp_dependency_line("mcp>=1.2"));
        assert!(is_mcp_dependency_line("  \"fastmcp[cli]>=2\","));
        assert!(is_mcp_dependency_line("mcp"));
        assert!(is_mcp_dependency_line("- mcp==1.0"));
        assert!(!is_mcp_dependency_line("mcp-crawler>=1"));
        assert!(!is_mcp_dependency_line("mcp_utils"));
        assert!(!is_mcp_dependency_line("name = \"sigil-api\""));
        assert!(!is_mcp_dependency_line("# talks to mcp servers"));
    }

    #[test]
    fn lifecycle_scripts_resolve_to_local_files_only() {
        let (d, files) = tree(&[
            (
                "package.json",
                r#"{"scripts":{"postinstall":"node ./scripts/setup.js && echo ok","prepare":"npm run build","test":"node test.js"}}"#,
            ),
            ("scripts/setup.js", "x"),
            ("test.js", "x"),
        ]);
        let refs = install_referenced(d.path(), &files);
        assert_eq!(
            refs.get("scripts/setup.js").map(String::as_str),
            Some("package.json postinstall")
        );
        assert!(
            !refs.contains_key("test.js"),
            "test script is not install-time"
        );
        assert_eq!(refs.len(), 1);
    }

    #[test]
    fn setup_py_quoted_script_paths_count() {
        let (d, files) = tree(&[
            (
                "setup.py",
                "import subprocess\nsubprocess.call(['bash', 'tools/post.sh'])\n",
            ),
            ("tools/post.sh", "x"),
        ]);
        let refs = install_referenced(d.path(), &files);
        assert_eq!(
            refs.get("tools/post.sh").map(String::as_str),
            Some("setup.py")
        );
    }

    #[test]
    fn install_link_is_one_explicit_finding_above_the_worst_in_the_file() {
        let (d, files) = tree(&[
            (
                "package.json",
                "{\n  \"scripts\": {\n    \"prepare\": \"node install.js\"\n  }\n}\n",
            ),
            ("install.js", "x"),
            ("lib.js", "x"),
            ("clean.js", "x"),
        ]);
        let mk = |file: &str, phase: Phase, rule: &str, severity: Severity| Finding {
            phase,
            rule: rule.into(),
            severity,
            file: file.into(),
            line: Some(1),
            snippet: "s".into(),
            weight: 1,
            kev: false,
            epss: 0.0,
            fingerprint: String::new(),
            locator: None,
            evidence: Default::default(),
        };
        let findings = vec![
            mk(
                "install.js",
                Phase::NetworkExfil,
                "NET-012",
                Severity::Medium,
            ),
            mk(
                "install.js",
                Phase::CodePatterns,
                "CODE-007",
                Severity::High,
            ),
            mk(
                "install.js",
                Phase::InstallHooks,
                "INSTALL-005",
                Severity::Low,
            ),
            mk("lib.js", Phase::NetworkExfil, "NET-012", Severity::High),
        ];
        let links = link_install_referenced(d.path(), &files, &findings);
        assert_eq!(links.len(), 1, "{links:?}");
        let link = &links[0];
        assert_eq!(link.rule, "INSTALL-REF-001");
        assert_eq!(link.phase, Phase::InstallHooks);
        assert_eq!(link.severity, Severity::Critical, "one above High");
        assert_eq!(link.file, "package.json");
        assert_eq!(link.line, Some(3));
        assert!(link.snippet.contains("package.json prepare -> install.js"));
        assert!(
            link.snippet.contains("CODE-007, NET-012"),
            "{}",
            link.snippet
        );
        assert!(
            !link.snippet.contains("INSTALL-005"),
            "install-hook findings are not counted"
        );

        // A referenced file with nothing above Low produces no link.
        let low_only = vec![mk(
            "install.js",
            Phase::Provenance,
            "PROV-001",
            Severity::Low,
        )];
        assert!(link_install_referenced(d.path(), &files, &low_only).is_empty());
        // A file no lifecycle script runs produces no link either.
        let unreferenced = vec![mk(
            "clean.js",
            Phase::CodePatterns,
            "CODE-001",
            Severity::High,
        )];
        assert!(link_install_referenced(d.path(), &files, &unreferenced).is_empty());
    }

    #[test]
    fn malformed_manifest_is_low_and_jsonc_is_fine() {
        let bad = malformed_manifest("skill/manifest.json", "{\"name\": \"x\",\n").unwrap();
        assert_eq!(bad.rule, "SKILL-007");
        assert_eq!(bad.severity, Severity::Low);
        assert_eq!(bad.phase, Phase::SkillSecurity);
        assert!(malformed_manifest("skill/manifest.json", "{\"name\": \"x\"}").is_none());
        assert!(malformed_manifest("README.json", "not json").is_none());
        let jsonc = "{\n  // comment\n  \"url\": \"https://a.example/b\", /* c */\n  \"servers\": [\"a\",],\n}\n";
        assert!(malformed_manifest(".vscode/mcp.json", jsonc).is_none());
    }
}
