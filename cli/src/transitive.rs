//! Transitive reference scanning: `sigil scan <path> --follow-refs`.
//!
//! A skill does not have to ship its payload. The commonest shape in the
//! real `ai-skills` malware corpus ships a clean-looking `SKILL.md` that tells
//! the agent, or the user, to "download and install" a helper from a
//! throwaway host, or to pipe a remote script into a shell. Scanning the
//! files on disk sees an innocent sentence and a URL; the malicious code is
//! one hop away.
//!
//! With `--follow-refs`, every URL the scanned tree tells someone to fetch,
//! install or run is downloaded into quarantine — never executed — and run
//! through the same phases, up to [`Policy::max_depth`] hops (a landing page
//! that links an installer is followed to the installer). Findings in fetched
//! content keep their rule ids and are attributed to the URL, with a
//! `ref://` locator naming the file and line that referenced it.
//!
//! Two findings are this module's own:
//!
//! - `REF-001` (High): a referenced download is a native executable
//!   (ELF, PE, Mach-O). Static analysis cannot vouch for it, and a skill that
//!   sends its reader to run one is asking for blind trust.
//! - `REF-002` (Low): a referenced artifact could not be fetched, so it was
//!   not scanned. Reported so a clean verdict is never read as covering code
//!   the scanner never saw.
//!
//! Fetching is bounded and fails closed: only `http(s)`, only hosts that
//! resolve to public addresses (a skill cannot turn the scanner into an SSRF
//! probe of the cloud metadata service or the LAN), at most [`Policy::max_refs`]
//! fetches of at most [`Policy::max_bytes`] each, a per-request timeout, and
//! every redirect hop re-checked.

use std::collections::HashSet;
use std::io::Read;
use std::net::{IpAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use regex::Regex;

use crate::scanner::{self, Finding, Phase, Severity};

/// Downloads one URL: `(body, content type)` or the reason it failed.
/// Injected so tests can exercise the walk without a network.
type Fetcher = dyn Fn(&str, &Policy) -> Result<(Vec<u8>, String), String>;

/// Limits for one `--follow-refs` run.
#[derive(Debug, Clone)]
pub struct Policy {
    /// Maximum number of URLs fetched across all hops.
    pub max_refs: usize,
    /// Maximum bytes read from one response.
    pub max_bytes: u64,
    /// Per-request timeout.
    pub timeout: Duration,
    /// Hops from the scanned tree: 1 fetches what the tree references, 2 also
    /// fetches what those documents reference.
    pub max_depth: usize,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            max_refs: 20,
            max_bytes: 10 * 1024 * 1024,
            timeout: Duration::from_secs(15),
            max_depth: 2,
        }
    }
}

/// A URL the scanned content tells someone to fetch, and where it said so.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    pub url: String,
    pub file: String,
    pub line: usize,
}

/// What following references produced.
#[derive(Debug, Default)]
pub struct Outcome {
    pub findings: Vec<Finding>,
    pub fetched: Vec<String>,
    pub failed: Vec<(String, String)>,
    /// References found but not fetched because `max_refs` was reached.
    pub skipped: usize,
}

// ---------------------------------------------------------------------------
// Reference extraction
// ---------------------------------------------------------------------------

fn url_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'*+,;=%]+").expect("static regex")
    })
}

/// Words on the same line that make a URL something to acquire and run
/// rather than something to read or call. A bare `curl https://api…` or
/// `requests.get(…)` is an API call and does not qualify; piping into an
/// interpreter, saving with `-o`, or telling the reader to download or
/// install does.
fn fetch_context_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(\|\s*(sudo\s+)?(sh|bash|zsh|python3?|node|perl|ruby|iex|pwsh|powershell)\b|\b(bash|sh|zsh|source)\s*<\(|\biex\b|invoke-expression|\bdownload(s|ing|ed)?\b|\binstall(er|ation)?\b|\bprerequisites?\b|\brun\s+this\b|\b(curl|wget)\b[^\n]*\s(-o|-O|--output|--remote-name)(\s|$))",
        )
        .expect("static regex")
    })
}

/// Hosts that are placeholders in documentation, templated, or not real
/// names: fetching them only produces "could not resolve" noise.
fn is_placeholder_host(host: &str) -> bool {
    const RESERVED_SUFFIXES: &[&str] = &[
        ".example",
        ".test",
        ".invalid",
        ".local",
        ".localhost",
        ".internal",
        ".lan",
    ];
    const EXAMPLE_DOMAINS: &[&str] = &["example.com", "example.org", "example.net"];
    !host.contains('.')
        || host.contains(['$', '{', '}', '<', '>', '*'])
        || RESERVED_SUFFIXES.iter().any(|s| host.ends_with(s))
        || EXAMPLE_DOMAINS
            .iter()
            .any(|d| host == *d || host.ends_with(&format!(".{d}")))
}

/// Paths shaped like an API route rather than a document or a download.
fn is_api_path(path: &str) -> bool {
    const MARKERS: &[&str] = &[
        "/api/", "/v1/", "/v2/", "/v3/", "/v4/", "/graphql", "/client/", "/rest/", "/oauth",
    ];
    path == "/api" || MARKERS.iter().any(|m| path.contains(m))
}

/// A line that SENDS data to its URL describes an exfiltration or API call,
/// not a download. Following it would contact the attacker's collection
/// endpoint on the scanner's behalf, so such URLs are never fetched.
fn sends_data_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(-X\s*(POST|PUT|PATCH)|--data|--data-binary|--upload-file|\s-d\s|\s-F\s|@-|\.post\(|\.put\(|upload|webhook|sendBeacon)",
        )
        .expect("static regex")
    })
}

/// Path suffixes that name something runnable or unpackable.
const ARTIFACT_SUFFIXES: &[&str] = &[
    ".sh",
    ".bash",
    ".zsh",
    ".ps1",
    ".psm1",
    ".bat",
    ".cmd",
    ".vbs",
    ".hta",
    ".py",
    ".js",
    ".mjs",
    ".cjs",
    ".rb",
    ".pl",
    ".php",
    ".zip",
    ".tar.gz",
    ".tgz",
    ".tar",
    ".whl",
    ".jar",
    ".exe",
    ".msi",
    ".dmg",
    ".pkg",
    ".deb",
    ".rpm",
    ".appimage",
    ".bin",
    ".run",
    ".command",
    ".scr",
    ".apk",
    ".elf",
];

/// Hosts that serve raw content or short links: whatever they return is
/// meant to be consumed, not browsed.
const RAW_HOSTS: &[&str] = &[
    "raw.githubusercontent.com",
    "gist.githubusercontent.com",
    "pastebin.com",
    "paste.ee",
    "hastebin.com",
    "glot.io",
    "rentry.co",
    "rentry.org",
    "transfer.sh",
    "termbin.com",
    "0x0.st",
    "bit.ly",
    "tinyurl.com",
    "is.gd",
];

/// Hosts whose pages are documentation or package indexes. A line saying
/// "install the SDK (https://docs.example.com/...)" points a human at
/// instructions; fetching the HTML would add nothing but noise.
const DOC_HOSTS: &[&str] = &[
    "docs.",
    "developer.",
    "developers.",
    "learn.microsoft.com",
    "readthedocs.io",
    "wikipedia.org",
    "stackoverflow.com",
    "npmjs.com",
    "pypi.org",
    "crates.io",
    "pkg.go.dev",
    "shields.io",
    "img.shields.io",
    "badge.fury.io",
    "opensource.org",
    "apache.org/licenses",
    "creativecommons.org",
    "schemas.",
    "json-schema.org",
    "w3.org",
];

fn host_of(url: &str) -> Option<&str> {
    let rest = url.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit('@').next()?;
    let host = if let Some(stripped) = host.strip_prefix('[') {
        stripped.split(']').next()?
    } else {
        host.split(':').next()?
    };
    (!host.is_empty()).then_some(host)
}

fn path_of(url: &str) -> &str {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let rest = rest.split(['?', '#']).next().unwrap_or(rest);
    rest.find('/').map(|i| &rest[i..]).unwrap_or("/")
}

fn trim_url(raw: &str) -> &str {
    raw.trim_end_matches([
        '.', ',', ';', ':', '!', '?', ')', ']', '\'', '"', '`', '>', '*', '_',
    ])
}

/// Whether `url` names a runnable or unpackable artifact by its path.
fn is_download_artifact(url: &str) -> bool {
    let path = path_of(url).to_ascii_lowercase();
    ARTIFACT_SUFFIXES.iter().any(|s| path.ends_with(s)) || path.contains("/releases/download/")
}

/// Whether `url`, found on `line`, is something the text tells its reader to
/// fetch or run.
pub fn is_fetch_reference(url: &str, line: &str) -> bool {
    let Some(host) = host_of(url) else {
        return false;
    };
    if sends_data_re().is_match(line) {
        return false;
    }
    let host = host.to_ascii_lowercase();
    if is_placeholder_host(&host) {
        return false;
    }
    let path = path_of(url).to_ascii_lowercase();
    if is_download_artifact(url) {
        return true;
    }
    if RAW_HOSTS
        .iter()
        .any(|h| host == *h || host.ends_with(&format!(".{h}")))
    {
        return true;
    }
    let full = format!("{host}{path}");
    if DOC_HOSTS.iter().any(|d| full.contains(d)) {
        return false;
    }
    // A bare repository page is browsed, not run; `sigil clone` covers it.
    if host == "github.com" || host == "gitlab.com" || is_api_path(&path) {
        return false;
    }
    fetch_context_re().is_match(line)
}

/// Extract fetch references from one file's text.
pub fn references_in(file: &str, text: &str) -> Vec<Reference> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        for m in url_re().find_iter(line) {
            let url = trim_url(m.as_str());
            if url.len() > 2048 {
                continue;
            }
            if is_fetch_reference(url, line) {
                out.push(Reference {
                    url: url.to_string(),
                    file: file.to_string(),
                    line: i + 1,
                });
            }
        }
    }
    out
}

/// Text files worth reading for references.
fn is_reference_source(path: &Path) -> bool {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    if matches!(name.as_str(), "makefile" | "dockerfile" | "justfile") {
        return true;
    }
    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    matches!(
        ext.as_str(),
        "md" | "mdx"
            | "txt"
            | "rst"
            | "html"
            | "htm"
            | "sh"
            | "bash"
            | "zsh"
            | "ps1"
            | "bat"
            | "cmd"
            | "py"
            | "js"
            | "mjs"
            | "cjs"
            | "ts"
            | "json"
            | "yaml"
            | "yml"
            | "toml"
    )
}

/// Every fetch reference under `root`, deduplicated by URL (first occurrence
/// wins), in file order.
pub fn collect_references(root: &Path) -> Vec<Reference> {
    let base = if root.is_file() {
        root.parent().unwrap_or(root)
    } else {
        root
    };
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for path in scanner::collect_files(root) {
        if !is_reference_source(&path) {
            continue;
        }
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };
        if meta.len() > 2 * 1024 * 1024 {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let text = String::from_utf8_lossy(&bytes);
        let rel = path
            .strip_prefix(base)
            .unwrap_or(&path)
            .to_string_lossy()
            .to_string();
        for r in references_in(&rel, &text) {
            if seen.insert(r.url.clone()) {
                out.push(r);
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Fetching
// ---------------------------------------------------------------------------

/// Whether `ip` is an address a scanner must never be steered at.
fn is_internal(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_documentation()
                || o[0] == 0
                // 100.64.0.0/10 carrier-grade NAT
                || (o[0] == 100 && (o[1] & 0xC0) == 64)
                // 198.18.0.0/15 benchmarking
                || (o[0] == 198 && (o[1] & 0xFE) == 18)
                || o[0] >= 240
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_internal(IpAddr::V4(v4));
            }
            let s = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // fc00::/7 unique local, fe80::/10 link local
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Redirects followed before a fetch is abandoned.
const MAX_REDIRECTS: usize = 5;

/// Vet `url`'s host and refuse anything that is not a public address.
///
/// The host comes from the same URL parser reqwest connects with, so the
/// host that is checked is the host that is dialled (a hand-rolled split
/// reads `http://127.0.0.1\@example.com/` as example.com; the WHATWG parser
/// reqwest uses reads it as 127.0.0.1). Returns the name and the vetted
/// address to pin the connection to, or `None` for an IP literal, which is
/// never resolved.
fn public_address(url: &str) -> Result<Option<(String, std::net::SocketAddr)>, String> {
    let parsed = reqwest::Url::parse(url).map_err(|e| format!("bad URL: {e}"))?;
    let default_port = match parsed.scheme() {
        "https" => 443,
        "http" => 80,
        _ => return Err("only http and https references are fetched".into()),
    };
    let port = parsed.port().unwrap_or(default_port);
    let host = parsed.host_str().ok_or("no host in URL")?;
    let literal = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = literal.parse::<IpAddr>() {
        if is_internal(ip) {
            return Err(format!("refused internal address {ip}"));
        }
        return Ok(None);
    }
    let host = host.to_ascii_lowercase();
    if host == "localhost" || host.ends_with(".localhost") {
        return Err(format!("refused internal host {host}"));
    }
    let addrs: Vec<_> = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve {host}: {e}"))?
        .collect();
    if addrs.is_empty() {
        return Err(format!("cannot resolve {host}"));
    }
    if let Some(bad) = addrs.iter().find(|a| is_internal(a.ip())) {
        return Err(format!(
            "refused {host}: resolves to internal address {}",
            bad.ip()
        ));
    }
    Ok(Some((host, addrs[0])))
}

/// Where a redirect from `current` to `location` leads, as an absolute URL.
fn redirect_target(current: &str, location: &str) -> Result<String, String> {
    reqwest::Url::parse(current)
        .and_then(|base| base.join(location))
        .map(|u| u.to_string())
        .map_err(|e| format!("bad redirect to {location:?}: {e}"))
}

/// Fetch `url`, following redirects by hand. Every hop is vetted by
/// `public_address` and its connection is pinned to the address that was
/// vetted, so a second DNS answer for a redirect's host cannot swap in an
/// internal address between the check and the connection.
fn fetch_bytes(url: &str, policy: &Policy) -> Result<(Vec<u8>, String), String> {
    let deadline = std::time::Instant::now() + policy.timeout;
    let mut current = url.to_string();
    for _ in 0..=MAX_REDIRECTS {
        let pin = public_address(&current)?;
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err("timed out".into());
        }
        let mut builder = reqwest::blocking::Client::builder()
            .timeout(remaining)
            .user_agent(concat!(
                "sigil/",
                env!("CARGO_PKG_VERSION"),
                " (reference scan; content is never executed)"
            ))
            .redirect(reqwest::redirect::Policy::none());
        if let Some((host, addr)) = &pin {
            builder = builder.resolve(host, *addr);
        }
        let client = builder.build().map_err(|e| format!("client: {e}"))?;
        let resp = client
            .get(&current)
            .send()
            .map_err(|e| format!("fetch failed: {e}"))?;
        let status = resp.status();
        if status.is_redirection() {
            let location = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| format!("HTTP {status} without a Location"))?;
            current = redirect_target(&current, location)?;
            continue;
        }
        if !status.is_success() {
            return Err(format!("HTTP {status}"));
        }
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();
        let mut body = Vec::new();
        resp.take(policy.max_bytes + 1)
            .read_to_end(&mut body)
            .map_err(|e| format!("read failed: {e}"))?;
        if body.len() as u64 > policy.max_bytes {
            return Err(format!("larger than {} bytes", policy.max_bytes));
        }
        return Ok((body, content_type));
    }
    Err("too many redirects".into())
}

/// What a downloaded body is, from its first bytes.
#[derive(Debug, PartialEq, Eq)]
enum Kind {
    NativeExecutable(&'static str),
    Zip,
    Gzip,
    Html,
    Other,
}

fn sniff(body: &[u8], content_type: &str) -> Kind {
    let head = &body[..body.len().min(16)];
    if head.starts_with(b"\x7fELF") {
        return Kind::NativeExecutable("ELF");
    }
    if head.starts_with(b"MZ") {
        return Kind::NativeExecutable("PE (Windows)");
    }
    if [
        &[0xfe, 0xed, 0xfa, 0xce][..],
        &[0xfe, 0xed, 0xfa, 0xcf],
        &[0xce, 0xfa, 0xed, 0xfe],
        &[0xcf, 0xfa, 0xed, 0xfe],
    ]
    .iter()
    .any(|m| head.starts_with(m))
    {
        return Kind::NativeExecutable("Mach-O");
    }
    if head.starts_with(b"PK\x03\x04") {
        return Kind::Zip;
    }
    if head.starts_with(&[0x1f, 0x8b]) {
        return Kind::Gzip;
    }
    let lower: String = String::from_utf8_lossy(&body[..body.len().min(512)])
        .trim_start()
        .to_ascii_lowercase();
    if content_type.contains("text/html")
        || lower.starts_with("<!doctype html")
        || lower.starts_with("<html")
    {
        return Kind::Html;
    }
    Kind::Other
}

/// A file name for fetched content that keeps the extension the phase file
/// filters key on.
fn local_name(url: &str, kind: &Kind) -> String {
    let last = path_of(url).rsplit('/').next().unwrap_or("");
    let cleaned: String = last
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        .take(96)
        .collect();
    let cleaned = cleaned.trim_start_matches('.').to_string();
    match kind {
        Kind::Html if !cleaned.ends_with(".html") && !cleaned.ends_with(".htm") => {
            "index.html".into()
        }
        Kind::Zip if !cleaned.ends_with(".zip") => "download.zip".into(),
        Kind::Gzip if !(cleaned.ends_with(".tar.gz") || cleaned.ends_with(".tgz")) => {
            "download.tar.gz".into()
        }
        _ if cleaned.is_empty() => "download.txt".into(),
        _ => cleaned,
    }
}

fn ref_finding(
    rule: &str,
    severity: Severity,
    weight: u32,
    r: &Reference,
    snippet: String,
) -> Finding {
    Finding {
        phase: Phase::SkillSecurity,
        rule: rule.to_string(),
        severity,
        file: r.file.clone(),
        line: Some(r.line),
        snippet,
        weight,
        kev: false,
        epss: 0.0,
        fingerprint: String::new(),
        locator: Some(format!("ref://{}", r.url)),
        evidence: Default::default(),
    }
}

/// Fetch and scan one reference into `dir`. Returns the findings and the
/// references found inside the fetched content (for the next hop).
fn follow_one(
    r: &Reference,
    dir: &Path,
    policy: &Policy,
    fetch: &Fetcher,
) -> Result<(Vec<Finding>, Vec<Reference>), String> {
    let (body, content_type) = fetch(&r.url, policy)?;
    let kind = sniff(&body, &content_type);
    if let Kind::NativeExecutable(format) = kind {
        return Ok((
            vec![ref_finding(
                "REF-001",
                Severity::High,
                5,
                r,
                format!(
                    "Referenced download is a native {format} executable ({} bytes) that static analysis cannot vouch for: {}",
                    body.len(),
                    r.url
                ),
            )],
            Vec::new(),
        ));
    }

    std::fs::create_dir_all(dir).map_err(|e| format!("quarantine dir: {e}"))?;
    let name = local_name(&r.url, &kind);
    let path = dir.join(&name);
    std::fs::write(&path, &body).map_err(|e| format!("write: {e}"))?;
    if matches!(kind, Kind::Zip | Kind::Gzip) {
        // Same bounded extractor the package workflows use.
        crate::extract_archives(dir).map_err(|e| format!("extract: {e}"))?;
    }

    let result = scanner::run_scan(dir, None, None);
    let via = format!("{}:{}", r.file, r.line);
    let findings = result
        .findings
        .into_iter()
        .map(|mut f| {
            f.locator = Some(format!("ref://{}|file://{}", r.url, f.file));
            f.snippet = format!("[fetched from {} via {via}] {}", r.url, f.snippet);
            f.file = r.url.clone();
            f
        })
        .collect();

    // Only a landing page is followed further, and only to what it offers
    // for download. URLs inside a fetched *script* are that script's own
    // network targets — often its exfiltration endpoint — and are reported by
    // the phases above, never contacted.
    let mut next = Vec::new();
    if kind == Kind::Html {
        let text = String::from_utf8_lossy(&body);
        next = references_in(&r.url, &text)
            .into_iter()
            .filter(|n| n.url != r.url && is_download_artifact(&n.url))
            .collect();
    }
    Ok((findings, next))
}

/// Follow every fetch reference under `root`, scanning what comes back.
///
/// `work_dir` receives one numbered subdirectory per fetched reference; the
/// caller decides whether it lives in quarantine or a temporary directory.
pub fn follow_references(root: &Path, work_dir: &Path, policy: &Policy) -> Outcome {
    follow_with(root, work_dir, policy, &fetch_bytes)
}

fn follow_with(root: &Path, work_dir: &Path, policy: &Policy, fetch: &Fetcher) -> Outcome {
    let mut outcome = Outcome::default();
    let mut seen: HashSet<String> = HashSet::new();
    let mut frontier = collect_references(root);
    let mut n = 0usize;

    for _depth in 0..policy.max_depth {
        let mut next = Vec::new();
        for r in frontier {
            if !seen.insert(r.url.clone()) {
                continue;
            }
            if n >= policy.max_refs {
                outcome.skipped += 1;
                continue;
            }
            n += 1;
            match follow_one(&r, &work_dir.join(format!("{n:03}")), policy, fetch) {
                Ok((findings, more)) => {
                    outcome.fetched.push(r.url.clone());
                    outcome.findings.extend(findings);
                    next.extend(more);
                }
                Err(reason) => {
                    outcome.findings.push(ref_finding(
                        "REF-002",
                        Severity::Low,
                        1,
                        &r,
                        format!("Referenced artifact was not scanned ({reason}): {}", r.url),
                    ));
                    outcome.failed.push((r.url.clone(), reason));
                }
            }
        }
        frontier = next;
        if frontier.is_empty() {
            break;
        }
    }
    outcome.skipped += frontier.iter().filter(|r| !seen.contains(&r.url)).count();
    outcome
}

/// Where a `--follow-refs` run keeps what it downloaded: a fresh directory
/// under the quarantine root, so the fetched bytes can be inspected later
/// and are never mistaken for trusted code.
pub fn default_work_dir() -> PathBuf {
    crate::quarantine::quarantine_path().join(format!("refs-{}", uuid::Uuid::new_v4()))
}

#[cfg(test)]
#[path = "transitive_tests.rs"]
mod tests;
