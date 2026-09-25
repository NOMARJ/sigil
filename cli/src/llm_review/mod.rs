//! Optional LLM review of scan findings (`sigil scan --llm-review`).
//!
//! Off by default: without it, a scan never opens a network connection for
//! this stage. When it is on, each finding at Medium or above is sent — rule,
//! title, file path, matched line and a few masked lines around it — to a
//! model the operator chooses: the Anthropic Messages API, or any
//! OpenAI-compatible chat-completions endpoint. The model answers per finding
//! `confirm`, `dismiss` or `escalate` with a one-line rationale, as JSON that
//! is parsed strictly.
//!
//! # Trust model
//!
//! The scanned content is attacker-controlled and will argue with the
//! reviewer. So the stage is **advisory** by default: it annotates findings
//! and adds an `llm_review` block to the report, and never changes a
//! severity or the verdict. A dismissal can lower a finding by one level only
//! when the scan policy sets `llm_may_downgrade: true`, and even then never:
//!
//! - a Critical finding;
//! - a prompt-injection or agent-manipulation finding (the prompt-injection
//!   phase, or a `PROMPT-`, `MANIP-` or `INTL-` rule);
//! - a finding below Medium (nothing goes below Low);
//! - any finding in a file where text addressed to a reviewer, a scanner or
//!   an AI model was seen (see [`REVIEWER_RULES`]).
//!
//! The report keeps the original severity and the model's rationale. Any
//! failure — no key, network, timeout, quota, a refusal, output that does not
//! parse — leaves the findings exactly as the offline scan produced them and
//! is reported as incomplete coverage *of the LLM stage*; it never changes
//! the scan's exit code.
//!
//! # What leaves the machine
//!
//! See `docs/llm-review.md`. Every string taken from the scanned tree is
//! masked first ([`mask::Masker`]); secret files (`.env*`, private keys,
//! `.npmrc`, `.netrc`, ...) are never read; symbolic links and paths that
//! resolve outside the scanned tree are never followed.

pub mod mask;
pub mod prompt;
pub mod provider;

#[cfg(test)]
mod tests;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use regex::Regex;
use serde::Serialize;
use serde_json::{json, Value};

pub use provider::Provider;

use crate::scanner::{Finding, Phase, ScanResult, Severity};
use mask::Masker;
use prompt::ParsedReview;

/// Default cap on HTTP calls per scan.
pub const DEFAULT_MAX_CALLS: u32 = 25;
/// Default cap on tokens (input + output) per scan.
pub const DEFAULT_MAX_TOKENS: u64 = 200_000;
/// Default per-request timeout.
pub const DEFAULT_TIMEOUT_SECS: u64 = 120;
/// Requests in flight at once.
pub const DEFAULT_CONCURRENCY: usize = 4;
/// Findings per request.
pub const DEFAULT_BATCH_SIZE: usize = 8;
/// Lines sent on each side of a finding's line.
pub const DEFAULT_CONTEXT_LINES: usize = 6;
/// Reply limit per request (`max_tokens`), thinking included.
pub const DEFAULT_MAX_OUTPUT_TOKENS: u64 = 8_192;

/// Smallest reply limit a request is sent with; below it a reply would be
/// cut off, so the request is not made.
const MIN_OUTPUT_TOKENS: u64 = 2_048;
/// Tokens reserved on top of the request's size for message framing.
const FRAMING_TOKENS: u64 = 1_024;
/// Longest line sent, in characters.
const MAX_LINE_CHARS: usize = 240;
/// Longest matched-line text sent, in characters.
const MAX_MATCHED_CHARS: usize = 400;
/// Longest rule guidance sent, in characters.
const MAX_GUIDANCE_CHARS: usize = 600;
/// Most bytes read from one file to find a finding's window.
const MAX_WINDOW_READ_BYTES: u64 = 32 * 1024 * 1024;
/// Longest wait honoured from a `retry-after` header.
const MAX_RETRY_WAIT: Duration = Duration::from_secs(10);

/// Rules whose match is text aimed at a reviewer, a scanner or a model. A
/// file carrying one never has a finding downgraded on a model's advice, and
/// the same patterns are run over every excerpt before it is sent.
pub const REVIEWER_RULES: &[&str] = &["MANIP-012", "MANIP-013", "PROMPT-001"];

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

/// An API key. Never printed, serialized or put in an error message.
#[derive(Clone)]
pub struct ApiKey(String);

impl ApiKey {
    pub fn new(s: String) -> Self {
        ApiKey(s)
    }
    fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApiKey(<redacted>)")
    }
}

/// Everything the stage needs to run.
#[derive(Debug, Clone)]
pub struct LlmSettings {
    pub provider: Provider,
    /// The full request URL.
    pub url: String,
    pub model: String,
    pub api_key: Option<ApiKey>,
    pub may_downgrade: bool,
    pub max_calls: u32,
    pub max_tokens: u64,
    pub timeout: Duration,
    pub concurrency: usize,
    pub batch_size: usize,
    pub context_lines: usize,
    pub max_output_tokens: u64,
}

impl LlmSettings {
    /// Settings for `provider` at `url` with the defaults for everything else.
    pub fn new(provider: Provider, url: String, model: String, api_key: Option<ApiKey>) -> Self {
        LlmSettings {
            provider,
            url,
            model,
            api_key,
            may_downgrade: false,
            max_calls: DEFAULT_MAX_CALLS,
            max_tokens: DEFAULT_MAX_TOKENS,
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            concurrency: DEFAULT_CONCURRENCY,
            batch_size: DEFAULT_BATCH_SIZE,
            context_lines: DEFAULT_CONTEXT_LINES,
            max_output_tokens: DEFAULT_MAX_OUTPUT_TOKENS,
        }
    }
}

/// The LLM keys of a merged scan policy (organisation, project, flags).
#[derive(Debug, Clone, Default)]
pub struct LlmPolicy {
    pub review: Option<bool>,
    pub may_downgrade: Option<bool>,
    pub provider: Option<Provider>,
    pub model: Option<String>,
    /// Set only by the organisation policy.
    pub endpoint: Option<String>,
    pub max_calls: Option<u32>,
    pub max_tokens: Option<u64>,
}

/// What the policy and the environment say about the stage.
#[derive(Debug)]
pub enum Resolution {
    /// Not requested.
    Off,
    /// Requested and configured.
    Ready(Box<LlmSettings>),
    /// Requested, but it cannot run; the report says why.
    Misconfigured(Box<LlmReport>),
}

/// Resolve the stage's settings. `env` looks up an environment variable
/// (injected so tests do not depend on the ambient environment).
///
/// Provider: the policy's `llm_provider`; otherwise OpenAI-compatible when an
/// endpoint is configured (the organisation's `llm_endpoint`, else
/// `SIGIL_LLM_ENDPOINT`), and Anthropic when not. The Anthropic key is only
/// ever sent to the Anthropic base URL (`ANTHROPIC_BASE_URL`, default
/// `https://api.anthropic.com`), never to a configured endpoint.
pub fn resolve(policy: &LlmPolicy, env: &dyn Fn(&str) -> Option<String>) -> Resolution {
    if policy.review != Some(true) {
        return Resolution::Off;
    }
    let env = |k: &str| env(k).filter(|v| !v.trim().is_empty());
    let endpoint = policy
        .endpoint
        .clone()
        .or_else(|| env("SIGIL_LLM_ENDPOINT"));
    let provider = policy.provider.unwrap_or(if endpoint.is_some() {
        Provider::OpenAiCompatible
    } else {
        Provider::Anthropic
    });
    let model = policy.model.clone().or_else(|| match provider {
        Provider::Anthropic => Some(provider::DEFAULT_ANTHROPIC_MODEL.to_string()),
        Provider::OpenAiCompatible => None,
    });
    let (url, key) = match provider {
        Provider::Anthropic => {
            let base = env("ANTHROPIC_BASE_URL")
                .unwrap_or_else(|| provider::ANTHROPIC_DEFAULT_BASE.to_string());
            (
                Some(provider::anthropic_url(&base)),
                env("ANTHROPIC_API_KEY"),
            )
        }
        Provider::OpenAiCompatible => (
            endpoint.as_deref().map(provider::openai_url),
            env("SIGIL_LLM_API_KEY"),
        ),
    };
    let fail = |reason: String| {
        let mut r = LlmReport::not_run(
            provider,
            url.as_deref()
                .map(provider::display_url)
                .unwrap_or_default(),
            model.clone().unwrap_or_default(),
            reason,
        );
        r.mode = mode_label(policy.may_downgrade.unwrap_or(false)).to_string();
        Resolution::Misconfigured(Box::new(r))
    };
    let Some(url) = url.clone() else {
        return fail(
            "no endpoint: set SIGIL_LLM_ENDPOINT (or llm_endpoint in the organisation policy) \
             for an OpenAI-compatible provider"
                .into(),
        );
    };
    if let Err(e) = provider::check_endpoint(&url) {
        return fail(e);
    }
    let Some(model) = model.clone() else {
        return fail(
            "no model: pass --llm-model or set SIGIL_LLM_MODEL (or llm_model in a policy)".into(),
        );
    };
    if provider == Provider::Anthropic && key.is_none() {
        return fail("ANTHROPIC_API_KEY is not set".into());
    }
    let mut s = LlmSettings::new(provider, url, model, key.map(ApiKey::new));
    s.may_downgrade = policy.may_downgrade.unwrap_or(false);
    s.max_calls = policy.max_calls.unwrap_or(DEFAULT_MAX_CALLS);
    s.max_tokens = policy.max_tokens.unwrap_or(DEFAULT_MAX_TOKENS);
    if let Some(t) = env("SIGIL_LLM_TIMEOUT_SECS") {
        match t.trim().parse::<u64>() {
            Ok(n) if (1..=3600).contains(&n) => s.timeout = Duration::from_secs(n),
            _ => {
                return fail(format!(
                    "SIGIL_LLM_TIMEOUT_SECS '{t}' is not a number of seconds between 1 and 3600"
                ))
            }
        }
    }
    Resolution::Ready(Box::new(s))
}

fn mode_label(may_downgrade: bool) -> &'static str {
    if may_downgrade {
        "downgrade_allowed"
    } else {
        "advisory"
    }
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

/// What was sent, in aggregate.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SentSummary {
    /// Findings whose data was sent at least once.
    pub findings: usize,
    /// Request bytes sent, over all calls.
    pub bytes: usize,
    /// Values masked before sending.
    pub masked_values: usize,
    /// Findings whose surrounding lines were withheld (secret file, symbolic
    /// link, outside the tree, binary, unreadable); only rule, title, path
    /// and the masked matched line were sent for them.
    pub excerpts_withheld: usize,
}

/// The model's review of one finding, and what Sigil did with it.
#[derive(Debug, Clone, Serialize)]
pub struct ReviewEntry {
    pub rule: String,
    pub file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub fingerprint: String,
    /// `confirm`, `dismiss` or `escalate`.
    pub verdict: String,
    pub rationale: String,
    /// `none` (confirm), `note` (escalate), `downgraded`, or `not_applied`
    /// (a dismissal the policy or the trust rules did not act on).
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_applied_reason: Option<String>,
    /// The finding's severity after the stage.
    pub severity: String,
    /// Set when the stage changed the severity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_severity: Option<String>,
    /// Text addressed to a reviewer was seen in this finding's file.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub manipulation_suspected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip)]
    key: String,
}

/// The `llm_review` block of a report.
#[derive(Debug, Clone, Serialize)]
pub struct LlmReport {
    /// `complete`, `incomplete` or `not_run`: coverage of this stage, not of
    /// the scan.
    pub status: String,
    /// `advisory` or `downgrade_allowed`.
    pub mode: String,
    pub provider: String,
    pub endpoint: String,
    pub model: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub served_models: Vec<String>,
    pub calls: u32,
    pub max_calls: u32,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub max_tokens: u64,
    /// Findings the stage should review (Medium and above).
    pub eligible: usize,
    pub reviewed: usize,
    pub not_reviewed: usize,
    pub confirmed: usize,
    pub dismissed: usize,
    pub escalated: usize,
    /// Dismissals acted on (`llm_may_downgrade: true`).
    pub downgraded: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub incomplete_reasons: Vec<String>,
    /// Files where text addressed to a reviewer was seen.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub manipulation_files: Vec<String>,
    pub sent: SentSummary,
    pub reviews: Vec<ReviewEntry>,
}

impl LlmReport {
    fn empty(provider: Provider, endpoint: String, model: String) -> Self {
        LlmReport {
            status: "complete".into(),
            mode: mode_label(false).into(),
            provider: provider.label().into(),
            endpoint,
            model,
            served_models: Vec::new(),
            calls: 0,
            max_calls: 0,
            input_tokens: 0,
            output_tokens: 0,
            max_tokens: 0,
            eligible: 0,
            reviewed: 0,
            not_reviewed: 0,
            confirmed: 0,
            dismissed: 0,
            escalated: 0,
            downgraded: 0,
            incomplete_reasons: Vec::new(),
            manipulation_files: Vec::new(),
            sent: SentSummary::default(),
            reviews: Vec::new(),
        }
    }

    /// A stage that could not run at all.
    pub fn not_run(provider: Provider, endpoint: String, model: String, reason: String) -> Self {
        let mut r = LlmReport::empty(provider, endpoint, model);
        r.status = "not_run".into();
        r.incomplete_reasons.push(reason);
        r
    }

    /// The review of `f`, if the model reviewed it.
    pub fn review_for(&self, f: &Finding) -> Option<&ReviewEntry> {
        let key = finding_key(f);
        self.reviews.iter().find(|r| r.key == key)
    }

    /// One line for the terminal and Markdown summaries.
    pub fn summary_line(&self) -> String {
        match self.status.as_str() {
            "not_run" => format!(
                "LLM review did not run: {}",
                self.incomplete_reasons.join("; ")
            ),
            _ => {
                let mut s = format!(
                    "LLM review ({}, {} via {}): {} of {} finding(s) reviewed — {} confirmed, {} dismissed{}, {} escalated; {} call(s), {} input + {} output tokens",
                    self.mode.replace('_', " "),
                    self.model,
                    self.provider,
                    self.reviewed,
                    self.eligible,
                    self.confirmed,
                    self.dismissed,
                    if self.dismissed > 0 {
                        format!(" ({} applied)", self.downgraded)
                    } else {
                        String::new()
                    },
                    self.escalated,
                    self.calls,
                    self.input_tokens,
                    self.output_tokens,
                );
                if self.status == "incomplete" {
                    s.push_str(&format!(
                        ". Incomplete: {}",
                        self.incomplete_reasons.join("; ")
                    ));
                }
                s
            }
        }
    }
}

/// How a finding is matched to its review across the report: the content
/// fingerprint, or the location when a finding has none.
fn finding_key(f: &Finding) -> String {
    if f.fingerprint.is_empty() {
        format!(
            "{}|{}|{}|{}",
            f.rule,
            f.file,
            f.line.unwrap_or(0),
            f.snippet
        )
    } else {
        f.fingerprint.clone()
    }
}

// ---------------------------------------------------------------------------
// Building requests
// ---------------------------------------------------------------------------

/// Patterns of the [`REVIEWER_RULES`], run over excerpts before sending.
struct ReviewerText {
    regexes: Vec<Regex>,
}

impl ReviewerText {
    fn from_corpus() -> Self {
        let regexes = crate::corpus::compiled::corpus()
            .content_rules_sorted()
            .into_iter()
            .filter(|r| REVIEWER_RULES.contains(&r.id.as_str()))
            .map(|r| r.regex.clone())
            .collect();
        ReviewerText { regexes }
    }

    fn any(&self, lines: &[String]) -> bool {
        lines
            .iter()
            .any(|l| self.regexes.iter().any(|re| re.is_match(l)))
    }
}

/// One finding, ready to send.
struct Packet {
    finding: usize,
    value: Value,
    masked: usize,
    withheld: bool,
    reviewer_text: bool,
}

/// Is this path a file whose content is secret by its nature? Its lines are
/// never read for an excerpt.
pub fn is_secret_file(rel: &str) -> bool {
    let norm = rel.replace('\\', "/").to_ascii_lowercase();
    let name = norm.rsplit('/').next().unwrap_or(&norm);
    let ext = name.rsplit_once('.').map(|(_, e)| e).unwrap_or("");
    name == ".env"
        || name.starts_with(".env.")
        || name.ends_with(".env")
        || matches!(
            ext,
            "pem" | "key" | "p12" | "pfx" | "jks" | "keystore" | "kdbx" | "ppk" | "gpg" | "asc"
        )
        // OpenSSH's default key file names: id_ followed by the key type.
        || name.strip_prefix("id_").is_some_and(|rest| {
            ["rsa", "dsa", "ecdsa", "ed25519"]
                .iter()
                .any(|t| rest.starts_with(t))
        })
        || matches!(
            name,
            "credentials"
                | ".npmrc"
                | ".pypirc"
                | ".netrc"
                | "_netrc"
                | ".git-credentials"
                | ".htpasswd"
                | ".pgpass"
                | ".dockercfg"
                | "secrets.yml"
                | "secrets.yaml"
                | "secrets.json"
        )
        || norm.ends_with(".aws/credentials")
        || norm.ends_with(".docker/config.json")
        || norm.ends_with(".kube/config")
}

/// The file a finding points at, if the stage may read it: a regular file
/// (not a symbolic link) inside the scanned tree.
fn resolve_file(root: &Path, rel: &str) -> Result<PathBuf, &'static str> {
    let base = if root.is_file() {
        root.parent().unwrap_or(root)
    } else {
        root
    };
    let candidate = base.join(rel);
    let meta = std::fs::symlink_metadata(&candidate).map_err(|_| "file not on disk")?;
    if meta.file_type().is_symlink() {
        return Err("symbolic link");
    }
    if !meta.is_file() {
        return Err("not a regular file");
    }
    let canon_base = std::fs::canonicalize(base).map_err(|_| "file not on disk")?;
    let canon = std::fs::canonicalize(&candidate).map_err(|_| "file not on disk")?;
    if !canon.starts_with(&canon_base) {
        return Err("outside the scanned tree");
    }
    Ok(canon)
}

/// Lines `line - ctx ..= line + ctx` of a file (1-based).
fn read_window(path: &Path, line: usize, ctx: usize) -> Result<Vec<(usize, String)>, &'static str> {
    use std::io::{BufRead, BufReader, Read};
    let file = std::fs::File::open(path).map_err(|_| "unreadable")?;
    let mut reader = BufReader::new(file.take(MAX_WINDOW_READ_BYTES));
    let first = line.saturating_sub(ctx).max(1);
    let last = line + ctx;
    let mut out = Vec::new();
    let mut buf = Vec::new();
    let mut n = 0usize;
    loop {
        buf.clear();
        let read = reader
            .read_until(b'\n', &mut buf)
            .map_err(|_| "unreadable")?;
        if read == 0 {
            break;
        }
        n += 1;
        if n >= first {
            if buf.contains(&0) {
                return Err("binary content");
            }
            let text = String::from_utf8_lossy(&buf)
                .trim_end_matches(['\n', '\r'])
                .to_string();
            out.push((n, text));
        }
        if n >= last {
            break;
        }
    }
    if out.iter().all(|(n, _)| *n != line) {
        return Err("line not found");
    }
    Ok(out)
}

/// At most `max` characters of `line`, centred on `focus` when the line is
/// longer and contains it.
fn clip(line: &str, focus: Option<&str>, max: usize) -> String {
    let chars: Vec<char> = line.chars().collect();
    if chars.len() <= max {
        return line.to_string();
    }
    let start_char = focus
        .filter(|f| !f.is_empty())
        .and_then(|f| line.find(f))
        .map(|byte| line[..byte].chars().count())
        .map(|c| c.saturating_sub(max / 3))
        .unwrap_or(0)
        .min(chars.len() - max);
    let mut s = String::new();
    if start_char > 0 {
        s.push('…');
    }
    s.extend(chars[start_char..start_char + max].iter());
    if start_char + max < chars.len() {
        s.push('…');
    }
    s
}

fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max).collect();
        t.push('…');
        t
    }
}

fn build_packet(
    id: &str,
    idx: usize,
    f: &Finding,
    root: &Path,
    settings: &LlmSettings,
    masker: &Masker,
    reviewer: &ReviewerText,
) -> Packet {
    let mut masked = 0usize;
    let mut m = |s: &str| {
        let (t, n) = masker.mask_text(s);
        masked += n;
        t
    };
    let title = m(&crate::scanner::profile::title_of(f));
    let guidance = crate::corpus::compiled::corpus()
        .rule_meta(&f.rule)
        .and_then(|meta| meta.remediation.clone())
        .map(|g| m(&truncate_chars(&g, MAX_GUIDANCE_CHARS)))
        .unwrap_or_default();
    let file = m(&f.file);
    let snippet = f.snippet.trim();
    let matched = m(&truncate_chars(snippet, MAX_MATCHED_CHARS));
    let focus: String = snippet.chars().take(40).collect();

    let line = f.line.filter(|l| *l > 0);
    let mut reviewer_text = reviewer.any(std::slice::from_ref(&f.snippet));
    let window: Result<Vec<(usize, String)>, &'static str> = if is_secret_file(&f.file) {
        Err("secret file")
    } else {
        match line {
            None => Err("no line number"),
            Some(l) => {
                resolve_file(root, &f.file).and_then(|p| read_window(&p, l, settings.context_lines))
            }
        }
    };
    let (excerpt, withheld) = match window {
        Ok(lines) => {
            let raw: Vec<String> = lines.iter().map(|(_, t)| t.clone()).collect();
            reviewer_text |= reviewer.any(&raw);
            let (masked_lines, n) = masker.mask_lines(&raw);
            masked += n;
            let text = lines
                .iter()
                .zip(masked_lines)
                .map(|((n, _), t)| {
                    let marker = if Some(*n) == line { ">" } else { " " };
                    format!(
                        "{marker}{n:>6} | {}",
                        clip(&t, Some(&focus), MAX_LINE_CHARS)
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            (Value::String(text), None)
        }
        Err(why) => (Value::Null, Some(why)),
    };
    let mut value = json!({
        "id": id,
        "rule": f.rule,
        "title": title,
        "severity": f.severity.to_string(),
        "phase": f.phase.display_name(),
        "file": file,
        "line": line,
        "matched": matched,
        "excerpt": excerpt,
    });
    if !guidance.is_empty() {
        value["guidance"] = json!(guidance);
    }
    if let Some(why) = withheld {
        value["excerpt_withheld"] = json!(why);
    }
    Packet {
        finding: idx,
        value,
        masked,
        withheld: withheld.is_some() && withheld != Some("no line number"),
        reviewer_text,
    }
}

// ---------------------------------------------------------------------------
// Running
// ---------------------------------------------------------------------------

/// Per-scan caps, shared by the requests in flight.
struct Budget {
    calls_left: u32,
    tokens_left: u64,
    calls: u32,
    input_tokens: u64,
    output_tokens: u64,
}

enum BatchOutcome {
    Reviewed {
        reviews: Vec<ParsedReview>,
        model: Option<String>,
    },
    Failed(String),
    Skipped(&'static str),
}

struct Batch {
    ids: Vec<String>,
    packets: Vec<usize>,
    user: String,
}

/// Findings the stage reviews, highest severity first.
fn eligible(result: &ScanResult) -> Vec<usize> {
    let mut idx: Vec<usize> = result
        .findings
        .iter()
        .enumerate()
        .filter(|(_, f)| {
            f.severity >= Severity::Medium && !crate::scanner::coverage::is_coverage_rule(&f.rule)
        })
        .map(|(i, _)| i)
        .collect();
    idx.sort_by(|a, b| {
        let (fa, fb) = (&result.findings[*a], &result.findings[*b]);
        fb.severity
            .cmp(&fa.severity)
            .then_with(|| fa.file.cmp(&fb.file))
            .then_with(|| fa.line.cmp(&fb.line))
    });
    idx
}

/// Files that carry a reviewer-addressing finding, active or suppressed.
fn reviewer_files(result: &ScanResult) -> HashSet<String> {
    result
        .findings
        .iter()
        .chain(result.inline_suppressed.iter())
        .chain(result.suppressed_findings.iter())
        .filter(|f| REVIEWER_RULES.contains(&f.rule.as_str()))
        .map(|f| f.file.clone())
        .collect()
}

/// Is this finding one the model may never talk down?
fn protected_reason(f: &Finding, reviewer_file: bool) -> Option<&'static str> {
    if f.severity == Severity::Critical {
        Some("Critical findings are never downgraded")
    } else if f.phase == Phase::PromptInjection
        || ["PROMPT-", "MANIP-", "INTL-"]
            .iter()
            .any(|p| f.rule.starts_with(p))
    {
        Some("prompt-injection and agent-manipulation findings are never downgraded")
    } else if f.severity <= Severity::Low {
        Some("nothing is downgraded below Low")
    } else if reviewer_file {
        Some("the file contains text addressed to a reviewer or a model")
    } else {
        None
    }
}

fn one_level_down(s: Severity) -> Severity {
    match s {
        Severity::Critical => Severity::High,
        Severity::High => Severity::Medium,
        Severity::Medium | Severity::Low => Severity::Low,
    }
}

/// Run the stage over a finished, policy-applied scan result.
///
/// Changes `result` only when `settings.may_downgrade` is set and a
/// dismissal passes every trust rule; score and verdict are then recomputed.
pub async fn run(result: &mut ScanResult, scan_root: &Path, settings: &LlmSettings) -> LlmReport {
    let mut report = LlmReport::empty(
        settings.provider,
        provider::display_url(&settings.url),
        settings.model.clone(),
    );
    report.mode = mode_label(settings.may_downgrade).into();
    report.max_calls = settings.max_calls;
    report.max_tokens = settings.max_tokens;

    let order = eligible(result);
    report.eligible = order.len();
    let flagged_files = reviewer_files(result);
    if order.is_empty() {
        report.manipulation_files = sorted(flagged_files);
        return report;
    }

    // Build every packet first (file reads and masking, no network).
    let masker = Masker::from_corpus();
    let reviewer = ReviewerText::from_corpus();
    let packets: Vec<Packet> = order
        .iter()
        .enumerate()
        .map(|(n, &i)| {
            build_packet(
                &format!("F{}", n + 1),
                i,
                &result.findings[i],
                scan_root,
                settings,
                &masker,
                &reviewer,
            )
        })
        .collect();
    let mut manipulation_files = flagged_files.clone();
    for p in packets.iter().filter(|p| p.reviewer_text) {
        manipulation_files.insert(result.findings[p.finding].file.clone());
    }

    let batch_size = settings.batch_size.max(1);
    let batches: Vec<Batch> = (0..packets.len())
        .collect::<Vec<_>>()
        .chunks(batch_size)
        .map(|chunk| {
            let values: Vec<Value> = chunk.iter().map(|&p| packets[p].value.clone()).collect();
            Batch {
                ids: chunk
                    .iter()
                    .map(|&p| {
                        packets[p].value["id"]
                            .as_str()
                            .unwrap_or_default()
                            .to_string()
                    })
                    .collect(),
                packets: chunk.to_vec(),
                user: prompt::user_message(&values),
            }
        })
        .collect();

    let mut builder = reqwest::Client::builder()
        .timeout(settings.timeout)
        .connect_timeout(settings.timeout.min(Duration::from_secs(10)))
        // A redirect would carry the key and the code to a host nobody
        // configured.
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("sigil/", env!("CARGO_PKG_VERSION")));
    if reqwest::Url::parse(&settings.url).is_ok_and(|u| provider::is_loopback(&u)) {
        // A model served on this machine is reached directly, never through
        // an HTTP(S) proxy from the environment.
        builder = builder.no_proxy();
    }
    let client = match builder.build() {
        Ok(c) => c,
        Err(_) => {
            report.status = "not_run".into();
            report
                .incomplete_reasons
                .push("could not build an HTTP client".into());
            report.not_reviewed = order.len();
            return report;
        }
    };

    let budget = Arc::new(Mutex::new(Budget {
        calls_left: settings.max_calls,
        tokens_left: settings.max_tokens,
        calls: 0,
        input_tokens: 0,
        output_tokens: 0,
    }));
    let sent_bytes = Arc::new(Mutex::new(0usize));
    let sem = Arc::new(tokio::sync::Semaphore::new(settings.concurrency.max(1)));
    let settings_arc = Arc::new(settings.clone());
    let mut set = tokio::task::JoinSet::new();
    let mut outcomes: Vec<Option<BatchOutcome>> = (0..batches.len()).map(|_| None).collect();
    // Batches are admitted in priority order: each waits for a free slot,
    // then reserves its first call from the caps here, before the next one
    // is considered. Under a cap, the highest-severity findings are the ones
    // reviewed, and a finished call's unused reservation is back in the
    // budget before a later batch is admitted.
    for (bi, batch) in batches.iter().enumerate() {
        let Ok(permit) = sem.clone().acquire_owned().await else {
            break;
        };
        let input_reserve = request_size(settings, &batch.user, &batch.ids) + FRAMING_TOKENS;
        let first = match reserve(&budget, settings, input_reserve) {
            Ok(r) => r,
            Err(why) => {
                outcomes[bi] = Some(BatchOutcome::Skipped(why));
                continue;
            }
        };
        let (client, budget, s, sent) = (
            client.clone(),
            budget.clone(),
            settings_arc.clone(),
            sent_bytes.clone(),
        );
        let (user, ids) = (batch.user.clone(), batch.ids.clone());
        set.spawn(async move {
            let _permit = permit;
            let call = BatchCall {
                client: &client,
                s: &s,
                user: &user,
                ids: &ids,
                budget: &budget,
                sent: &sent,
                input_reserve,
            };
            (bi, call.run(first).await)
        });
    }
    while let Some(joined) = set.join_next().await {
        if let Ok((bi, outcome)) = joined {
            outcomes[bi] = Some(outcome);
        }
    }

    {
        let b = budget.lock().unwrap_or_else(|e| e.into_inner());
        report.calls = b.calls;
        report.input_tokens = b.input_tokens;
        report.output_tokens = b.output_tokens;
    }
    report.sent.bytes = *sent_bytes.lock().unwrap_or_else(|e| e.into_inner());

    // Apply, in batch order.
    let mut skipped: HashMap<&'static str, usize> = HashMap::new();
    let mut changed = false;
    let mut served: Vec<String> = Vec::new();
    for (batch, outcome) in batches.iter().zip(outcomes) {
        let sent_any = !matches!(outcome, Some(BatchOutcome::Skipped(_)));
        if sent_any {
            for &p in &batch.packets {
                report.sent.findings += 1;
                report.sent.masked_values += packets[p].masked;
                report.sent.excerpts_withheld += usize::from(packets[p].withheld);
            }
        }
        match outcome {
            Some(BatchOutcome::Reviewed { reviews, model }) => {
                if let Some(m) = &model {
                    if !served.contains(m) {
                        served.push(m.clone());
                    }
                }
                for r in reviews {
                    let Some(pos) = batch.ids.iter().position(|id| *id == r.id) else {
                        continue;
                    };
                    let packet = &packets[batch.packets[pos]];
                    let f = &mut result.findings[packet.finding];
                    let reviewer_file = manipulation_files.contains(&f.file);
                    let mut entry =
                        apply_review(f, &r, reviewer_file, settings.may_downgrade, &mut report);
                    changed |= entry.original_severity.is_some();
                    entry.model = model.clone();
                    report.reviews.push(entry);
                    report.reviewed += 1;
                }
            }
            Some(BatchOutcome::Failed(reason)) => {
                report.not_reviewed += batch.packets.len();
                report.incomplete_reasons.push(format!(
                    "{} finding(s) not reviewed: {reason}",
                    batch.packets.len()
                ));
            }
            Some(BatchOutcome::Skipped(why)) => {
                report.not_reviewed += batch.packets.len();
                *skipped.entry(why).or_insert(0) += batch.packets.len();
            }
            None => {
                report.not_reviewed += batch.packets.len();
                report.incomplete_reasons.push(format!(
                    "{} finding(s) not reviewed: the request task failed",
                    batch.packets.len()
                ));
            }
        }
    }
    let mut skipped: Vec<(&'static str, usize)> = skipped.into_iter().collect();
    skipped.sort();
    for (why, n) in skipped {
        report
            .incomplete_reasons
            .push(format!("{n} finding(s) not reviewed: {why}"));
    }
    report.served_models = served;
    report.manipulation_files = sorted(manipulation_files);
    if report.not_reviewed > 0 {
        report.status = "incomplete".into();
    }
    if changed {
        result.score = crate::scanner::scoring::calculate_score(&result.findings);
        result.verdict = crate::scanner::scoring::determine_verdict_with_size(
            &result.findings,
            result.score,
            result.files_scanned,
        );
    }
    report
}

fn sorted(set: HashSet<String>) -> Vec<String> {
    let mut v: Vec<String> = set.into_iter().collect();
    v.sort();
    v
}

/// Record one review against its finding, downgrading only when every trust
/// rule allows it.
fn apply_review(
    f: &mut Finding,
    r: &ParsedReview,
    reviewer_file: bool,
    may_downgrade: bool,
    report: &mut LlmReport,
) -> ReviewEntry {
    let mut entry = ReviewEntry {
        rule: f.rule.clone(),
        file: f.file.clone(),
        line: f.line,
        fingerprint: f.fingerprint.clone(),
        verdict: r.verdict.clone(),
        rationale: r.rationale.clone(),
        action: "none".into(),
        not_applied_reason: None,
        severity: f.severity.to_string(),
        original_severity: None,
        manipulation_suspected: reviewer_file,
        model: None,
        key: finding_key(f),
    };
    match r.verdict.as_str() {
        "confirm" => report.confirmed += 1,
        "escalate" => {
            report.escalated += 1;
            entry.action = "note".into();
        }
        _ => {
            report.dismissed += 1;
            let blocked = if !may_downgrade {
                Some("advisory mode (llm_may_downgrade is off)")
            } else {
                protected_reason(f, reviewer_file)
            };
            match blocked {
                Some(why) => {
                    entry.action = "not_applied".into();
                    entry.not_applied_reason = Some(why.to_string());
                }
                None => {
                    let original = f.severity;
                    f.severity = one_level_down(original);
                    entry.action = "downgraded".into();
                    entry.original_severity = Some(original.to_string());
                    entry.severity = f.severity.to_string();
                    report.downgraded += 1;
                }
            }
        }
    }
    entry
}

/// The request body for a batch, and whether it needs the fallback beta.
fn request_body(s: &LlmSettings, user: &str, ids: &[String], max_out: u64) -> (Value, bool) {
    match s.provider {
        Provider::Anthropic => provider::anthropic_body(&s.model, user, ids, max_out),
        Provider::OpenAiCompatible => (provider::openai_body(&s.model, user, max_out), false),
    }
}

/// Size in bytes of a batch's request with the largest reply limit: an upper
/// bound on its input tokens, since a token covers at least one byte.
fn request_size(s: &LlmSettings, user: &str, ids: &[String]) -> u64 {
    serde_json::to_vec(&request_body(s, user, ids, s.max_output_tokens).0)
        .map(|b| b.len())
        .unwrap_or(0) as u64
}

/// One call's share of the caps, taken before the call is made.
struct Reservation {
    max_out: u64,
    reserved: u64,
}

/// Take one call and `input_reserve` plus a reply limit from the caps, or
/// say which cap stops it. The reply limit shrinks to what is left, but not
/// below [`MIN_OUTPUT_TOKENS`].
fn reserve(
    budget: &Mutex<Budget>,
    s: &LlmSettings,
    input_reserve: u64,
) -> Result<Reservation, &'static str> {
    let mut b = budget.lock().unwrap_or_else(|e| e.into_inner());
    if b.calls_left == 0 {
        return Err("call cap (llm_max_calls) reached");
    }
    if b.tokens_left < input_reserve + MIN_OUTPUT_TOKENS {
        return Err("token cap (llm_max_tokens) reached");
    }
    let max_out = s.max_output_tokens.min(b.tokens_left - input_reserve);
    b.calls_left -= 1;
    b.calls += 1;
    b.tokens_left -= input_reserve + max_out;
    Ok(Reservation {
        max_out,
        reserved: input_reserve + max_out,
    })
}

/// One batch's request, with what it shares with the others.
struct BatchCall<'a> {
    client: &'a reqwest::Client,
    s: &'a LlmSettings,
    user: &'a str,
    ids: &'a [String],
    budget: &'a Mutex<Budget>,
    sent: &'a Mutex<usize>,
    input_reserve: u64,
}

impl BatchCall<'_> {
    /// Send the batch on `first`, retrying once on a rate limit, overload or
    /// server error when the caps still allow another call.
    async fn run(&self, first: Reservation) -> BatchOutcome {
        let mut res = first;
        let mut attempt = 0;
        loop {
            let (body, fallback) = request_body(self.s, self.user, self.ids, res.max_out);
            if let Ok(bytes) = serde_json::to_vec(&body) {
                *self.sent.lock().unwrap_or_else(|e| e.into_inner()) += bytes.len();
            }
            let endpoint = provider::Endpoint {
                provider: self.s.provider,
                url: &self.s.url,
                api_key: self.s.api_key.as_ref().map(ApiKey::expose),
            };
            let outcome =
                provider::send(self.client, &endpoint, &body, fallback, self.s.timeout).await;
            self.settle(&res, &outcome);
            let error = match outcome.text {
                Ok(text) => {
                    return match prompt::parse_reviews(&text, self.ids) {
                        Ok(reviews) => BatchOutcome::Reviewed {
                            reviews,
                            model: outcome.served_model,
                        },
                        Err(e) => BatchOutcome::Failed(e),
                    }
                }
                Err(e) => e,
            };
            if !outcome.retryable || attempt == 1 {
                return BatchOutcome::Failed(error);
            }
            let wait = outcome
                .retry_after
                .unwrap_or(Duration::from_secs(2))
                .min(MAX_RETRY_WAIT);
            tokio::time::sleep(wait).await;
            res = match reserve(self.budget, self.s, self.input_reserve) {
                Ok(r) => r,
                Err(why) => return BatchOutcome::Failed(format!("{error}; not retried: {why}")),
            };
            attempt += 1;
        }
    }

    /// Replace a call's reservation with what it used: the provider's
    /// reported usage, nothing for an error response (not billed), and the
    /// whole reservation when usage is unknown (a timeout, a server that
    /// reports none).
    fn settle(&self, res: &Reservation, outcome: &provider::CallOutcome) {
        let mut b = self.budget.lock().unwrap_or_else(|e| e.into_inner());
        let used = match (outcome.input_tokens, outcome.output_tokens) {
            (Some(i), Some(o)) => {
                b.input_tokens += i;
                b.output_tokens += o;
                i + o
            }
            _ if outcome.text.is_err() && outcome.status.is_some_and(|s| s >= 400) => 0,
            _ => res.reserved,
        };
        if used < res.reserved {
            b.tokens_left += res.reserved - used;
        } else {
            b.tokens_left = b.tokens_left.saturating_sub(used - res.reserved);
        }
    }
}
