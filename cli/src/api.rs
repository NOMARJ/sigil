use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::fs;
use std::path::PathBuf;

use crate::scanner::cloud_sigs::{self, SignatureResponse as CloudSigResponse};
use crate::scanner::{Phase, ScanResult};

const DEFAULT_ENDPOINT: &str = "https://api.sigilsec.ai";

/// The `target` that `sigil scan --submit` and `--enhanced` send.
///
/// The API requires one. A fixed label is sent instead of the scanned path:
/// a path, or even its last component, can carry a user or project name, and
/// `docs/data-handling.md` does not list the path among what is sent. The API
/// records the same label for a CLI 1.3.7 submission, which has no target.
pub const CLI_SCAN_TARGET: &str = "cli-scan";

/// API client for the Sigil cloud service.
pub struct SigilClient {
    endpoint: String,
    client: reqwest::Client,
    token: Option<String>,
}

/// Response from `POST /v1/scan` and `POST /v1/scan-enhanced`: the API's
/// `ScanResponse`. Only the fields the CLI reads are modelled, and every one
/// is optional so an older or newer API still parses.
#[derive(Debug, Default, Deserialize)]
pub struct ScanResponse {
    #[serde(default)]
    pub scan_id: Option<String>,
    /// Alias of `scan_id` the API adds for CLI 1.3.7. Kept as its own field:
    /// a serde alias would reject a body that carries both keys.
    #[serde(default)]
    pub id: Option<String>,
    /// Every finding the API holds for the scan; `--enhanced` adds its LLM
    /// findings (phase `llm_analysis`) to the submitted ones.
    #[serde(default)]
    pub findings: Vec<Value>,
    /// Endpoint notes: `/v1/scan-enhanced` says here whether LLM analysis ran.
    #[serde(default)]
    pub metadata: Map<String, Value>,
}

impl ScanResponse {
    /// The scan's id, whichever key carried it.
    pub fn scan_id(&self) -> Option<&str> {
        self.scan_id
            .as_deref()
            .or(self.id.as_deref())
            .filter(|id| !id.is_empty())
    }
}

/// What `/v1/scan-enhanced` did with the uploaded files, read from the
/// response metadata. Only an explicit `llm_analysis_performed: true` counts
/// as analysis: the endpoint answers 200 with the static result whenever the
/// LLM step does not run.
#[derive(Debug, PartialEq)]
pub enum EnhancedOutcome {
    /// LLM analysis ran; these are the findings it added.
    Analysed { llm_findings: Vec<Value> },
    /// The account's plan does not include LLM analysis.
    UpgradeRequired,
    /// LLM analysis did not run, for the reason given.
    NotRun(String),
}

impl EnhancedOutcome {
    pub fn from_response(response: &ScanResponse) -> Self {
        let m = &response.metadata;
        let flag = |key: &str| m.get(key).and_then(Value::as_bool) == Some(true);
        if flag("llm_analysis_performed") {
            let llm_findings = response
                .findings
                .iter()
                .filter(|f| f.get("phase").and_then(Value::as_str) == Some("llm_analysis"))
                .cloned()
                .collect();
            return EnhancedOutcome::Analysed { llm_findings };
        }
        if flag("upgrade_required") {
            return EnhancedOutcome::UpgradeRequired;
        }
        let reason = ["llm_error", "reason"]
            .iter()
            .find_map(|k| m.get(*k).and_then(Value::as_str))
            .map(|r| format!("server reported: {}", terminal_text(r)))
            .unwrap_or_else(|| "the response does not say it ran".to_string());
        EnhancedOutcome::NotRun(reason)
    }
}

/// Response from `GET /v1/threat/{hash}`: the API's threat entry. The API
/// answers 404 for an unknown hash, so a body that names an entry is a match;
/// the API adds `known_malicious` and `references` for CLI 1.3.7, and an API
/// without them still parses. A 2xx body that names no entry (`{}` from a
/// proxy or captive portal) is not a match and not a "no match" either: see
/// [`parse_threat_info`], which sets `known_malicious` and `unrecognised`.
#[derive(Debug, Serialize, Deserialize)]
pub struct ThreatInfo {
    #[serde(default)]
    pub hash: String,
    #[serde(default)]
    pub known_malicious: bool,
    #[serde(default)]
    pub package_name: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub confirmed_at: Option<String>,
    #[serde(default)]
    pub threat_type: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub references: Vec<String>,
    /// Set by [`parse_threat_info`] for a 2xx body that neither names an
    /// entry nor says `known_malicious` either way: not an answer the Sigil
    /// API gives (it answers 404 for an unknown hash), so it is neither a
    /// match nor a "no match".
    #[serde(skip)]
    pub unrecognised: bool,
}

impl ThreatInfo {
    fn no_match(hash: &str) -> Self {
        ThreatInfo {
            hash: hash.to_string(),
            known_malicious: false,
            package_name: None,
            version: None,
            severity: None,
            source: None,
            confirmed_at: None,
            threat_type: None,
            description: None,
            references: vec![],
            unrecognised: false,
        }
    }
}

/// A threat detection signature from the cloud.
#[derive(Debug, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct Signature {
    pub id: String,
    pub pattern: String,
    pub phase: String,
    pub severity: String,
    pub description: String,
}

/// Response from `POST /v1/report`: the API's `ThreatReportResponse`.
#[derive(Debug, Default, Deserialize)]
pub struct ReportResponse {
    #[serde(default)]
    pub report_id: Option<String>,
    /// Alias of `report_id` the API adds for CLI 1.3.7 (see `ScanResponse::id`).
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
}

impl ReportResponse {
    pub fn report_id(&self) -> Option<&str> {
        self.report_id
            .as_deref()
            .or(self.id.as_deref())
            .filter(|id| !id.is_empty())
    }
}

// ---------------------------------------------------------------------------
// Request bodies (the API's pydantic models: api/models.py)
// ---------------------------------------------------------------------------

/// The API's `ScanPhase` value for a phase name in any spelling the CLI
/// writes: serde `InstallHooks` (scan JSON), `install_hooks`, and so on.
pub fn api_phase(name: &str) -> String {
    if let Some(phase) = Phase::from_name(name) {
        return phase.canonical_name().to_string();
    }
    let key: String = name
        .chars()
        .filter(|c| !matches!(c, '_' | '-' | ' '))
        .flat_map(char::to_lowercase)
        .collect();
    if key == "llmanalysis" {
        "llm_analysis".to_string()
    } else {
        name.to_lowercase()
    }
}

/// Normalise one CLI finding to the API's `Finding` schema: phase in
/// `snake_case`, severity upper-case. Other keys pass through untouched; the
/// API ignores the ones it does not model.
pub fn api_finding(finding: &Value) -> Value {
    let mut out = finding.clone();
    if let Some(obj) = out.as_object_mut() {
        if let Some(phase) = obj.get("phase").and_then(Value::as_str) {
            let normalized = api_phase(phase);
            obj.insert("phase".into(), Value::String(normalized));
        }
        if let Some(sev) = obj.get("severity").and_then(Value::as_str) {
            let upper = sev.to_uppercase();
            obj.insert("severity".into(), Value::String(upper));
        }
    }
    out
}

/// Body of `POST /v1/scan` and `POST /v1/scan-enhanced` (the API's
/// `ScanRequest`): the fixed [`CLI_SCAN_TARGET`], the number of files
/// scanned, every active finding (snippet included) and `metadata` holding
/// the CLI's own score and verdict plus `extra_metadata`. Suppressed findings
/// are not sent.
pub fn scan_request_body(
    result: &ScanResult,
    source: &str,
    extra_metadata: Map<String, Value>,
) -> Result<Value, String> {
    let findings = result
        .findings
        .iter()
        .map(|f| serde_json::to_value(f).map(|v| api_finding(&v)))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("failed to serialize findings: {}", e))?;
    let mut metadata = Map::new();
    metadata.insert("source".into(), json!(source));
    metadata.insert("cli_score".into(), json!(result.score));
    metadata.insert(
        "cli_verdict".into(),
        json!(result.verdict.to_string().replace(' ', "_")),
    );
    metadata.extend(extra_metadata);
    Ok(json!({
        "target": CLI_SCAN_TARGET,
        "target_type": "directory",
        "files_scanned": result.files_scanned,
        "findings": findings,
        "metadata": metadata,
    }))
}

/// The digest `sigil report` files: a SHA-256 hash of 64 hexadecimal
/// characters in any case, trimmed and lower-cased. The API refuses anything
/// else, so it is checked before anything is sent.
pub fn report_digest(hash: &str) -> Result<String, String> {
    let digest = hash.trim().to_ascii_lowercase();
    let length = digest.chars().count();
    if length != 64 {
        // The input is never echoed: it may hold terminal escapes.
        return Err(format!(
            "the hash must be a SHA-256 digest: 64 hexadecimal characters (0-9, a-f); \
             got {length} characters"
        ));
    }
    if !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(
            "the hash must be a SHA-256 digest: 64 hexadecimal characters \
             (0-9, a-f); it is 64 characters long but contains characters outside 0-9, a-f"
                .to_string(),
        );
    }
    Ok(digest)
}

/// Body of `POST /v1/report` (the API's `ThreatReport`). The API identifies a
/// report by package, so a hash report is filed as package `sha256:<hash>`
/// with the description as the reason and the threat type and hash as
/// evidence: the same record the API makes of CLI 1.3.7's
/// `{hash, threat_type, description}` body.
pub fn report_request_body(hash: &str, threat_type: &str, description: &str) -> Value {
    let digest = hash.trim().to_lowercase();
    let mut evidence = Vec::new();
    if !threat_type.trim().is_empty() {
        evidence.push(format!("Threat type: {}", threat_type.trim()));
    }
    evidence.push(format!("SHA-256: {}", digest));
    json!({
        "package_name": format!("sha256:{}", digest),
        "reason": description,
        "evidence": evidence.join("\n"),
    })
}

/// Whether `c` is a format (Unicode category Cf) or line or paragraph
/// separator (Zl, Zp) character. None of these draws anything, and several
/// change how the text around them is drawn: the bidirectional overrides and
/// isolates (U+202A to U+202E, U+2066 to U+2069) reorder what follows, the
/// zero-width and joining characters hide text, and U+2028 and U+2029 start
/// a new line in some terminals and log viewers.
///
/// The standard library has no general-category lookup, so these are the Cf
/// code points of Unicode 15.1 (as listed by Python 3.13's `unicodedata`) and
/// the two separators, written out. A character added to Cf later passes
/// through until it is listed here.
fn is_format_or_separator(c: char) -> bool {
    matches!(u32::from(c),
        0x00AD
        | 0x0600..=0x0605
        | 0x061C
        | 0x06DD
        | 0x070F
        | 0x0890..=0x0891
        | 0x08E2
        | 0x180E
        | 0x200B..=0x200F
        | 0x2028..=0x202E
        | 0x2060..=0x2064
        | 0x2066..=0x206F
        | 0xFEFF
        | 0xFFF9..=0xFFFB
        | 0x110BD
        | 0x110CD
        | 0x13430..=0x1343F
        | 0x1BCA0..=0x1BCA3
        | 0x1D173..=0x1D17A
        | 0xE0001
        | 0xE0020..=0xE007F
    )
}

/// Text from an API response, made safe to print: control characters
/// (terminal escapes included), format characters (bidirectional overrides
/// and zero-width characters included) and line or paragraph separators
/// become spaces. A threat entry's description can come from a community
/// report, and none of it is ours to emit raw.
pub fn terminal_text(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_control() || is_format_or_separator(c) {
                ' '
            } else {
                c
            }
        })
        .collect()
}

/// The start of an API response body as one printable line: control
/// characters removed ([`terminal_text`]), cut to 600 characters.
pub fn error_excerpt(body: &str) -> String {
    let body = terminal_text(body.trim());
    let mut excerpt: String = body.chars().take(600).collect();
    if excerpt.len() < body.len() {
        excerpt.push('…');
    }
    excerpt
}

/// An API error as one line: the status, a hint for the statuses with a
/// known cause, and the start of the body.
fn api_error(status: reqwest::StatusCode, body: &str, forbidden_hint: &str) -> String {
    let hint = match status.as_u16() {
        401 => " (not signed in, or the token expired: run `sigil login`)",
        402 => " (this needs a paid plan)",
        403 if !forbidden_hint.is_empty() => forbidden_hint,
        429 => " (rate limit or monthly scan quota reached)",
        _ => "",
    };
    let excerpt = error_excerpt(body);
    if excerpt.is_empty() {
        format!("API error: {}{}", status, hint)
    } else {
        format!("API error: {}{}: {}", status, hint, excerpt)
    }
}

/// Authentication response.
#[derive(Debug, Serialize, Deserialize)]
struct AuthResponse {
    pub token: String,
    pub expires_at: Option<String>,
}

/// Response from POST /v1/auth/device/code.
#[derive(Debug, Deserialize)]
struct DeviceCodeResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    #[serde(default)]
    verification_uri_complete: String,
    #[serde(default = "default_interval")]
    interval: u64,
}

fn default_interval() -> u64 {
    5
}

/// Success body from POST /v1/auth/device/token.
#[derive(Debug, Deserialize)]
struct DeviceTokenResponse {
    access_token: String,
}

// ---------------------------------------------------------------------------
// Token storage
// ---------------------------------------------------------------------------

/// Path to the stored API token: ~/.sigil/token
fn token_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".sigil")
        .join("token")
}

/// Load a stored API token from disk.
pub(crate) fn load_token() -> Option<String> {
    fs::read_to_string(token_path())
        .ok()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
}

/// Save an API token to disk.
fn save_token(token: &str) -> Result<(), String> {
    let path = token_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create config directory: {}", e))?;
    }
    fs::write(&path, token).map_err(|e| format!("failed to save token: {}", e))?;

    // Restrict permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Client implementation
// ---------------------------------------------------------------------------

impl SigilClient {
    /// Create a new API client. If no endpoint is provided, uses the default.
    /// Automatically loads a stored token if one exists.
    pub fn new(endpoint: Option<String>) -> Self {
        let endpoint = endpoint.unwrap_or_else(|| DEFAULT_ENDPOINT.to_string());
        let token = load_token();
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent(format!("sigil-cli/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .unwrap_or_default();

        SigilClient {
            endpoint,
            client,
            token,
        }
    }

    /// Submit a scan result to the Sigil cloud.
    ///
    /// POST /v1/scan
    pub async fn submit_scan(&self, result: &ScanResult) -> Result<ScanResponse, String> {
        let url = format!("{}/v1/scan", self.endpoint);
        let body = scan_request_body(result, "sigil-scan", Map::new())?;

        let mut request = self.client.post(&url).json(&body);
        if let Some(ref token) = self.token {
            request = request.bearer_auth(token);
        }

        let response = request
            .send()
            .await
            .map_err(|e| offline_fallback_message(&e))?;

        let status = response.status();
        if !status.is_success() {
            let text = response.text().await.unwrap_or_default();
            return Err(api_error(status, &text, ""));
        }

        response
            .json::<ScanResponse>()
            .await
            .map_err(|e| format!("failed to parse response: {}", e))
    }

    /// Look up a hash in the threat intelligence database.
    ///
    /// GET /v1/threat/{hash}. A 404 is "no match", not an error.
    pub async fn lookup_threat(&self, hash: &str) -> Result<ThreatInfo, String> {
        let url = format!("{}/v1/threat/{}", self.endpoint, hash);

        let mut request = self.client.get(&url);
        if let Some(ref token) = self.token {
            request = request.bearer_auth(token);
        }

        let response = request
            .send()
            .await
            .map_err(|e| offline_fallback_message(&e))?;

        let status = response.status();
        if status.as_u16() == 404 {
            return Ok(ThreatInfo::no_match(hash));
        }

        if !status.is_success() {
            let text = response.text().await.unwrap_or_default();
            return Err(api_error(
                status,
                &text,
                " (the threat database needs a Pro plan)",
            ));
        }

        let text = response
            .text()
            .await
            .map_err(|e| format!("failed to read response: {}", e))?;
        parse_threat_info(&text, hash)
    }

    /// Fetch the latest threat detection signatures.
    ///
    /// GET /v1/signatures
    ///
    /// Supports delta sync: if `force` is false and we have a previous
    /// sync timestamp, only signatures updated after that time are fetched
    /// and merged with the local set.
    ///
    /// Returns the total number of local signatures after the update.
    pub async fn get_signatures(&self, force: bool) -> Result<usize, String> {
        let mut url = format!("{}/v1/signatures", self.endpoint);

        // Delta sync: append ?since= if we have a previous sync timestamp
        if !force {
            if let Some(since) = cloud_sigs::get_last_sync_time() {
                url = format!("{}?since={}", url, since);
            }
        }

        let mut request = self.client.get(&url);
        if let Some(ref token) = self.token {
            request = request.bearer_auth(token);
        }

        let response = request
            .send()
            .await
            .map_err(|e| offline_fallback_message(&e))?;

        if !response.status().is_success() {
            return Err(format!("API error: {}", response.status()));
        }

        let body = response
            .text()
            .await
            .map_err(|e| format!("failed to read response: {}", e))?;

        // Parse the wrapped response format: {signatures: [...], total, last_updated}
        let sig_response: CloudSigResponse = serde_json::from_str(&body)
            .map_err(|e| format!("failed to parse signatures response: {}", e))?;

        let fetched = sig_response.signatures;
        let last_updated = sig_response.last_updated.unwrap_or_default();

        // Merge with existing local signatures (for delta sync)
        let mut all_sigs = if force {
            vec![]
        } else {
            cloud_sigs::load_cloud_signatures()
        };

        // Upsert fetched signatures by ID
        for new_sig in &fetched {
            if let Some(pos) = all_sigs.iter().position(|s| s.id == new_sig.id) {
                all_sigs[pos] = new_sig.clone();
            } else {
                all_sigs.push(new_sig.clone());
            }
        }

        // Write merged set to disk
        let sigs_path = cloud_sigs::signatures_path();
        if let Some(parent) = sigs_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        // Store in the wrapped format so load_cloud_signatures can read it back
        let wrapped = serde_json::json!({
            "signatures": all_sigs,
            "total": all_sigs.len(),
            "last_updated": &last_updated,
        });
        let json = serde_json::to_string_pretty(&wrapped)
            .map_err(|e| format!("failed to serialize signatures: {}", e))?;
        fs::write(&sigs_path, json).map_err(|e| format!("failed to write signatures: {}", e))?;

        // Save sync metadata for next delta sync
        if !last_updated.is_empty() {
            cloud_sigs::save_sync_meta(&last_updated);
        }

        Ok(all_sigs.len())
    }

    /// Report a new threat to the Sigil cloud.
    ///
    /// POST /v1/report. A `hash` that is not a SHA-256 digest is refused
    /// before anything is sent (see [`report_digest`]).
    pub async fn report_threat(
        &self,
        hash: &str,
        threat_type: &str,
        description: &str,
    ) -> Result<ReportResponse, String> {
        let url = format!("{}/v1/report", self.endpoint);
        let digest = report_digest(hash)?;
        let body = report_request_body(&digest, threat_type, description);

        let mut request = self.client.post(&url).json(&body);
        if let Some(ref token) = self.token {
            request = request.bearer_auth(token);
        }

        let response = request
            .send()
            .await
            .map_err(|e| offline_fallback_message(&e))?;

        let status = response.status();
        if !status.is_success() {
            let text = response.text().await.unwrap_or_default();
            return Err(api_error(status, &text, ""));
        }

        response
            .json::<ReportResponse>()
            .await
            .map_err(|e| format!("failed to parse response: {}", e))
    }

    /// Authenticate with a pre-existing API token.
    /// Validates the token against the server, then stores it locally.
    pub async fn login_with_token(&self, token: &str) -> Result<(), String> {
        // Validate token by calling a simple authenticated endpoint
        let url = format!("{}/v1/auth/verify", self.endpoint);

        let response = self
            .client
            .get(&url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| offline_fallback_message(&e))?;

        if !response.status().is_success() {
            return Err(format!(
                "invalid token (server returned {})",
                response.status()
            ));
        }

        save_token(token)?;
        Ok(())
    }

    /// Check whether the client has a stored authentication token.
    pub fn is_authenticated(&self) -> bool {
        self.token.is_some()
    }

    /// Submit an enhanced scan with LLM analysis (Pro feature).
    ///
    /// POST /v1/scan-enhanced
    pub async fn submit_enhanced_scan(
        &self,
        result: &ScanResult,
        file_contents: std::collections::HashMap<String, String>,
    ) -> Result<ScanResponse, String> {
        let url = format!("{}/v1/scan-enhanced", self.endpoint);

        // The scan request, with the collected file contents for LLM analysis.
        let mut extra = Map::new();
        extra.insert(
            "file_contents".to_string(),
            serde_json::to_value(&file_contents)
                .map_err(|e| format!("failed to serialize file contents: {}", e))?,
        );
        let request_body = scan_request_body(result, "sigil-scan-enhanced", extra)?;

        let mut request = self.client.post(&url).json(&request_body);
        if let Some(ref token) = self.token {
            request = request.bearer_auth(token);
        } else {
            return Err(
                "Authentication required for enhanced scanning. Run: sigil login".to_string(),
            );
        }

        let response = request
            .send()
            .await
            .map_err(|e| offline_fallback_message(&e))?;

        let status = response.status();
        if status.as_u16() == 402 {
            return Err(
                "Pro subscription required for LLM analysis. Upgrade at https://app.sigilsec.ai/upgrade"
                    .to_string(),
            );
        }

        if !status.is_success() {
            let text = response.text().await.unwrap_or_default();
            return Err(api_error(status, &text, ""));
        }

        response
            .json::<ScanResponse>()
            .await
            .map_err(|e| format!("failed to parse response: {}", e))
    }

    /// Authenticate via the OAuth 2.0 device authorization flow.
    ///
    /// Requests a device code, shows the user the verification URL + code,
    /// then polls until they complete sign-in in the browser. Saves the
    /// resulting access token. This replaces the removed password login.
    pub async fn login_device_flow(&self) -> Result<(), String> {
        use colored::Colorize;

        // 1. Request a device code.
        let code: DeviceCodeResponse = self
            .client
            .post(format!("{}/v1/auth/device/code", self.endpoint))
            .json(&serde_json::json!({}))
            .send()
            .await
            .map_err(|e| offline_fallback_message(&e))?
            .error_for_status()
            .map_err(|e| match e.status() {
                Some(s) if s.as_u16() == 503 => {
                    "device flow unavailable (server returned 503 — Auth0 not configured)"
                        .to_string()
                }
                Some(s) => format!("could not start device flow (server returned {})", s),
                None => format!("could not start device flow: {}", e),
            })?
            .json()
            .await
            .map_err(|e| format!("failed to parse device code response: {}", e))?;

        // 2. Prompt the user.
        let url = if code.verification_uri_complete.is_empty() {
            code.verification_uri.clone()
        } else {
            code.verification_uri_complete.clone()
        };
        println!(
            "\n{} open this URL to sign in:\n    {}\n  and confirm the code: {}\n",
            "sigil:".bold().cyan(),
            url.bold().underline(),
            code.user_code.bold().yellow()
        );
        println!(
            "{} waiting for you to finish in the browser…",
            "sigil:".dimmed()
        );

        // 3. Poll for the token.
        let token_url = format!(
            "{}/v1/auth/device/token?device_code={}",
            self.endpoint, code.device_code
        );
        let mut interval = code.interval.max(1);
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(interval)).await;

            let resp = self
                .client
                .post(&token_url)
                .send()
                .await
                .map_err(|e| offline_fallback_message(&e))?;

            let status = resp.status();
            if status.is_success() {
                let body: DeviceTokenResponse = resp
                    .json()
                    .await
                    .map_err(|e| format!("failed to parse token response: {}", e))?;
                save_token(&body.access_token)?;
                return Ok(());
            }

            // 400 carries an OAuth error in {"detail": {"error": ...}}.
            let body: serde_json::Value = resp.json().await.unwrap_or_default();
            let err = body
                .get("detail")
                .and_then(|d| d.get("error"))
                .and_then(|e| e.as_str())
                .unwrap_or("unknown_error");
            match err {
                "authorization_pending" => continue,
                "slow_down" => {
                    interval += 5;
                    continue;
                }
                "expired_token" => {
                    return Err("the sign-in code expired — run `sigil login` again".to_string())
                }
                "access_denied" => return Err("sign-in was denied".to_string()),
                other => return Err(format!("device flow failed: {}", other)),
            }
        }
    }

    /// Register a new account and receive a token.
    #[allow(dead_code)]
    pub async fn register(&self, email: &str) -> Result<String, String> {
        let url = format!("{}/v1/auth/register", self.endpoint);

        let body = serde_json::json!({ "email": email });

        let response = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| offline_fallback_message(&e))?;

        if !response.status().is_success() {
            return Err(format!("registration failed: {}", response.status()));
        }

        let auth: AuthResponse = response
            .json()
            .await
            .map_err(|e| format!("failed to parse auth response: {}", e))?;

        save_token(&auth.token)?;
        Ok(auth.token)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse a `GET /v1/threat/{hash}` success body. `hash` fills in a body
/// that omits it.
///
/// The API answers 404 for an unknown hash and always names the entry it
/// matched, so a body is a match when it says `known_malicious: true` or
/// carries a `hash` or a `package_name`. `known_malicious: false` is no match
/// whatever else the body holds. A body that does neither (`{}`, or an error
/// object) is no match and is marked `unrecognised`: the Sigil API answers 404
/// for an unknown hash, so a proxy or portal answered. The caller says so
/// instead of reporting a lookup result.
pub fn parse_threat_info(body: &str, hash: &str) -> Result<ThreatInfo, String> {
    let parse_error = |e: serde_json::Error| format!("failed to parse response: {}", e);
    let value: Value = serde_json::from_str(body).map_err(parse_error)?;
    // serde would also read a JSON array positionally into the struct.
    if !value.is_object() {
        return Err("failed to parse response: expected a JSON object".to_string());
    }
    let explicit = value.get("known_malicious").and_then(Value::as_bool);
    let mut info: ThreatInfo = serde_json::from_value(value).map_err(parse_error)?;
    let names_an_entry = !info.hash.trim().is_empty()
        || info
            .package_name
            .as_deref()
            .is_some_and(|name| !name.trim().is_empty());
    info.known_malicious = explicit.unwrap_or(names_an_entry);
    info.unrecognised = explicit.is_none() && !names_an_entry;
    if info.hash.is_empty() {
        info.hash = hash.to_string();
    }
    Ok(info)
}

/// Produce a user-friendly error message when the API is unreachable.
fn offline_fallback_message(err: &reqwest::Error) -> String {
    if err.is_connect() || err.is_timeout() {
        "Sigil cloud is unreachable (running in offline mode). \
         Local scanning will continue to work, but threat intelligence \
         and signature updates are unavailable."
            .to_string()
    } else {
        format!("network error: {}", err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    /// A scan result as the scanner produces it, with one finding per shape
    /// that matters to the API: a Phase 10 finding (absent from the API's
    /// enum before), a finding with no line, and suppressed findings that
    /// must not be sent.
    fn sample_result() -> ScanResult {
        let finding = |phase: &str, rule: &str, severity: &str, line: Value| {
            json!({"phase": phase, "rule": rule, "severity": severity, "file": "src/a.py",
                   "line": line, "snippet": "x", "weight": 5, "fingerprint": "f"})
        };
        serde_json::from_value(json!({
            "findings": [
                finding("InstallHooks", "INSTALL-001", "Critical", json!(3)),
                finding("InferenceSecurity", "INFER-001", "High", json!(2)),
                finding("Provenance", "PROV-001", "Low", Value::Null),
            ],
            "score": 42,
            "verdict": "HighRisk",
            "files_scanned": 7,
            "duration_ms": 12,
            "suppressed_findings": [finding("CodePatterns", "CODE-001", "High", json!(1))],
            "suppressed_by": "ledger:example",
            "inline_suppressed": [finding("Credentials", "CRED-001", "Medium", json!(4))],
            "inline_suppressions": ["src/a.py:4 CRED-001 — test"],
            "platform": "pypi",
        }))
        .expect("sample ScanResult")
    }

    #[test]
    fn api_phase_maps_every_cli_spelling_to_the_api_value() {
        for phase in Phase::ALL {
            let serde_name = serde_json::to_value(phase).unwrap();
            let serde_name = serde_name.as_str().unwrap();
            assert_eq!(
                api_phase(serde_name),
                phase.canonical_name(),
                "{serde_name}"
            );
            assert_eq!(api_phase(phase.canonical_name()), phase.canonical_name());
        }
        // `sigil explain` 1.3.7 sent the concatenated form.
        assert_eq!(api_phase("inferencesecurity"), "inference_security");
        assert_eq!(api_phase("LlmAnalysis"), "llm_analysis");
        // An unknown name is passed on (lower-cased) for the API to refuse.
        assert_eq!(api_phase("Mystery"), "mystery");
    }

    #[test]
    fn scan_request_body_has_the_api_scan_request_shape() {
        let body = scan_request_body(&sample_result(), "sigil-scan", Map::new()).unwrap();
        let keys: Vec<&str> = body
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            [
                "files_scanned",
                "findings",
                "metadata",
                "target",
                "target_type"
            ]
        );
        assert_eq!(body["target"], CLI_SCAN_TARGET);
        assert_eq!(body["target_type"], "directory");
        assert_eq!(body["files_scanned"], 7);
        assert_eq!(
            body["metadata"],
            json!({"source": "sigil-scan", "cli_score": 42, "cli_verdict": "HIGH_RISK"})
        );

        // Active findings only, in the API's enum spellings.
        let findings = body["findings"].as_array().unwrap();
        let summary: Vec<(String, String, String)> = findings
            .iter()
            .map(|f| {
                (
                    f["rule"].as_str().unwrap().to_string(),
                    f["phase"].as_str().unwrap().to_string(),
                    f["severity"].as_str().unwrap().to_string(),
                )
            })
            .collect();
        assert_eq!(
            summary,
            [
                (
                    "INSTALL-001".into(),
                    "install_hooks".into(),
                    "CRITICAL".into()
                ),
                (
                    "INFER-001".into(),
                    "inference_security".into(),
                    "HIGH".into()
                ),
                ("PROV-001".into(), "provenance".into(), "LOW".into()),
            ]
        );
        assert!(findings[2]["line"].is_null());
        assert_eq!(findings[0]["snippet"], "x");
    }

    #[test]
    fn enhanced_body_adds_file_contents_to_the_same_request() {
        let mut extra = Map::new();
        extra.insert("file_contents".into(), json!({"src/a.py": "print(1)"}));
        let body = scan_request_body(&sample_result(), "sigil-scan-enhanced", extra).unwrap();
        assert_eq!(body["target"], CLI_SCAN_TARGET);
        assert_eq!(body["metadata"]["source"], "sigil-scan-enhanced");
        assert_eq!(body["metadata"]["file_contents"]["src/a.py"], "print(1)");
        assert_eq!(body["findings"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn report_body_has_the_api_threat_report_shape() {
        let body = report_request_body("  ABCDEF01 ", "malware", "steals tokens");
        assert_eq!(
            body,
            json!({
                "package_name": "sha256:abcdef01",
                "reason": "steals tokens",
                "evidence": "Threat type: malware\nSHA-256: abcdef01",
            })
        );
        let body = report_request_body("ab", " ", "d");
        assert_eq!(body["evidence"], "SHA-256: ab");
    }

    #[test]
    fn scan_response_reads_the_id_from_either_key() {
        let both: ScanResponse =
            serde_json::from_str(r#"{"scan_id":"s-1","id":"s-1","status":"completed"}"#).unwrap();
        assert_eq!(both.scan_id(), Some("s-1"));
        let scan_id_only: ScanResponse = serde_json::from_str(r#"{"scan_id":"s-2"}"#).unwrap();
        assert_eq!(scan_id_only.scan_id(), Some("s-2"));
        let id_only: ScanResponse = serde_json::from_str(r#"{"id":"s-3"}"#).unwrap();
        assert_eq!(id_only.scan_id(), Some("s-3"));
        let neither: ScanResponse = serde_json::from_str("{}").unwrap();
        assert_eq!(neither.scan_id(), None);
    }

    #[test]
    fn enhanced_outcome_claims_analysis_only_when_the_api_says_so() {
        let parse = |s: &str| EnhancedOutcome::from_response(&serde_json::from_str(s).unwrap());
        assert_eq!(
            parse(
                r#"{"scan_id":"s","findings":[{"phase":"llm_analysis","rule":"LLM-1"},
                    {"phase":"code_patterns","rule":"CODE-1"}],
                    "metadata":{"llm_analysis_performed":true}}"#
            ),
            EnhancedOutcome::Analysed {
                llm_findings: vec![json!({"phase":"llm_analysis","rule":"LLM-1"})]
            }
        );
        assert_eq!(
            parse(r#"{"scan_id":"s","metadata":{"upgrade_required":true}}"#),
            EnhancedOutcome::UpgradeRequired
        );
        assert_eq!(
            parse(
                r#"{"scan_id":"s","metadata":{"llm_analysis_performed":false,"llm_error":"ValueError"}}"#
            ),
            EnhancedOutcome::NotRun("server reported: ValueError".into())
        );
        // An API that says nothing about the LLM step did not run it.
        assert_eq!(
            parse(r#"{"scan_id":"s"}"#),
            EnhancedOutcome::NotRun("the response does not say it ran".into())
        );
    }

    #[test]
    fn threat_info_parses_the_api_threat_entry() {
        // The threat entry without the fields CLI 1.3.7 required: a 200 is a match.
        let info = parse_threat_info(
            r#"{"hash":"h1","package_name":"evil","version":"","severity":"CRITICAL",
                "source":"community","confirmed_at":null,"description":"steals keys"}"#,
            "h1",
        )
        .unwrap();
        assert!(info.known_malicious);
        assert_eq!(info.package_name.as_deref(), Some("evil"));
        assert_eq!(info.description.as_deref(), Some("steals keys"));
        assert!(info.references.is_empty());

        let explicit = parse_threat_info(r#"{"known_malicious":false}"#, "h2").unwrap();
        assert!(!explicit.known_malicious);
        assert_eq!(explicit.hash, "h2");

        assert!(parse_threat_info("not json", "h3").is_err());
    }

    #[test]
    fn threat_info_is_a_match_only_when_the_body_names_an_entry() {
        let matches = |body: &str| parse_threat_info(body, "h").unwrap().known_malicious;
        // The API's own bodies: the entry, with or without `known_malicious`.
        assert!(matches(r#"{"hash":"h1"}"#));
        assert!(matches(r#"{"package_name":"evil"}"#));
        assert!(matches(r#"{"hash":"h1","known_malicious":true}"#));
        assert!(matches(r#"{"known_malicious":true}"#));
        // A 2xx that names no entry is what a proxy or captive portal sends.
        for body in [
            "{}",
            r#"{"detail":"Not Found"}"#,
            r#"{"hash":"","package_name":null}"#,
            r#"{"hash":" ","package_name":"  "}"#,
            r#"{"status":"ok","message":"welcome to the guest network"}"#,
        ] {
            assert!(!matches(body), "{body}");
        }
        // An explicit "no" wins over a body that otherwise looks like an entry.
        assert!(!matches(r#"{"hash":"h1","known_malicious":false}"#));
        // The requested hash still fills in the no-match record.
        assert_eq!(parse_threat_info("{}", "h9").unwrap().hash, "h9");
        // Not an object at all (serde would read an array into the struct).
        for body in ["[]", r#"["h1","evil"]"#, "null", "true", r#""h1""#] {
            let err = parse_threat_info(body, "h").unwrap_err();
            assert!(err.contains("failed to parse response"), "{body}: {err}");
        }
    }

    #[test]
    fn report_response_reads_either_id_key() {
        let current: ReportResponse =
            serde_json::from_str(r#"{"report_id":"r-1","status":"received","message":"m"}"#)
                .unwrap();
        assert_eq!(current.report_id(), Some("r-1"));
        assert_eq!(current.status.as_deref(), Some("received"));
        let legacy: ReportResponse = serde_json::from_str(r#"{"id":"r-2","status":"ok"}"#).unwrap();
        assert_eq!(legacy.report_id(), Some("r-2"));
    }

    #[test]
    fn api_error_names_the_cause_of_known_statuses() {
        use reqwest::StatusCode;
        let e = api_error(StatusCode::UNAUTHORIZED, "", "");
        assert!(e.contains("401") && e.contains("sigil login"), "{e}");
        let e = api_error(StatusCode::FORBIDDEN, "{}", " (needs Pro)");
        assert!(e.contains("(needs Pro): {}"), "{e}");
        let long = "x".repeat(2000);
        let e = api_error(StatusCode::UNPROCESSABLE_ENTITY, &long, "");
        assert!(e.ends_with('…') && e.len() < 700, "{}", e.len());
    }

    /// Whether `s` holds anything `terminal_text` removes.
    fn holds_unprintable(s: &str) -> bool {
        s.chars()
            .any(|c| c.is_control() || is_format_or_separator(c))
    }

    #[test]
    fn terminal_text_removes_format_characters_and_line_separators() {
        // One from each Cf range and from Zl and Zp, with the effect that
        // makes it worth removing.
        let hostile = [
            ('\u{202E}', "right-to-left override"),
            ('\u{202A}', "left-to-right embedding"),
            ('\u{2066}', "left-to-right isolate"),
            ('\u{2069}', "pop directional isolate"),
            ('\u{200B}', "zero-width space"),
            ('\u{200D}', "zero-width joiner"),
            ('\u{2060}', "word joiner"),
            ('\u{206A}', "inhibit symmetric swapping"),
            ('\u{FEFF}', "byte order mark"),
            ('\u{00AD}', "soft hyphen"),
            ('\u{061C}', "arabic letter mark"),
            ('\u{180E}', "mongolian vowel separator"),
            ('\u{FFF9}', "interlinear annotation anchor"),
            ('\u{E0041}', "tag latin capital letter a"),
            ('\u{2028}', "line separator"),
            ('\u{2029}', "paragraph separator"),
            ('\u{9b}', "C1 control sequence introducer"),
        ];
        for (c, name) in hostile {
            let cleaned = terminal_text(&format!("a{c}b"));
            assert_eq!(cleaned, "a b", "{name} (U+{:04X})", u32::from(c));
        }

        // The reviewer's probe: a reversed tail and a forged next line.
        let spoof = "safe \u{202E})(txet desrever\u{2069} \u{200B}\u{2066} end \
                     U+2028:\u{2028}next-line";
        let cleaned = terminal_text(spoof);
        assert!(!holds_unprintable(&cleaned), "{cleaned:?}");
        assert_eq!(cleaned.split_whitespace().count(), 6);

        // Text that is only text is left alone, other scripts and emoji included.
        let plain = "naïve – 日本語 Привет שלום ✓ 🎉 a\tb";
        assert_eq!(
            terminal_text(plain),
            "naïve – 日本語 Привет שלום ✓ 🎉 a b",
            "only the tab is replaced"
        );
        assert_eq!(terminal_text("plain ascii, 100%"), "plain ascii, 100%");
    }

    #[test]
    fn api_text_is_printed_without_control_characters() {
        let hostile = "evil\u{1b}]8;;https://x.invalid\u{7}pkg\r\n\u{202E}tail\u{2028}";
        assert!(!holds_unprintable(&terminal_text(hostile)));
        assert!(!holds_unprintable(&error_excerpt(hostile)));
        // Whitespace around the body goes; an escape inside it becomes a space.
        assert_eq!(
            error_excerpt("  \u{1b}[31mdown\u{1b}[0m\r\n"),
            " [31mdown [0m"
        );
        let e = api_error(reqwest::StatusCode::BAD_REQUEST, hostile, "");
        assert!(!holds_unprintable(&e), "{e:?}");
        let resp: ScanResponse =
            serde_json::from_value(json!({"scan_id": "s", "metadata": {"llm_error": hostile}}))
                .unwrap();
        match EnhancedOutcome::from_response(&resp) {
            EnhancedOutcome::NotRun(reason) => {
                assert!(!holds_unprintable(&reason), "{reason:?}")
            }
            other => panic!("{other:?}"),
        }
    }

    // -- The request path, against a loopback server ----------------------

    /// Answer one request with `status` and `body`; the raw request comes
    /// back on the channel.
    pub(super) fn serve_once(
        status: &str,
        body: &str,
    ) -> (String, std::sync::mpsc::Receiver<String>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        std::thread::spawn(move || {
            let Ok((mut s, _)) = listener.accept() else {
                return;
            };
            let (mut buf, mut tmp) = (Vec::new(), [0u8; 8192]);
            let (mut header_end, mut len) = (0usize, 0usize);
            loop {
                let n = s.read(&mut tmp).unwrap_or(0);
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
                if header_end == 0 {
                    if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        header_end = p + 4;
                        let head = String::from_utf8_lossy(&buf[..header_end]).to_lowercase();
                        len = head
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length:"))
                            .and_then(|v| v.trim().parse().ok())
                            .unwrap_or(0);
                    }
                }
                if header_end > 0 && buf.len() >= header_end + len {
                    break;
                }
            }
            let _ = s.write_all(response.as_bytes());
            let _ = tx.send(String::from_utf8_lossy(&buf).to_string());
        });
        (format!("http://{addr}"), rx)
    }

    pub(super) fn test_client(endpoint: String) -> SigilClient {
        SigilClient {
            endpoint,
            client: reqwest::Client::builder().no_proxy().build().unwrap(),
            token: Some("test-token".into()),
        }
    }

    fn request_body(raw: &str) -> Value {
        let (_, body) = raw.split_once("\r\n\r\n").expect("http request");
        serde_json::from_str(body).expect("json body")
    }

    #[tokio::test]
    async fn submit_scan_posts_the_scan_request_and_reads_scan_id() {
        let (url, rx) = serve_once(
            "200 OK",
            r#"{"scan_id":"s-9","id":"s-9","status":"completed","verdict":"HIGH_RISK"}"#,
        );
        let result = sample_result();
        let resp = test_client(url).submit_scan(&result).await.unwrap();
        assert_eq!(resp.scan_id(), Some("s-9"));
        let raw = rx.recv().unwrap();
        assert!(raw.starts_with("POST /v1/scan HTTP/1.1"), "{raw}");
        assert!(raw
            .to_lowercase()
            .contains("authorization: bearer test-token"));
        assert_eq!(
            request_body(&raw),
            scan_request_body(&result, "sigil-scan", Map::new()).unwrap()
        );
    }

    #[tokio::test]
    async fn submit_scan_reports_a_rejection_with_its_status() {
        let (url, _rx) = serve_once(
            "422 Unprocessable Entity",
            r#"{"detail":"Validation error"}"#,
        );
        let err = test_client(url)
            .submit_scan(&sample_result())
            .await
            .unwrap_err();
        assert!(
            err.contains("422") && err.contains("Validation error"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn report_threat_posts_the_threat_report() {
        let (url, rx) = serve_once(
            "201 Created",
            r#"{"report_id":"r-1","id":"r-1","status":"received","message":"thanks"}"#,
        );
        let hash = "AB12".repeat(16);
        let resp = test_client(url)
            .report_threat(&hash, "backdoor", "opens a port")
            .await
            .unwrap();
        assert_eq!(resp.report_id(), Some("r-1"));
        let raw = rx.recv().unwrap();
        assert!(raw.starts_with("POST /v1/report HTTP/1.1"), "{raw}");
        assert_eq!(
            request_body(&raw),
            report_request_body(&"ab12".repeat(16), "backdoor", "opens a port")
        );
    }

    #[test]
    fn report_digest_accepts_only_a_sha256_hash() {
        let hex = "0123456789abcdef".repeat(4);
        assert_eq!(report_digest(&hex).unwrap(), hex);
        assert_eq!(
            report_digest(&format!("  {} ", hex.to_uppercase())).unwrap(),
            hex
        );
        for bad in [
            "",
            "ab",
            &hex[..63],
            &format!("{hex}0"),
            &"g".repeat(64),
            "x|.*",
            &format!("sha256:{hex}"),
            &"x".repeat(300),
        ] {
            let err = report_digest(bad).unwrap_err();
            assert!(err.contains("64 hexadecimal characters"), "{bad}: {err}");
        }
    }

    #[test]
    fn report_digest_names_the_actual_problem() {
        let hex = "0123456789abcdef".repeat(4);
        // Wrong length: the count is the problem, and it is stated.
        let short = report_digest(&hex[..63]).unwrap_err();
        assert!(short.ends_with("got 63 characters"), "{short}");
        let long = report_digest(&format!("{hex}0")).unwrap_err();
        assert!(long.ends_with("got 65 characters"), "{long}");
        // The count is of characters, not bytes, and of the trimmed input.
        let wide = report_digest(&"\u{e9}".repeat(32)).unwrap_err();
        assert!(wide.ends_with("got 32 characters"), "{wide}");
        let padded = report_digest(&format!("  {}  ", &hex[..60])).unwrap_err();
        assert!(padded.ends_with("got 60 characters"), "{padded}");
        // Right length, wrong characters: never "got 64 characters".
        for bad in [
            "g".repeat(64),
            format!("{}z", &hex[..63]),
            "\u{e9}".repeat(64),
            "x".repeat(32) + &hex[..32],
        ] {
            let err = report_digest(&bad).unwrap_err();
            assert!(!err.contains("got 64 characters"), "{bad}: {err}");
            assert!(
                err.contains("contains characters outside 0-9, a-f"),
                "{bad}: {err}"
            );
        }
        // The rejected input is not echoed back (it may hold terminal escapes).
        assert!(!report_digest("\u{1b}[2J").unwrap_err().contains('\u{1b}'));
    }

    #[tokio::test]
    async fn report_threat_sends_nothing_for_an_invalid_hash() {
        // Nothing listens on this loopback port: an attempted request would
        // fail with a connection error, not the hash error checked below.
        let client = test_client("http://127.0.0.1:9".into());
        let err = client
            .report_threat("x|.*", "malware", "d")
            .await
            .unwrap_err();
        assert!(err.contains("SHA-256"), "{err}");
    }

    #[tokio::test]
    async fn lookup_threat_reads_a_match_a_miss_and_a_refusal() {
        let (url, rx) = serve_once(
            "200 OK",
            r#"{"hash":"h","package_name":"evil","severity":"HIGH","description":"bad"}"#,
        );
        let hit = test_client(url).lookup_threat("h").await.unwrap();
        assert!(hit.known_malicious);
        assert!(rx.recv().unwrap().starts_with("GET /v1/threat/h HTTP/1.1"));

        let (url, _rx) = serve_once("404 Not Found", r#"{"detail":"No threat entry"}"#);
        let miss = test_client(url).lookup_threat("h").await.unwrap();
        assert!(!miss.known_malicious);

        let (url, _rx) = serve_once("403 Forbidden", r#"{"detail":"requires the pro plan"}"#);
        let err = test_client(url).lookup_threat("h").await.unwrap_err();
        assert!(err.contains("403") && err.contains("Pro plan"), "{err}");
    }
}

/// The golden contract shared with the API's tests: `tests/fixtures/api_contract`
/// at the repository root (see its README for how it was captured).
#[cfg(test)]
mod contract_fixture_tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture(rel: &str) -> Value {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../tests/fixtures/api_contract")
            .join(rel);
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
    }

    /// CLI 1.3.7 posted the raw ScanResult, so its body is the scan itself.
    fn scan_from_released_cli() -> ScanResult {
        serde_json::from_value(fixture("cli-1.3.7/scan_submit.json")).expect("ScanResult")
    }

    #[test]
    fn submit_body_is_the_captured_one() {
        let body = scan_request_body(&scan_from_released_cli(), "sigil-scan", Map::new()).unwrap();
        assert_eq!(body, fixture("cli-current/scan_submit.json"));
    }

    #[test]
    fn enhanced_body_is_the_captured_one() {
        let released = fixture("cli-1.3.7/scan_enhanced.json");
        let mut extra = Map::new();
        extra.insert(
            "file_contents".into(),
            released["metadata"]["file_contents"].clone(),
        );
        let body =
            scan_request_body(&scan_from_released_cli(), "sigil-scan-enhanced", extra).unwrap();
        assert_eq!(body, fixture("cli-current/scan_enhanced.json"));
    }

    #[test]
    fn report_body_is_the_captured_one() {
        let released = fixture("cli-1.3.7/report.json");
        let body = report_request_body(
            released["hash"].as_str().unwrap(),
            released["threat_type"].as_str().unwrap(),
            released["description"].as_str().unwrap(),
        );
        assert_eq!(body, fixture("cli-current/report.json"));
    }

    #[test]
    fn explain_body_is_the_captured_one() {
        // 1.3.7 normalised Phase 10 to "inferencesecurity" and named the scan
        // after the report file; the shared normaliser repairs that spelling,
        // and today's body carries the fixed target.
        let released = fixture("cli-1.3.7/explain_scan.json");
        let body = crate::explain::explain_scan_body(released["findings"].as_array().unwrap());
        assert_eq!(body, fixture("cli-current/explain_scan.json"));
    }

    #[test]
    fn phases_fixture_lists_every_cli_phase() {
        // api/tests/test_cli_contract.py checks each of these against the
        // API's ScanPhase. A new CLI phase fails here until it is listed.
        let actual: Vec<Value> = Phase::ALL
            .iter()
            .map(|p| {
                let serde_name = serde_json::to_value(p).unwrap();
                let api = api_phase(serde_name.as_str().unwrap());
                json!({"serde": serde_name, "api": api})
            })
            .collect();
        assert_eq!(
            Value::Array(actual),
            fixture("cli-current/phases.json")["phases"],
            "update tests/fixtures/api_contract/cli-current/phases.json and the \
             API's ScanPhase (api/models.py)"
        );
    }

    #[tokio::test]
    async fn lookup_refusal_on_a_free_plan_names_the_plan() {
        let body = fixture("api-patched/threat_lookup_403_free_plan.json").to_string();
        let (url, _rx) = super::tests::serve_once("403 Forbidden", &body);
        let err = super::tests::test_client(url)
            .lookup_threat(&"0".repeat(64))
            .await
            .unwrap_err();
        assert!(
            err.contains("403") && err.contains("needs a Pro plan"),
            "{err}"
        );
        assert!(err.contains("requires the pro plan"), "{err}");
    }

    #[test]
    fn responses_from_both_apis_parse() {
        for api in ["api-patched", "api-deployed"] {
            let scan: ScanResponse =
                serde_json::from_value(fixture(&format!("{api}/scan_response.json"))).unwrap();
            assert!(scan.scan_id().is_some(), "{api}");

            let enhanced: ScanResponse = serde_json::from_value(fixture(&format!(
                "{api}/scan_enhanced_response_free_plan.json"
            )))
            .unwrap();
            let outcome = EnhancedOutcome::from_response(&enhanced);
            assert!(
                !matches!(outcome, EnhancedOutcome::Analysed { .. }),
                "{api}: a Free plan response must not read as LLM analysis"
            );

            let report: ReportResponse =
                serde_json::from_value(fixture(&format!("{api}/report_response.json"))).unwrap();
            assert!(report.report_id().is_some(), "{api}");

            let lookup = fixture(&format!("{api}/threat_lookup_response.json"));
            let info = parse_threat_info(&lookup.to_string(), "unused").unwrap();
            assert!(info.known_malicious, "{api}");
            assert_eq!(info.package_name.as_deref(), Some("contract-test-pkg"));
        }
        let enhanced: ScanResponse =
            serde_json::from_value(fixture("api-patched/scan_enhanced_response_free_plan.json"))
                .unwrap();
        assert_eq!(
            EnhancedOutcome::from_response(&enhanced),
            EnhancedOutcome::UpgradeRequired
        );
    }

    /// CLI 1.3.7's scan response type (`cli/src/api.rs` at v1.3.7). 1.3.7
    /// prints success for any `--submit` or `--enhanced` response that
    /// deserializes into it, without reading anything else.
    #[derive(Deserialize)]
    #[allow(dead_code)]
    struct ReleasedCliScanResponse {
        id: String,
        status: String,
        message: Option<String>,
    }

    #[test]
    fn released_cli_reads_success_only_where_it_is_true() {
        let parses =
            |rel: &str| serde_json::from_value::<ReleasedCliScanResponse>(fixture(rel)).is_ok();
        // The scan was stored: 1.3.7's "results submitted" is true.
        assert!(parses("api-patched/scan_response.json"));
        // No LLM analysis ran: 1.3.7 must not print "Enhanced LLM analysis
        // completed", so the API leaves out the `id` it needs.
        assert!(!parses("api-patched/scan_enhanced_response_free_plan.json"));
    }
}
