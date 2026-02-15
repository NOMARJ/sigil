use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

use crate::scanner::ScanResult;

const DEFAULT_ENDPOINT: &str = "https://api.sigil.nomark.dev";

/// API client for the Sigil cloud service.
pub struct SigilClient {
    endpoint: String,
    client: reqwest::Client,
    token: Option<String>,
}

/// Response from a scan submission.
#[derive(Debug, Serialize, Deserialize)]
pub struct ScanResponse {
    pub id: String,
    pub status: String,
    pub message: Option<String>,
}

/// Response from a threat lookup.
#[derive(Debug, Serialize, Deserialize)]
pub struct ThreatInfo {
    pub hash: String,
    pub known_malicious: bool,
    pub threat_type: Option<String>,
    pub description: Option<String>,
    pub first_seen: Option<String>,
    pub references: Vec<String>,
}

/// A threat detection signature from the cloud.
#[derive(Debug, Serialize, Deserialize)]
pub struct Signature {
    pub id: String,
    pub pattern: String,
    pub phase: String,
    pub severity: String,
    pub description: String,
}

/// Response from a threat report submission.
#[derive(Debug, Serialize, Deserialize)]
pub struct ReportResponse {
    pub id: String,
    pub status: String,
}

/// Authentication response.
#[derive(Debug, Serialize, Deserialize)]
struct AuthResponse {
    pub token: String,
    pub expires_at: Option<String>,
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
fn load_token() -> Option<String> {
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

        let mut request = self.client.post(&url).json(result);
        if let Some(ref token) = self.token {
            request = request.bearer_auth(token);
        }

        let response = request
            .send()
            .await
            .map_err(|e| offline_fallback_message(&e))?;

        if !response.status().is_success() {
            return Err(format!(
                "API error: {} {}",
                response.status(),
                response.text().await.unwrap_or_default()
            ));
        }

        response
            .json::<ScanResponse>()
            .await
            .map_err(|e| format!("failed to parse response: {}", e))
    }

    /// Look up a file hash in the threat intelligence database.
    ///
    /// GET /v1/threat/{hash}
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

        if response.status().as_u16() == 404 {
            return Ok(ThreatInfo {
                hash: hash.to_string(),
                known_malicious: false,
                threat_type: None,
                description: None,
                first_seen: None,
                references: vec![],
            });
        }

        if !response.status().is_success() {
            return Err(format!("API error: {}", response.status()));
        }

        response
            .json::<ThreatInfo>()
            .await
            .map_err(|e| format!("failed to parse response: {}", e))
    }

    /// Fetch the latest threat detection signatures.
    ///
    /// GET /v1/signatures
    ///
    /// Returns the number of signatures downloaded.
    pub async fn get_signatures(&self, _force: bool) -> Result<usize, String> {
        let url = format!("{}/v1/signatures", self.endpoint);

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

        let signatures: Vec<Signature> = response
            .json()
            .await
            .map_err(|e| format!("failed to parse signatures: {}", e))?;

        // Store signatures locally
        let sigs_path = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".sigil")
            .join("signatures.json");

        if let Some(parent) = sigs_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        let json = serde_json::to_string_pretty(&signatures)
            .map_err(|e| format!("failed to serialize signatures: {}", e))?;
        fs::write(&sigs_path, json)
            .map_err(|e| format!("failed to write signatures: {}", e))?;

        Ok(signatures.len())
    }

    /// Report a new threat to the Sigil cloud.
    ///
    /// POST /v1/report
    pub async fn report_threat(
        &self,
        hash: &str,
        threat_type: &str,
        description: &str,
    ) -> Result<ReportResponse, String> {
        let url = format!("{}/v1/report", self.endpoint);

        let body = serde_json::json!({
            "hash": hash,
            "threat_type": threat_type,
            "description": description,
        });

        let mut request = self.client.post(&url).json(&body);
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

    /// Authenticate with email and password.
    ///
    /// POST /v1/auth/login
    pub async fn login(&self, email: &str, password: &str) -> Result<(), String> {
        let url = format!("{}/v1/auth/login", self.endpoint);

        let body = serde_json::json!({
            "email": email,
            "password": password,
        });

        let response = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| offline_fallback_message(&e))?;

        if !response.status().is_success() {
            return Err(format!(
                "login failed (server returned {})",
                response.status()
            ));
        }

        let auth: AuthResponse = response
            .json()
            .await
            .map_err(|e| format!("failed to parse auth response: {}", e))?;

        save_token(&auth.token)?;
        Ok(())
    }

    /// Register a new account and receive a token.
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
