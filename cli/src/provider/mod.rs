use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// A named credential bundle — a set of environment variable names that
/// can be injected into a sandboxed execution environment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provider {
    /// Provider name (e.g., "github", "anthropic")
    pub name: String,
    /// Environment variable names this provider grants access to
    pub vars: Vec<String>,
    /// Optional description
    #[serde(default)]
    pub description: Option<String>,
    /// When this provider was created
    pub created_at: String,
}

impl Provider {
    /// Create a new provider with the given name, variable list, and optional description.
    pub fn new(name: &str, vars: Vec<String>, description: Option<String>) -> Self {
        Self {
            name: name.to_string(),
            vars,
            description,
            created_at: chrono::Utc::now().to_rfc3339(),
        }
    }
}

/// Returns the path to `~/.sigil/providers/`, creating it if necessary.
pub fn providers_dir() -> PathBuf {
    let dir = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".sigil")
        .join("providers");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// Serialize a provider to `~/.sigil/providers/<name>.json`.
pub fn save(provider: &Provider) -> Result<(), Box<dyn std::error::Error>> {
    let path = providers_dir().join(format!("{}.json", provider.name));
    let json = serde_json::to_string_pretty(provider)?;
    std::fs::write(path, json)?;
    Ok(())
}

/// Load a provider from its JSON file by name.
pub fn load(name: &str) -> Result<Provider, Box<dyn std::error::Error>> {
    let path = providers_dir().join(format!("{}.json", name));
    if !path.exists() {
        return Err(format!("provider '{}' not found", name).into());
    }
    let data = std::fs::read_to_string(path)?;
    let provider: Provider = serde_json::from_str(&data)?;
    Ok(provider)
}

/// List all saved providers.
pub fn list_providers() -> Vec<Provider> {
    let dir = providers_dir();
    let mut providers = Vec::new();

    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                if let Ok(data) = std::fs::read_to_string(&path) {
                    if let Ok(provider) = serde_json::from_str::<Provider>(&data) {
                        providers.push(provider);
                    }
                }
            }
        }
    }

    providers.sort_by(|a, b| a.name.cmp(&b.name));
    providers
}

/// Remove a provider file by name.
pub fn delete(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = providers_dir().join(format!("{}.json", name));
    if !path.exists() {
        return Err(format!("provider '{}' not found", name).into());
    }
    std::fs::remove_file(path)?;
    Ok(())
}

/// Given provider names, collect all matching env vars from the current environment.
/// Only includes vars that are listed in the provider AND exist in the current env.
pub fn resolve_env(providers: &[String]) -> HashMap<String, String> {
    let mut env_map = HashMap::new();

    for provider_name in providers {
        if let Ok(provider) = load(provider_name) {
            for var in &provider.vars {
                if let Ok(value) = std::env::var(var) {
                    env_map.insert(var.clone(), value);
                }
            }
        }
    }

    env_map
}

/// Check current env for well-known agent credentials and suggest provider bundles.
pub fn auto_discover() -> Vec<(String, Vec<String>)> {
    let mut suggestions = Vec::new();

    // Anthropic
    if std::env::var("ANTHROPIC_API_KEY").is_ok() {
        suggestions.push((
            "anthropic".to_string(),
            vec!["ANTHROPIC_API_KEY".to_string()],
        ));
    }

    // OpenAI
    if std::env::var("OPENAI_API_KEY").is_ok() {
        suggestions.push(("openai".to_string(), vec!["OPENAI_API_KEY".to_string()]));
    }

    // GitHub
    {
        let mut gh_vars = Vec::new();
        if std::env::var("GITHUB_TOKEN").is_ok() {
            gh_vars.push("GITHUB_TOKEN".to_string());
        }
        if std::env::var("GH_TOKEN").is_ok() {
            gh_vars.push("GH_TOKEN".to_string());
        }
        if !gh_vars.is_empty() {
            suggestions.push(("github".to_string(), gh_vars));
        }
    }

    // AWS
    if std::env::var("AWS_ACCESS_KEY_ID").is_ok() {
        suggestions.push(("aws".to_string(), vec!["AWS_ACCESS_KEY_ID".to_string()]));
    }

    // Azure
    {
        let mut azure_vars = Vec::new();
        if std::env::var("AZURE_SUBSCRIPTION_ID").is_ok() {
            azure_vars.push("AZURE_SUBSCRIPTION_ID".to_string());
        }
        if std::env::var("AZURE_CLIENT_ID").is_ok() {
            azure_vars.push("AZURE_CLIENT_ID".to_string());
        }
        if !azure_vars.is_empty() {
            suggestions.push(("azure".to_string(), azure_vars));
        }
    }

    suggestions
}
