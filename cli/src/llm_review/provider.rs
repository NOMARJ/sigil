//! The two wire protocols the LLM stage speaks: the Anthropic Messages API
//! and the OpenAI-compatible chat-completions API (self-hosted servers and
//! other vendors).
//!
//! Rust has no official Anthropic SDK, so the Messages API is called over
//! HTTP with the existing `reqwest` dependency: `POST {base}/v1/messages`
//! with `x-api-key` and `anthropic-version: 2023-06-01`.

use std::time::Duration;

use serde_json::{json, Value};

use super::prompt;

/// Default Anthropic API base (overridden by `ANTHROPIC_BASE_URL`, as the
/// official SDKs do).
pub const ANTHROPIC_DEFAULT_BASE: &str = "https://api.anthropic.com";
/// The Messages API version header.
pub const ANTHROPIC_VERSION: &str = "2023-06-01";
/// Default model for the Anthropic provider.
pub const DEFAULT_ANTHROPIC_MODEL: &str = "claude-opus-5";
/// Beta header for `fallbacks: "default"`: a request the model's safety
/// classifiers decline is re-run on the model Anthropic recommends for that
/// refusal category, inside the same call. Security code trips those
/// classifiers now and then, so the stage opts in on the models that take it.
const FALLBACK_BETA: &str = "server-side-fallback-2026-07-01";

/// Largest response body read.
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

/// Which API an endpoint speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    Anthropic,
    OpenAiCompatible,
}

impl Provider {
    pub fn label(self) -> &'static str {
        match self {
            Provider::Anthropic => "anthropic",
            Provider::OpenAiCompatible => "openai-compatible",
        }
    }

    /// Parse a provider name from a policy or the environment.
    pub fn parse(s: &str) -> Option<Provider> {
        match s.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "anthropic" | "claude" => Some(Provider::Anthropic),
            "openai-compatible" | "openai" => Some(Provider::OpenAiCompatible),
            _ => None,
        }
    }
}

/// Check an endpoint URL: `https`, or plain `http` to a loopback address
/// only (a model served on this machine), and no credentials in the URL.
///
/// Error messages show the URL without credentials or query string, so a
/// token placed there is never echoed into a report.
pub fn check_endpoint(url: &str) -> Result<reqwest::Url, String> {
    let u =
        reqwest::Url::parse(url.trim()).map_err(|e| format!("the endpoint is not a URL ({e})"))?;
    if !u.username().is_empty() || u.password().is_some() {
        return Err("the endpoint URL must not carry credentials; use SIGIL_LLM_API_KEY".into());
    }
    let shown = display_url(url.trim());
    if u.host_str().is_none() {
        return Err(format!("'{shown}' has no host"));
    }
    let loopback = is_loopback(&u);
    match u.scheme() {
        "https" => Ok(u),
        "http" if loopback => Ok(u),
        "http" => Err(format!(
            "'{shown}' uses plain http; scanned code may only be sent over https (plain http is accepted for localhost)"
        )),
        other => Err(format!("'{shown}' has unsupported scheme '{other}'")),
    }
}

/// Does the URL point at this machine (`localhost`, `127.0.0.0/8`, `::1`)?
pub fn is_loopback(u: &reqwest::Url) -> bool {
    let Some(host) = u.host_str() else {
        return false;
    };
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    bare.eq_ignore_ascii_case("localhost")
        || bare
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// The Messages API URL under an Anthropic base URL.
pub fn anthropic_url(base: &str) -> String {
    format!("{}/v1/messages", base.trim().trim_end_matches('/'))
}

/// The chat-completions URL for an OpenAI-compatible endpoint: used as given
/// when it already ends in `/chat/completions`, otherwise treated as the API
/// base (`http://localhost:11434/v1`).
pub fn openai_url(endpoint: &str) -> String {
    let e = endpoint.trim().trim_end_matches('/');
    if e.ends_with("/chat/completions") {
        e.to_string()
    } else {
        format!("{e}/chat/completions")
    }
}

/// An endpoint as it is shown in reports: no credentials, query string or
/// fragment.
pub fn display_url(url: &str) -> String {
    match reqwest::Url::parse(url) {
        Ok(mut u) => {
            let _ = u.set_username("");
            let _ = u.set_password(None);
            u.set_query(None);
            u.set_fragment(None);
            u.to_string()
        }
        Err(_) => "(not a URL)".to_string(),
    }
}

fn model_has(model: &str, prefixes: &[&str]) -> bool {
    prefixes.iter().any(|p| model.starts_with(p))
}

/// Models that take `output_config.effort`.
fn supports_effort(model: &str) -> bool {
    model_has(
        model,
        &[
            "claude-opus-5",
            "claude-fable-5",
            "claude-mythos-5",
            "claude-sonnet-5",
            "claude-opus-4-8",
            "claude-opus-4-7",
            "claude-opus-4-6",
            "claude-sonnet-4-6",
        ],
    )
}

/// Models that take structured outputs (`output_config.format`).
fn supports_structured_output(model: &str) -> bool {
    model_has(
        model,
        &[
            "claude-opus-5",
            "claude-fable-5",
            "claude-mythos-5",
            "claude-sonnet-5",
            "claude-opus-4-8",
            "claude-haiku-4-5",
            "claude-opus-4-5",
            "claude-opus-4-1",
        ],
    )
}

/// Models that take `fallbacks: "default"`.
fn supports_default_fallbacks(model: &str) -> bool {
    model_has(
        model,
        &["claude-opus-5", "claude-fable-5-1", "claude-mythos-5-1"],
    )
}

/// The Messages API request body, and whether it needs the fallback beta.
pub fn anthropic_body(model: &str, user: &str, ids: &[String], max_tokens: u64) -> (Value, bool) {
    let mut body = json!({
        "model": model,
        "max_tokens": max_tokens,
        "system": prompt::SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": user}],
    });
    let mut output_config = serde_json::Map::new();
    if supports_effort(model) {
        // A per-finding classification, not an open-ended task: medium keeps
        // the reasoning while bounding cost. Thinking stays at the model's
        // default (adaptive on Claude Opus 5); `max_tokens` covers both.
        output_config.insert("effort".into(), json!("medium"));
    }
    if supports_structured_output(model) {
        output_config.insert(
            "format".into(),
            json!({"type": "json_schema", "schema": prompt::response_schema(ids)}),
        );
    }
    if !output_config.is_empty() {
        body["output_config"] = Value::Object(output_config);
    }
    let fallbacks = supports_default_fallbacks(model);
    if fallbacks {
        body["fallbacks"] = json!("default");
    }
    (body, fallbacks)
}

/// The chat-completions request body. Only fields every compatible server
/// accepts: no `response_format` (support varies), no sampling parameters.
pub fn openai_body(model: &str, user: &str, max_tokens: u64) -> Value {
    json!({
        "model": model,
        "max_tokens": max_tokens,
        "messages": [
            {"role": "system", "content": prompt::SYSTEM_PROMPT},
            {"role": "user", "content": user},
        ],
    })
}

/// What one HTTP call produced.
#[derive(Debug)]
pub struct CallOutcome {
    /// The model's text reply, or why there is none.
    pub text: Result<String, String>,
    /// Worth one retry (rate limit, overload, server error).
    pub retryable: bool,
    pub retry_after: Option<Duration>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    /// The model that served the reply, as the provider reports it.
    pub served_model: Option<String>,
    /// The HTTP status, when a response arrived.
    pub status: Option<u16>,
}

impl CallOutcome {
    fn new(text: Result<String, String>) -> Self {
        CallOutcome {
            text,
            retryable: false,
            retry_after: None,
            input_tokens: None,
            output_tokens: None,
            served_model: None,
            status: None,
        }
    }
}

/// Everything needed to send one request.
pub struct Endpoint<'a> {
    pub provider: Provider,
    pub url: &'a str,
    pub api_key: Option<&'a str>,
}

/// Send one request and interpret the reply.
pub async fn send(
    client: &reqwest::Client,
    endpoint: &Endpoint<'_>,
    body: &Value,
    fallback_beta: bool,
    timeout: Duration,
) -> CallOutcome {
    let mut req = client
        .post(endpoint.url)
        .header("content-type", "application/json")
        .json(body);
    match endpoint.provider {
        Provider::Anthropic => {
            req = req.header("anthropic-version", ANTHROPIC_VERSION);
            if let Some(key) = endpoint.api_key {
                req = req.header("x-api-key", key);
            }
            if fallback_beta {
                req = req.header("anthropic-beta", FALLBACK_BETA);
            }
        }
        Provider::OpenAiCompatible => {
            if let Some(key) = endpoint.api_key {
                req = req.bearer_auth(key);
            }
        }
    }
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => return failed(describe_transport_error(&e, timeout)),
    };
    let status = resp.status();
    let retry_after = resp
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(Duration::from_secs);
    let bytes = match read_capped(resp).await {
        Ok(b) => b,
        Err(e) => return failed(e),
    };
    let doc: Option<Value> = serde_json::from_slice(&bytes).ok();
    if !status.is_success() {
        let msg = doc
            .as_ref()
            .and_then(error_message)
            .unwrap_or_else(|| "no error message".to_string());
        let mut out = CallOutcome::new(Err(format!("HTTP {}: {}", status.as_u16(), msg)));
        out.retryable = matches!(status.as_u16(), 429 | 500 | 502 | 503 | 504 | 529);
        out.retry_after = retry_after;
        out.status = Some(status.as_u16());
        return out;
    }
    let Some(doc) = doc else {
        let mut out = failed("the provider's response is not JSON".to_string());
        out.status = Some(status.as_u16());
        return out;
    };
    let mut out = match endpoint.provider {
        Provider::Anthropic => interpret_anthropic(&doc),
        Provider::OpenAiCompatible => interpret_openai(&doc),
    };
    out.status = Some(status.as_u16());
    out
}

fn failed(reason: String) -> CallOutcome {
    CallOutcome::new(Err(reason))
}

fn describe_transport_error(e: &reqwest::Error, timeout: Duration) -> String {
    if e.is_timeout() {
        format!("request timed out after {}s", timeout.as_secs())
    } else if e.is_connect() {
        "could not connect to the endpoint".to_string()
    } else if e.is_redirect() {
        "the endpoint redirected; redirects are not followed".to_string()
    } else {
        "request failed before a response arrived".to_string()
    }
}

async fn read_capped(mut resp: reqwest::Response) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                if out.len() + chunk.len() > MAX_RESPONSE_BYTES {
                    return Err(format!(
                        "the provider's response exceeds {MAX_RESPONSE_BYTES} bytes"
                    ));
                }
                out.extend_from_slice(&chunk);
            }
            Ok(None) => return Ok(out),
            Err(e) if e.is_timeout() => {
                return Err("timed out while reading the response".to_string())
            }
            Err(_) => return Err("the response was cut off".to_string()),
        }
    }
}

/// `error.message` (with `error.type`) from an Anthropic or OpenAI error
/// body, sanitized and shortened.
fn error_message(doc: &Value) -> Option<String> {
    let err = doc.get("error")?;
    let msg = err
        .get("message")
        .and_then(Value::as_str)
        .or_else(|| err.as_str())?;
    let kind = err.get("type").and_then(Value::as_str);
    let text = match kind {
        Some(k) => format!("{k}: {msg}"),
        None => msg.to_string(),
    };
    Some(prompt::sanitize_rationale(&text))
}

fn interpret_anthropic(doc: &Value) -> CallOutcome {
    let usage = doc.get("usage");
    let n = |k: &str| usage.and_then(|u| u.get(k)).and_then(Value::as_u64);
    let input = [
        n("input_tokens"),
        n("cache_creation_input_tokens"),
        n("cache_read_input_tokens"),
    ]
    .iter()
    .flatten()
    .copied()
    .reduce(|a, b| a + b);
    let mut out = CallOutcome::new(Err(String::new()));
    out.input_tokens = input;
    out.output_tokens = n("output_tokens");
    out.served_model = doc.get("model").and_then(Value::as_str).map(str::to_string);
    let stop = doc.get("stop_reason").and_then(Value::as_str).unwrap_or("");
    out.text = match stop {
        "refusal" => {
            let category = doc
                .get("stop_details")
                .and_then(|d| d.get("category"))
                .and_then(Value::as_str)
                .map(|c| format!(" (category {})", prompt::sanitize_rationale(c)))
                .unwrap_or_default();
            Err(format!("the model declined the request{category}"))
        }
        "max_tokens" => Err("the reply was cut off at max_tokens".to_string()),
        _ => {
            let text: String = doc
                .get("content")
                .and_then(Value::as_array)
                .map(|blocks| {
                    blocks
                        .iter()
                        .filter(|b| b.get("type").and_then(Value::as_str) == Some("text"))
                        .filter_map(|b| b.get("text").and_then(Value::as_str))
                        .collect::<Vec<_>>()
                        .join("")
                })
                .unwrap_or_default();
            if text.trim().is_empty() {
                Err("the reply has no text".to_string())
            } else {
                Ok(text)
            }
        }
    };
    out
}

fn interpret_openai(doc: &Value) -> CallOutcome {
    let usage = doc.get("usage");
    let n = |k: &str| usage.and_then(|u| u.get(k)).and_then(Value::as_u64);
    let mut out = CallOutcome::new(Err(String::new()));
    out.input_tokens = n("prompt_tokens");
    out.output_tokens = n("completion_tokens");
    out.served_model = doc.get("model").and_then(Value::as_str).map(str::to_string);
    let choice = doc
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|c| c.first());
    let Some(choice) = choice else {
        out.text = Err("the reply has no choices".to_string());
        return out;
    };
    let finish = choice
        .get("finish_reason")
        .and_then(Value::as_str)
        .unwrap_or("");
    let message = choice.get("message");
    let refusal = message
        .and_then(|m| m.get("refusal"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty());
    out.text = if finish == "length" {
        Err("the reply was cut off at max_tokens".to_string())
    } else if finish == "content_filter" || refusal.is_some() {
        Err("the model declined the request".to_string())
    } else {
        match message
            .and_then(|m| m.get("content"))
            .and_then(Value::as_str)
        {
            Some(t) if !t.trim().is_empty() => Ok(t.to_string()),
            _ => Err("the reply has no text".to_string()),
        }
    };
    out
}
