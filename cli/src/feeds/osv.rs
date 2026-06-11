//! OSV.dev integration for dependency vulnerability lookups.
//!
//! Queries `https://api.osv.dev/v1/querybatch` with batched package/version
//! requests derived from SBOM lockfile parsers. Responses are cached under
//! `~/.sigil/osv-cache/` keyed by `{ecosystem}-{name}-{version}.json`.
//!
//! MAL- prefixed advisory IDs are promoted to Critical; CVE/GHSA IDs use
//! the OSV `database_specific.severity` field or CVSS vector; fallback is High
//! for CVE/GHSA and Critical for MAL-.
//!
//! When the network is unavailable the module falls back to cached responses
//! and emits a notice to stderr. A scan with neither network nor cache never
//! errors the containing scan — it returns an empty Vec<Finding>.

use crate::sbom::Component;
use crate::scanner::{Finding, Phase, Severity};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// OSV ecosystem identifiers mapped from our package_type strings.
fn ecosystem_for(package_type: &str) -> Option<&'static str> {
    match package_type {
        "pip" => Some("PyPI"),
        "npm" => Some("npm"),
        "cargo" => Some("crates.io"),
        "go" => Some("Go"),
        _ => None,
    }
}

// ── Cache helpers ──────────────────────────────────────────────────────────

fn cache_dir() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".sigil").join("osv-cache"))
}

fn cache_key(ecosystem: &str, name: &str, version: &str) -> String {
    // Sanitize to safe filesystem characters
    let safe = |s: &str| s.replace(['/', '\\', ':'], "_");
    format!("{}-{}-{}", safe(ecosystem), safe(name), safe(version))
}

fn read_cache(dir: &Path, key: &str) -> Option<serde_json::Value> {
    let path = dir.join(format!("{}.json", key));
    let bytes = std::fs::read(&path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn write_cache(dir: &Path, key: &str, value: &serde_json::Value) {
    let _ = std::fs::create_dir_all(dir);
    let path = dir.join(format!("{}.json", key));
    if let Ok(s) = serde_json::to_string(value) {
        let _ = std::fs::write(path, s);
    }
}

// ── OSV API types (only what we need) ──────────────────────────────────────

#[derive(Debug, Serialize)]
struct OsvQuery {
    package: OsvPackage,
    version: String,
}

#[derive(Debug, Serialize)]
struct OsvPackage {
    name: String,
    ecosystem: String,
}

#[derive(Debug, Serialize)]
struct OsvBatchRequest {
    queries: Vec<OsvQuery>,
}

#[derive(Debug, Deserialize)]
struct OsvBatchResponse {
    results: Vec<OsvResult>,
}

#[derive(Debug, Deserialize, Clone)]
struct OsvResult {
    #[serde(default)]
    vulns: Vec<OsvVuln>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct OsvVuln {
    pub id: String,
    #[serde(default)]
    pub severity: Vec<OsvSeverity>,
    pub database_specific: Option<serde_json::Value>,
    pub summary: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct OsvSeverity {
    #[serde(rename = "type")]
    pub severity_type: String,
    pub score: String,
}

// ── Severity mapping ────────────────────────────────────────────────────────

/// Map an OSV advisory ID + severity information to a `Severity` enum value.
///
/// MAL- prefixed IDs (OpenSSF malicious-packages) → Critical.
/// CVE/GHSA → use `database_specific.severity` string or CVSS score if present,
/// else default to High.
pub fn osv_severity(vuln: &OsvVuln) -> Severity {
    if vuln.id.starts_with("MAL-") {
        return Severity::Critical;
    }
    // Try database_specific.severity first. GitHub advisories (the bulk of the
    // npm/PyPI corpus) use LOW / MODERATE / HIGH / CRITICAL — note MODERATE, not
    // MEDIUM. Mapping MODERATE here was the missing case that over-rated every
    // moderate advisory as High.
    if let Some(ref db) = vuln.database_specific {
        if let Some(sev) = db.get("severity").and_then(|s| s.as_str()) {
            if let Some(mapped) = severity_from_label(sev) {
                return mapped;
            }
        }
    }
    // Otherwise derive from the CVSS vector's computed base score (records like
    // raw CVE/PYSEC often carry only a CVSS vector, no qualitative label).
    for s in &vuln.severity {
        if s.severity_type.starts_with("CVSS") {
            if let Some(score) = cvss3_base_score(&s.score) {
                return severity_from_cvss_score(score);
            }
        }
    }
    // No qualitative label and no parseable CVSS: default conservatively to High
    // (a known advisory with unknown severity is treated as actionable).
    Severity::High
}

/// Map a qualitative severity label (case-insensitive) to `Severity`.
/// Accepts both "MEDIUM" and GitHub's "MODERATE".
fn severity_from_label(label: &str) -> Option<Severity> {
    match label.to_uppercase().as_str() {
        "CRITICAL" => Some(Severity::Critical),
        "HIGH" => Some(Severity::High),
        "MEDIUM" | "MODERATE" => Some(Severity::Medium),
        "LOW" => Some(Severity::Low),
        _ => None,
    }
}

/// CVSS 3.x qualitative rating from a base score.
fn severity_from_cvss_score(score: f64) -> Severity {
    if score >= 9.0 {
        Severity::Critical
    } else if score >= 7.0 {
        Severity::High
    } else if score >= 4.0 {
        Severity::Medium
    } else {
        Severity::Low
    }
}

/// Compute a CVSS 3.0/3.1 base score from a vector string such as
/// `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`. Returns None if the string
/// is not a parseable CVSS v3 base vector. Implements the spec formula so a
/// vector without an embedded numeric score still yields a correct rating.
fn cvss3_base_score(vector: &str) -> Option<f64> {
    if !vector.starts_with("CVSS:3") {
        return None;
    }
    let mut m = std::collections::HashMap::new();
    for part in vector.split('/').skip(1) {
        let (k, v) = part.split_once(':')?;
        m.insert(k, v);
    }
    let scope_changed = *m.get("S")? == "C";
    let av = match *m.get("AV")? {
        "N" => 0.85,
        "A" => 0.62,
        "L" => 0.55,
        "P" => 0.2,
        _ => return None,
    };
    let ac = match *m.get("AC")? {
        "L" => 0.77,
        "H" => 0.44,
        _ => return None,
    };
    let pr = match (*m.get("PR")?, scope_changed) {
        ("N", _) => 0.85,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        ("H", false) => 0.27,
        ("H", true) => 0.5,
        _ => return None,
    };
    let ui = match *m.get("UI")? {
        "N" => 0.85,
        "R" => 0.62,
        _ => return None,
    };
    let imp = |s: &str| match s {
        "H" => 0.56,
        "L" => 0.22,
        "N" => 0.0,
        _ => f64::NAN,
    };
    let (c, i, a) = (imp(m.get("C")?), imp(m.get("I")?), imp(m.get("A")?));
    if c.is_nan() || i.is_nan() || a.is_nan() {
        return None;
    }
    let isc_base = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a));
    let impact = if scope_changed {
        7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02).powi(15)
    } else {
        6.42 * isc_base
    };
    if impact <= 0.0 {
        return Some(0.0);
    }
    let exploitability = 8.22 * av * ac * pr * ui;
    let raw = if scope_changed {
        (1.08 * (impact + exploitability)).min(10.0)
    } else {
        (impact + exploitability).min(10.0)
    };
    // CVSS roundup: ceil to one decimal place.
    Some((raw * 10.0).ceil() / 10.0)
}

// ── Core query function ─────────────────────────────────────────────────────

/// Query OSV for a batch of components.
///
/// Returns a list of (component_index, vuln) pairs for every vulnerability
/// found. Components without a version or without a known ecosystem are
/// silently skipped.
///
/// Network failures fall back to cache; complete cache miss + network failure
/// yields an empty result (not an error) so the containing scan can continue.
pub fn query_osv(
    components: &[Component],
    offline_hint: bool,
) -> Vec<(usize, OsvVuln)> {
    // Build queries for components that have both a version and a known ecosystem
    let indexed: Vec<(usize, &Component, &str)> = components
        .iter()
        .enumerate()
        .filter_map(|(i, c)| {
            let eco = ecosystem_for(&c.package_type)?;
            let _version = c.version.as_deref()?;
            Some((i, c, eco))
        })
        .collect();

    if indexed.is_empty() {
        return Vec::new();
    }

    let cache_dir = cache_dir();

    // Separate components that are already cached from those needing network
    let mut results: Vec<Option<OsvResult>> = (0..indexed.len()).map(|_| None).collect();
    let mut uncached_positions: Vec<usize> = Vec::new(); // indexes into `indexed`

    for (pos, (_, comp, eco)) in indexed.iter().enumerate() {
        let version = comp.version.as_deref().unwrap_or("");
        let key = cache_key(eco, &comp.name, version);
        if let Some(ref dir) = cache_dir {
            if let Some(cached) = read_cache(dir, &key) {
                // Deserialize the cached OsvResult
                if let Ok(r) = serde_json::from_value::<OsvResult>(cached) {
                    results[pos] = Some(r);
                    continue;
                }
            }
        }
        if !offline_hint {
            uncached_positions.push(pos);
        }
    }

    // If there are uncached components and we're not in offline mode, fetch them
    if !uncached_positions.is_empty() {
        let queries: Vec<OsvQuery> = uncached_positions
            .iter()
            .map(|&pos| {
                let (_, comp, eco) = indexed[pos];
                OsvQuery {
                    package: OsvPackage {
                        name: comp.name.clone(),
                        ecosystem: eco.to_string(),
                    },
                    version: comp.version.clone().unwrap_or_default(),
                }
            })
            .collect();

        let body = OsvBatchRequest { queries };
        match fetch_osv_batch(&body) {
            Ok(response) => {
                // Write results back to cache and fill results vec
                for (batch_idx, pos) in uncached_positions.iter().enumerate() {
                    let (_, comp, eco) = indexed[*pos];
                    let version = comp.version.as_deref().unwrap_or("");
                    let key = cache_key(eco, &comp.name, version);
                    if batch_idx < response.results.len() {
                        let r = &response.results[batch_idx];
                        // Cache the raw result
                        if let Ok(v) = serde_json::to_value(r) {
                            if let Some(ref dir) = cache_dir {
                                write_cache(dir, &key, &v);
                            }
                        }
                        results[*pos] = Some(OsvResult {
                            vulns: r.vulns.clone(),
                        });
                    } else {
                        // No result for this position — cache empty
                        let empty = serde_json::json!({"vulns": []});
                        if let Some(ref dir) = cache_dir {
                            write_cache(dir, &key, &empty);
                        }
                        results[*pos] = Some(OsvResult { vulns: vec![] });
                    }
                }
            }
            Err(e) => {
                eprintln!("sigil: OSV offline — using cached data ({})", e);
                // Already have whatever cache provided; uncached positions yield None (no findings)
            }
        }
    } else if uncached_positions.is_empty()
        && results.iter().any(|r| r.is_none())
        && offline_hint
    {
        // offline_hint set and some positions have no cache
        eprintln!("sigil: OSV offline — no cached data for some packages");
    }

    // Flatten into (original_component_index, vuln) pairs
    let mut findings_pairs: Vec<(usize, OsvVuln)> = Vec::new();
    for (pos, result) in results.into_iter().enumerate() {
        if let Some(r) = result {
            let (comp_idx, _, _) = indexed[pos];
            for vuln in r.vulns {
                findings_pairs.push((comp_idx, vuln));
            }
        }
    }
    findings_pairs
}

// ── HTTP call (synchronous via reqwest blocking) ────────────────────────────

fn fetch_osv_batch(body: &OsvBatchRequest) -> Result<OsvBatchResponse, Box<dyn std::error::Error>> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    let response = client
        .post("https://api.osv.dev/v1/querybatch")
        .json(body)
        .send()?;

    if !response.status().is_success() {
        return Err(format!("OSV API returned {}", response.status()).into());
    }

    Ok(response.json::<OsvBatchResponse>()?)
}

// ── Convert OSV results to scanner Findings ─────────────────────────────────

/// Run OSV lookups for all components and convert matches to `Finding` objects.
///
/// The `lockfile_path` is used as the finding's `file` field so the source
/// context is clear in output.
pub fn osv_findings_for_components(
    components: &[Component],
    lockfile_path: &str,
) -> Vec<Finding> {
    let pairs = query_osv(components, false);
    pairs_to_findings(pairs, lockfile_path)
}

/// Same as `osv_findings_for_components` but skips the network entirely.
/// Used when the caller already knows the network is unavailable.
#[allow(dead_code)]
pub fn osv_findings_offline(components: &[Component], lockfile_path: &str) -> Vec<Finding> {
    let pairs = query_osv(components, true);
    pairs_to_findings(pairs, lockfile_path)
}

/// The `/v1/querybatch` endpoint returns advisory IDs only — no severity or
/// summary. Fetch the full record from `/v1/vulns/{id}` (cached per id) so
/// `osv_severity` has the `database_specific.severity` / CVSS vector to grade
/// against. Without this every finding falls through to the High default.
/// Network/parse failure returns the vuln unchanged (degrades to that default).
/// One keep-alive blocking client reused across every detail fetch. Building a
/// fresh `reqwest::blocking::Client` per request (the original code) spun up a
/// new tokio runtime + TLS handshake each time and was the dominant cost when a
/// lockfile produced hundreds of advisories.
fn detail_client() -> Option<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .pool_max_idle_per_host(8)
        .build()
        .ok()
}

fn enrich_vuln_detail(client: &reqwest::blocking::Client, vuln: OsvVuln) -> OsvVuln {
    // Already has gradeable severity info — nothing to fetch.
    if vuln.database_specific.is_some() || !vuln.severity.is_empty() {
        return vuln;
    }
    let dir = cache_dir();
    let key = format!("vuln-{}", vuln.id.replace(['/', '\\', ':'], "_"));
    if let Some(ref d) = dir {
        if let Some(v) = read_cache(d, &key) {
            if let Ok(detail) = serde_json::from_value::<OsvVuln>(v) {
                return detail;
            }
        }
    }
    match fetch_vuln_detail(client, &vuln.id) {
        Ok(detail) => {
            if let Some(ref d) = dir {
                if let Ok(v) = serde_json::to_value(&detail) {
                    write_cache(d, &key, &v);
                }
            }
            detail
        }
        Err(_) => vuln,
    }
}

fn fetch_vuln_detail(
    client: &reqwest::blocking::Client,
    id: &str,
) -> Result<OsvVuln, Box<dyn std::error::Error>> {
    let resp = client
        .get(format!("https://api.osv.dev/v1/vulns/{}", id))
        .send()?;
    if !resp.status().is_success() {
        return Err(format!("OSV vuln detail returned {}", resp.status()).into());
    }
    Ok(resp.json::<OsvVuln>()?)
}

fn pairs_to_findings(pairs: Vec<(usize, OsvVuln)>, lockfile_path: &str) -> Vec<Finding> {
    use rayon::prelude::*;
    use std::collections::{HashMap, HashSet};

    // Detail enrichment (one `/v1/vulns/{id}` round-trip per advisory) dominates
    // wall-clock on a cold cache. Sequential fetches made real-world lockfiles
    // (hundreds of advisories across hundreds of deps) effectively un-scannable —
    // a 798-dep lockfile did not finish in hours. Fix: dedup advisories by id so
    // an advisory affecting N components is fetched once (this also makes the
    // per-id cache writes collision-free), then fetch the unique set concurrently
    // through a shared keep-alive client on a bounded pool. MAL- ids are Critical
    // by prefix and need no detail fetch.
    let needs: Vec<OsvVuln> = {
        let mut seen = HashSet::new();
        pairs
            .iter()
            .filter(|(_, v)| {
                !v.id.starts_with("MAL-")
                    && v.database_specific.is_none()
                    && v.severity.is_empty()
            })
            .filter(|(_, v)| seen.insert(v.id.clone()))
            .map(|(_, v)| v.clone())
            .collect()
    };

    let detail_by_id: HashMap<String, OsvVuln> = if needs.is_empty() {
        HashMap::new()
    } else if let Some(client) = detail_client() {
        let enrich = || -> Vec<OsvVuln> {
            needs
                .into_par_iter()
                .map(|v| enrich_vuln_detail(&client, v))
                .collect()
        };
        // Bounded concurrency: independent fetches, but cap at 8 in-flight so we
        // stay a polite OSV client rather than opening one socket per advisory.
        let enriched = match rayon::ThreadPoolBuilder::new().num_threads(8).build() {
            Ok(pool) => pool.install(enrich),
            Err(_) => enrich(),
        };
        enriched.into_iter().map(|v| (v.id.clone(), v)).collect()
    } else {
        HashMap::new()
    };

    pairs
        .into_iter()
        .map(|(_idx, vuln)| {
            let vuln = detail_by_id.get(&vuln.id).cloned().unwrap_or(vuln);
            let sev = osv_severity(&vuln);
            let weight = match sev {
                Severity::Critical => 10,
                Severity::High => 5,
                Severity::Medium => 2,
                Severity::Low => 1,
            };
            let summary = vuln
                .summary
                .as_deref()
                .unwrap_or("known vulnerability in dependency")
                .to_string();
            Finding {
                phase: Phase::Provenance,
                rule: vuln.id.clone(),
                severity: sev,
                file: lockfile_path.to_string(),
                line: None,
                snippet: summary,
                weight,
                kev: false,
                epss: 0.0,
            }
        })
        .collect()
}

// ── Public scan entrypoint ──────────────────────────────────────────────────

/// Walk `path` for lockfiles, parse components, query OSV, return findings.
///
/// This is the top-level function called by `run_scan` integration.
/// It never panics: errors from individual lockfile parsing or network issues
/// are handled gracefully.
///
/// Uses the same `WalkBuilder` configuration as the main scanner, including
/// `.sigilignore` support, so first-party detection-engine files that embed
/// vulnerable patterns as test data are not flagged.
pub fn scan_for_osv_findings(path: &Path) -> Vec<Finding> {
    use crate::sbom::parsers;
    use ignore::WalkBuilder;

    let lockfile_names = [
        "package-lock.json",
        "requirements.txt",
        "Cargo.lock",
        "go.mod",
    ];

    const EXCLUDED_DIRS: &[&str] = &[
        "node_modules",
        ".git",
        "target",
        "dist",
        "build",
        ".next",
        "__pycache__",
        ".venv",
        "venv",
    ];

    let mut all_findings = Vec::new();

    let mut builder = WalkBuilder::new(path);
    builder
        .follow_links(false)
        .hidden(false)
        .git_ignore(true)
        .require_git(true)
        .git_global(false)
        .git_exclude(false)
        .ignore(false)
        .parents(false)
        .add_custom_ignore_filename(".sigilignore");
    builder.filter_entry(|entry| {
        let is_dir = entry.file_type().map_or(false, |t| t.is_dir());
        if !is_dir {
            return true;
        }
        let name = entry.file_name().to_string_lossy();
        !EXCLUDED_DIRS.contains(&name.as_ref())
    });

    for entry in builder.build().filter_map(|e| e.ok()) {
        let file_path = entry.path();
        let file_name = match file_path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };

        if !lockfile_names.contains(&file_name) {
            continue;
        }

        let components: Vec<Component> = match file_name {
            "package-lock.json" => match parsers::parse_package_lock(file_path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!(
                        "sigil: OSV: failed to parse {}: {}",
                        file_path.display(),
                        e
                    );
                    continue;
                }
            },
            "requirements.txt" => match parsers::parse_requirements_txt(file_path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!(
                        "sigil: OSV: failed to parse {}: {}",
                        file_path.display(),
                        e
                    );
                    continue;
                }
            },
            "Cargo.lock" => match parsers::parse_cargo_lock(file_path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!(
                        "sigil: OSV: failed to parse {}: {}",
                        file_path.display(),
                        e
                    );
                    continue;
                }
            },
            "go.mod" => match parse_go_mod(file_path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!(
                        "sigil: OSV: failed to parse {}: {}",
                        file_path.display(),
                        e
                    );
                    continue;
                }
            },
            _ => continue,
        };

        if components.is_empty() {
            continue;
        }

        let lockfile_rel = file_path
            .strip_prefix(path)
            .unwrap_or(file_path)
            .to_string_lossy()
            .to_string();

        let findings = osv_findings_for_components(&components, &lockfile_rel);
        all_findings.extend(findings);
    }

    all_findings
}

// ── go.mod parser ───────────────────────────────────────────────────────────

/// Minimal `go.mod` parser — extracts `require` directives.
pub fn parse_go_mod(path: &Path) -> Result<Vec<Component>, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    let mut components = Vec::new();
    let mut in_require_block = false;

    for line in content.lines() {
        let line = line.trim();
        if line.starts_with("require (") || line == "require (" {
            in_require_block = true;
            continue;
        }
        if in_require_block && line == ")" {
            in_require_block = false;
            continue;
        }
        if line.starts_with("require ") && !line.ends_with('(') {
            // Single-line require: `require example.com/foo v1.2.3`
            let rest = &line["require ".len()..];
            if let Some(comp) = parse_go_require_line(rest) {
                components.push(comp);
            }
            continue;
        }
        if in_require_block && !line.is_empty() && !line.starts_with("//") {
            if let Some(comp) = parse_go_require_line(line) {
                components.push(comp);
            }
        }
    }

    Ok(components)
}

fn parse_go_require_line(line: &str) -> Option<Component> {
    // Strip inline comments
    let line = line.split("//").next()?.trim();
    if line.is_empty() {
        return None;
    }
    // Format: `module/path vX.Y.Z` or `module/path vX.Y.Z // indirect`
    let mut parts = line.split_whitespace();
    let name = parts.next()?.to_string();
    let version = parts.next().map(String::from);
    if name.is_empty() {
        return None;
    }
    Some(Component {
        package_type: "go".to_string(),
        name,
        version,
        hash: None,
        threat_flagged: false,
        threat_severity: None,
        threat_description: None,
    })
}

// ── Serialization helpers for OsvResult (needed for cache round-trip) ───────

impl Serialize for OsvResult {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = s.serialize_struct("OsvResult", 1)?;
        st.serialize_field("vulns", &self.vulns)?;
        st.end()
    }
}

impl Serialize for OsvVuln {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = s.serialize_struct("OsvVuln", 4)?;
        st.serialize_field("id", &self.id)?;
        st.serialize_field("severity", &self.severity)?;
        st.serialize_field("database_specific", &self.database_specific)?;
        st.serialize_field("summary", &self.summary)?;
        st.end()
    }
}

impl Serialize for OsvSeverity {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = s.serialize_struct("OsvSeverity", 2)?;
        st.serialize_field("type", &self.severity_type)?;
        st.serialize_field("score", &self.score)?;
        st.end()
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sbom::Component;

    fn make_component(package_type: &str, name: &str, version: &str) -> Component {
        Component {
            package_type: package_type.to_string(),
            name: name.to_string(),
            version: Some(version.to_string()),
            hash: None,
            threat_flagged: false,
            threat_severity: None,
            threat_description: None,
        }
    }

    fn make_vuln(id: &str, db_severity: Option<&str>) -> OsvVuln {
        let database_specific = db_severity.map(|s| {
            serde_json::json!({ "severity": s })
        });
        OsvVuln {
            id: id.to_string(),
            severity: vec![],
            database_specific,
            summary: Some(format!("Test vuln {}", id)),
        }
    }

    // ── Positive tests: known-vuln correctly classified ──────────────────

    #[test]
    fn osv_severity_mal_prefix_is_critical() {
        let vuln = make_vuln("MAL-2023-1234", None);
        assert_eq!(osv_severity(&vuln), Severity::Critical);
    }

    #[test]
    fn osv_severity_ghsa_with_db_critical() {
        let vuln = make_vuln("GHSA-xxxx-yyyy-zzzz", Some("CRITICAL"));
        assert_eq!(osv_severity(&vuln), Severity::Critical);
    }

    #[test]
    fn osv_severity_ghsa_with_db_high() {
        let vuln = make_vuln("GHSA-xxxx-yyyy-zzzz", Some("HIGH"));
        assert_eq!(osv_severity(&vuln), Severity::High);
    }

    #[test]
    fn osv_severity_cve_no_db_severity_defaults_high() {
        let vuln = make_vuln("CVE-2023-12345", None);
        assert_eq!(osv_severity(&vuln), Severity::High);
    }

    #[test]
    fn osv_severity_ghsa_medium() {
        let vuln = make_vuln("GHSA-xxxx-yyyy-zzzz", Some("MEDIUM"));
        assert_eq!(osv_severity(&vuln), Severity::Medium);
    }

    #[test]
    fn osv_severity_github_moderate_is_medium_not_high() {
        // Regression: GitHub advisories say MODERATE, not MEDIUM. This was
        // mapped to High, which over-rated moderate dep CVEs and tripped the
        // self-scan high gate (e.g. postcss GHSA-qx2v-qp2m-jg93).
        let vuln = make_vuln("GHSA-qx2v-qp2m-jg93", Some("MODERATE"));
        assert_eq!(osv_severity(&vuln), Severity::Medium);
    }

    #[test]
    fn cvss3_score_postcss_moderate_vector() {
        // The real postcss advisory vector → 6.1 → Medium.
        let s = cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
        let v = s.expect("parseable");
        assert!((v - 6.1).abs() < 0.05, "expected ~6.1, got {v}");
        assert_eq!(severity_from_cvss_score(v), Severity::Medium);
    }

    #[test]
    fn cvss3_score_critical_vector() {
        // AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8 → Critical (e.g. log4shell-class).
        let v = cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").unwrap();
        assert!((v - 9.8).abs() < 0.05, "expected ~9.8, got {v}");
        assert_eq!(severity_from_cvss_score(v), Severity::Critical);
    }

    #[test]
    fn cvss3_score_via_severity_array_when_no_label() {
        // A CVE record with only a CVSS vector (no database_specific.severity)
        // must derive Medium, not fall through to the High default.
        let vuln = OsvVuln {
            id: "CVE-2026-41305".to_string(),
            severity: vec![OsvSeverity {
                severity_type: "CVSS_V3".to_string(),
                score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N".to_string(),
            }],
            database_specific: None,
            summary: None,
        };
        assert_eq!(osv_severity(&vuln), Severity::Medium);
    }

    #[test]
    fn cvss3_score_rejects_non_cvss() {
        assert_eq!(cvss3_base_score("not-a-vector"), None);
    }

    // ── Negative tests: clean/no-finding scenarios ───────────────────────

    #[test]
    fn osv_no_ecosystem_for_unknown_package_type() {
        // An unrecognized package_type should be filtered out (no ecosystem mapping)
        assert_eq!(ecosystem_for("gem"), None);
        assert_eq!(ecosystem_for("nuget"), None);
        assert_eq!(ecosystem_for("unknown"), None);
    }

    #[test]
    fn osv_component_without_version_is_skipped() {
        let comp = Component {
            package_type: "pip".to_string(),
            name: "requests".to_string(),
            version: None, // no version → cannot query OSV
            hash: None,
            threat_flagged: false,
            threat_severity: None,
            threat_description: None,
        };
        // query_osv in offline mode with no cache → no findings
        let result = query_osv(&[comp], true);
        assert!(
            result.is_empty(),
            "component without version must produce no findings"
        );
    }

    #[test]
    fn osv_pairs_to_findings_maps_correctly() {
        let vuln = make_vuln("GHSA-test-0001", Some("HIGH"));
        let pairs = vec![(0usize, vuln)];
        let findings = pairs_to_findings(pairs, "requirements.txt");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "GHSA-test-0001");
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].file, "requirements.txt");
        assert_eq!(findings[0].phase, Phase::Provenance);
    }

    #[test]
    fn osv_mal_finding_has_critical_severity_and_weight_10() {
        let vuln = make_vuln("MAL-2024-9999", None);
        let pairs = vec![(0usize, vuln)];
        let findings = pairs_to_findings(pairs, "package-lock.json");
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].weight, 10);
    }

    // ── go.mod parser ─────────────────────────────────────────────────────

    #[test]
    fn go_mod_parse_block_require() {
        let content = r#"
module example.com/app

go 1.21

require (
    github.com/pkg/errors v0.9.1
    golang.org/x/text v0.14.0
)
"#;
        let tmpdir = tempfile::tempdir().unwrap();
        let gomod = tmpdir.path().join("go.mod");
        std::fs::write(&gomod, content).unwrap();
        let comps = parse_go_mod(&gomod).unwrap();
        assert_eq!(comps.len(), 2);
        assert_eq!(comps[0].name, "github.com/pkg/errors");
        assert_eq!(comps[0].version.as_deref(), Some("v0.9.1"));
        assert_eq!(comps[0].package_type, "go");
        assert_eq!(comps[1].name, "golang.org/x/text");
    }

    #[test]
    fn go_mod_parse_single_require() {
        let content = "module ex.com/a\ngo 1.21\nrequire github.com/foo/bar v1.2.3\n";
        let tmpdir = tempfile::tempdir().unwrap();
        let gomod = tmpdir.path().join("go.mod");
        std::fs::write(&gomod, content).unwrap();
        let comps = parse_go_mod(&gomod).unwrap();
        assert_eq!(comps.len(), 1);
        assert_eq!(comps[0].name, "github.com/foo/bar");
        assert_eq!(comps[0].version.as_deref(), Some("v1.2.3"));
    }

    #[test]
    fn go_mod_empty_file_returns_no_components() {
        let content = "module ex.com/a\ngo 1.21\n";
        let tmpdir = tempfile::tempdir().unwrap();
        let gomod = tmpdir.path().join("go.mod");
        std::fs::write(&gomod, content).unwrap();
        let comps = parse_go_mod(&gomod).unwrap();
        assert!(comps.is_empty());
    }

    // ── Cache round-trip ──────────────────────────────────────────────────

    #[test]
    fn cache_key_sanitizes_slashes() {
        // go module paths contain slashes — must not create subdirectories
        let key = cache_key("Go", "github.com/foo/bar", "v1.0.0");
        assert!(!key.contains('/'), "cache key must not contain path separators");
    }

    #[test]
    fn cache_round_trip() {
        let tmpdir = tempfile::tempdir().unwrap();
        let dir = tmpdir.path();
        let key = "test-key";
        let value = serde_json::json!({"vulns": [{"id": "CVE-2023-0001"}]});
        write_cache(dir, key, &value);
        let loaded = read_cache(dir, key);
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap(), value);
    }
}
