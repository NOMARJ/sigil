//! KEV/EPSS prioritization overlay for OSV-derived findings (US-E2).
//!
//! Two data sources are used as **best-effort overlays** — neither is required
//! for a successful scan:
//!
//! * **CISA KEV** (`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`)
//!   A static JSON catalogue of vulnerabilities known to be actively exploited in the wild.
//!   Matched CVE IDs set `finding.kev = true`.
//!
//! * **FIRST EPSS** (`https://api.first.org/data/v1/epss?cve=CVE-XXXX`)
//!   Exploit Prediction Scoring System — a 0.0–1.0 probability that a CVE will be exploited.
//!   Matched CVE IDs set `finding.epss` to the returned score.
//!
//! Both feeds are cached. Network failures are treated as "no enrichment available"
//! and never abort the scan.

use crate::scanner::Finding;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

// ── Cache helpers ─────────────────────────────────────────────────────────────

fn enrichment_cache_dir() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".sigil").join("enrichment-cache"))
}

fn read_bytes_cache(dir: &Path, key: &str) -> Option<Vec<u8>> {
    std::fs::read(dir.join(format!("{}.json", key))).ok()
}

fn write_bytes_cache(dir: &Path, key: &str, data: &[u8]) {
    let _ = std::fs::create_dir_all(dir);
    let _ = std::fs::write(dir.join(format!("{}.json", key)), data);
}

// ── CISA KEV feed ─────────────────────────────────────────────────────────────

/// Minimal deserialization of the CISA KEV JSON catalogue.
#[derive(Debug, Deserialize)]
struct KevCatalog {
    vulnerabilities: Vec<KevEntry>,
}

#[derive(Debug, Deserialize)]
struct KevEntry {
    #[serde(rename = "cveID")]
    cve_id: String,
}

const KEV_CACHE_KEY: &str = "cisa-kev";
const KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

/// Load the KEV catalogue from cache, fetching from the network if stale.
///
/// On network failure, returns whatever is cached. If no cache exists, returns
/// an empty set (non-fatal: enrichment simply does not apply).
pub fn load_kev_set(fixture_path: Option<&Path>) -> HashSet<String> {
    // Tests can inject a fixture file path to avoid network calls.
    if let Some(path) = fixture_path {
        return parse_kev_from_bytes(&std::fs::read(path).unwrap_or_default());
    }

    let cache_dir = match enrichment_cache_dir() {
        Some(d) => d,
        None => return HashSet::new(),
    };

    // Try network first; fall back to cache.
    match fetch_bytes(KEV_URL) {
        Ok(bytes) => {
            write_bytes_cache(&cache_dir, KEV_CACHE_KEY, &bytes);
            parse_kev_from_bytes(&bytes)
        }
        Err(e) => {
            eprintln!("sigil: KEV offline — using cached data ({})", e);
            let cached = read_bytes_cache(&cache_dir, KEV_CACHE_KEY).unwrap_or_default();
            parse_kev_from_bytes(&cached)
        }
    }
}

fn parse_kev_from_bytes(bytes: &[u8]) -> HashSet<String> {
    if bytes.is_empty() {
        return HashSet::new();
    }
    match serde_json::from_slice::<KevCatalog>(bytes) {
        Ok(catalog) => catalog
            .vulnerabilities
            .into_iter()
            .map(|e| e.cve_id)
            .collect(),
        Err(e) => {
            eprintln!("sigil: failed to parse KEV feed: {}", e);
            HashSet::new()
        }
    }
}

// ── FIRST EPSS feed ───────────────────────────────────────────────────────────

/// Minimal deserialization of the FIRST EPSS JSON response.
#[derive(Debug, Deserialize)]
struct EpssResponse {
    data: Vec<EpssEntry>,
}

#[derive(Debug, Deserialize)]
struct EpssEntry {
    cve: String,
    epss: String,
}

const EPSS_BASE_URL: &str = "https://api.first.org/data/v1/epss";

/// Load EPSS scores for a batch of CVE IDs.
///
/// Returns a map of CVE ID → score (0.0–1.0).
/// On network failure, returns whatever is cached, or empty map.
pub fn load_epss_scores(cve_ids: &[&str], fixture_path: Option<&Path>) -> HashMap<String, f32> {
    // Tests can inject a fixture file path — check before the empty-list short-circuit
    // so that fixture-based tests don't need to provide CVE IDs.
    if let Some(path) = fixture_path {
        return parse_epss_from_bytes(&std::fs::read(path).unwrap_or_default());
    }

    if cve_ids.is_empty() {
        return HashMap::new();
    }

    let cache_dir = match enrichment_cache_dir() {
        Some(d) => d,
        None => return HashMap::new(),
    };

    // Build a stable cache key from the sorted CVE list.
    let mut sorted = cve_ids.to_vec();
    sorted.sort_unstable();
    let cache_key = format!("epss-{}", &sha256_hex(sorted.join(",").as_bytes())[..16]);

    // Batch query: comma-separated CVE IDs.
    let url = format!("{}?cve={}", EPSS_BASE_URL, sorted.join(","));

    match fetch_bytes(&url) {
        Ok(bytes) => {
            write_bytes_cache(&cache_dir, &cache_key, &bytes);
            parse_epss_from_bytes(&bytes)
        }
        Err(e) => {
            eprintln!("sigil: EPSS offline — using cached data ({})", e);
            let cached = read_bytes_cache(&cache_dir, &cache_key).unwrap_or_default();
            parse_epss_from_bytes(&cached)
        }
    }
}

fn parse_epss_from_bytes(bytes: &[u8]) -> HashMap<String, f32> {
    if bytes.is_empty() {
        return HashMap::new();
    }
    match serde_json::from_slice::<EpssResponse>(bytes) {
        Ok(resp) => resp
            .data
            .into_iter()
            .filter_map(|e| {
                let score = e.epss.parse::<f32>().ok()?;
                Some((e.cve, score))
            })
            .collect(),
        Err(e) => {
            eprintln!("sigil: failed to parse EPSS response: {}", e);
            HashMap::new()
        }
    }
}

// ── HTTP helper ───────────────────────────────────────────────────────────────

fn fetch_bytes(url: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()?;
    let response = client.get(url).send()?;
    if !response.status().is_success() {
        return Err(format!("HTTP {}", response.status()).into());
    }
    Ok(response.bytes()?.to_vec())
}

// ── SHA-256 helper (no new dep — reuse sha2 already in Cargo.toml) ────────────

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::new().chain_update(data).finalize())
}

// ── Public enrichment entrypoint ─────────────────────────────────────────────

/// Enrich OSV-derived findings with KEV and EPSS data.
///
/// Modifies findings **in place**: sets `kev = true` for CVE IDs in the CISA
/// catalogue, and sets `epss` to the FIRST probability score when available.
///
/// `kev_fixture` and `epss_fixture` allow tests to inject recorded JSON
/// responses instead of hitting the network.
pub fn enrich_findings_with_kev_epss(
    findings: &mut [Finding],
    kev_fixture: Option<&Path>,
    epss_fixture: Option<&Path>,
) {
    // Collect CVE IDs present in findings.
    let cve_ids: Vec<&str> = findings
        .iter()
        .map(|f| f.rule.as_str())
        .filter(|id| id.starts_with("CVE-"))
        .collect();

    if cve_ids.is_empty() && kev_fixture.is_none() {
        // Nothing to enrich.
        return;
    }

    let kev_set = load_kev_set(kev_fixture);
    let epss_map = load_epss_scores(&cve_ids, epss_fixture);

    for finding in findings.iter_mut() {
        if finding.rule.starts_with("CVE-") {
            if kev_set.contains(&finding.rule) {
                finding.kev = true;
            }
            if let Some(&score) = epss_map.get(&finding.rule) {
                finding.epss = score;
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{Finding, Phase, Severity};

    fn kev_fixture_path() -> std::path::PathBuf {
        // Path relative to workspace root — tests run from cli/ directory.
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("tests/fixtures/kev-epss/kev_subset.json")
    }

    fn epss_fixture_path() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("tests/fixtures/kev-epss/epss_subset.json")
    }

    fn make_cve_finding(cve: &str) -> Finding {
        Finding {
            phase: Phase::Provenance,
            rule: cve.to_string(),
            severity: Severity::High,
            file: "requirements.txt".to_string(),
            line: None,
            snippet: "known vulnerability in dependency".to_string(),
            weight: 5,
            kev: false,
            epss: 0.0,
        }
    }

    // ── Positive tests ────────────────────────────────────────────────────

    #[test]
    fn kev_fixture_parses_correctly() {
        let kev_set = load_kev_set(Some(&kev_fixture_path()));
        assert!(
            kev_set.contains("CVE-2023-32681"),
            "CVE-2023-32681 must be in KEV fixture"
        );
        assert!(
            kev_set.contains("CVE-2021-44228"),
            "CVE-2021-44228 (Log4Shell) must be in KEV fixture"
        );
        assert_eq!(kev_set.len(), 3);
    }

    #[test]
    fn epss_fixture_parses_correctly() {
        let epss_map = load_epss_scores(&[], Some(&epss_fixture_path()));
        assert!(
            epss_map.contains_key("CVE-2021-44228"),
            "CVE-2021-44228 must have an EPSS score"
        );
        let log4j_score = epss_map["CVE-2021-44228"];
        assert!(
            (log4j_score - 0.97565_f32).abs() < 0.001,
            "Log4Shell EPSS score should be ~0.97565, got {}",
            log4j_score
        );
    }

    #[test]
    fn kev_flag_set_on_known_exploited_cve() {
        let mut findings = vec![make_cve_finding("CVE-2023-32681")];
        enrich_findings_with_kev_epss(
            &mut findings,
            Some(&kev_fixture_path()),
            Some(&epss_fixture_path()),
        );
        assert!(
            findings[0].kev,
            "CVE-2023-32681 is in CISA KEV — kev must be true"
        );
    }

    #[test]
    fn epss_score_attached_to_cve_finding() {
        let mut findings = vec![make_cve_finding("CVE-2021-44228")];
        enrich_findings_with_kev_epss(
            &mut findings,
            Some(&kev_fixture_path()),
            Some(&epss_fixture_path()),
        );
        let score = findings[0].epss;
        assert!(
            score > 0.9,
            "Log4Shell EPSS score must be >0.9, got {}",
            score
        );
    }

    #[test]
    fn both_kev_and_epss_applied_to_same_finding() {
        let mut findings = vec![make_cve_finding("CVE-2023-32681")];
        enrich_findings_with_kev_epss(
            &mut findings,
            Some(&kev_fixture_path()),
            Some(&epss_fixture_path()),
        );
        assert!(findings[0].kev, "kev must be true for CVE-2023-32681");
        assert!(
            findings[0].epss > 0.0,
            "epss must be set for CVE-2023-32681"
        );
    }

    // ── Negative tests ────────────────────────────────────────────────────

    #[test]
    fn non_cve_finding_not_modified() {
        let mut findings = vec![Finding {
            phase: Phase::Provenance,
            rule: "GHSA-xxxx-yyyy-zzzz".to_string(),
            severity: Severity::High,
            file: "package-lock.json".to_string(),
            line: None,
            snippet: "known vulnerability".to_string(),
            weight: 5,
            kev: false,
            epss: 0.0,
        }];
        enrich_findings_with_kev_epss(
            &mut findings,
            Some(&kev_fixture_path()),
            Some(&epss_fixture_path()),
        );
        assert!(!findings[0].kev, "GHSA ID must not be KEV-flagged");
        assert_eq!(findings[0].epss, 0.0, "GHSA ID must have no EPSS score");
    }

    #[test]
    fn unknown_cve_not_in_kev_stays_false() {
        let mut findings = vec![make_cve_finding("CVE-9999-00000")];
        enrich_findings_with_kev_epss(
            &mut findings,
            Some(&kev_fixture_path()),
            Some(&epss_fixture_path()),
        );
        assert!(!findings[0].kev, "unknown CVE must not be marked KEV");
        assert_eq!(findings[0].epss, 0.0, "unknown CVE must have no EPSS score");
    }

    #[test]
    fn empty_findings_produces_no_panic() {
        let mut findings: Vec<Finding> = vec![];
        enrich_findings_with_kev_epss(
            &mut findings,
            Some(&kev_fixture_path()),
            Some(&epss_fixture_path()),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn empty_kev_bytes_returns_empty_set() {
        let set = parse_kev_from_bytes(&[]);
        assert!(set.is_empty());
    }

    #[test]
    fn empty_epss_bytes_returns_empty_map() {
        let map = parse_epss_from_bytes(&[]);
        assert!(map.is_empty());
    }
}
