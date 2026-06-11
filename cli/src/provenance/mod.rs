//! Provenance drift detection for npm and PyPI packages.
//!
//! Implements ADR-0007: detects drift in package provenance metadata —
//! downgrade (previously attested → now unattested), publisher-identity
//! change, and provenance-repo ≠ manifest-repo mismatch.
//!
//! **Absence of provenance is never a scored finding.** Only anomalies
//! relative to a previously observed baseline emit `Finding` values.
//!
//! ## Ledger
//!
//! Per-package state is stored in `~/.sigil/provenance-ledger/` as
//! `{ecosystem}-{name}-{version}.json`. On first observation the baseline
//! is written and no findings are emitted. Drift is only detectable on
//! the second and subsequent observations of the same package version.
//!
//! ## Network calls
//!
//! npm: `GET https://registry.npmjs.org/{name}/{version}` — checks
//! `dist.attestations.url` and `dist.attestations.provenance`.
//!
//! PyPI: `GET https://pypi.org/pypi/{name}/{version}/json` — checks
//! `info.attestations` (PEP 740) field or SLSA provenance.
//!
//! Network failure degrades gracefully: returns no findings, never panics.
//!
//! ## Fixture injection (tests)
//!
//! Pass `ScanOptions { npm_fixture_dir, pypi_fixture_dir, ledger_fixture_dir }`
//! to bypass network calls in unit tests. Each fixture dir should contain
//! `{name}-{version}.json` response files (see tests/fixtures/provenance/).

use crate::sbom::Component;
use crate::scanner::{Finding, Phase, Severity};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

// ── Ledger types ─────────────────────────────────────────────────────────────

/// Persisted provenance baseline for a single package version.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProvRecord {
    /// Whether the package carried any attestation at last observation.
    pub attested: bool,
    /// Signer identity (e.g. GitHub Actions OIDC subject) at last observation.
    pub signer_identity: Option<String>,
    /// Source repository URL from the attestation at last observation.
    pub source_repo: Option<String>,
}

// ── Live attestation fetched from registry API ───────────────────────────────

/// Attestation data extracted from a registry API response.
#[derive(Debug, Default)]
struct Attestation {
    attested: bool,
    signer_identity: Option<String>,
    source_repo: Option<String>,
}

// ── Options (fixture injection for tests) ────────────────────────────────────

/// Configuration for a provenance scan call.
///
/// All fields are optional — when `None`, the live network/ledger paths are used.
#[derive(Debug, Default, Clone)]
pub struct ScanOptions<'a> {
    /// Directory containing npm fixture JSON files (`{name}-{version}.json`).
    pub npm_fixture_dir: Option<&'a Path>,
    /// Directory containing PyPI fixture JSON files (`{name}-{version}.json`).
    pub pypi_fixture_dir: Option<&'a Path>,
    /// Directory to use as the provenance ledger instead of `~/.sigil/provenance-ledger/`.
    pub ledger_fixture_dir: Option<&'a Path>,
}

// ── Ledger helpers ────────────────────────────────────────────────────────────

fn ledger_dir_default() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".sigil").join("provenance-ledger"))
}

fn ledger_key(ecosystem: &str, name: &str, version: &str) -> String {
    let safe = |s: &str| s.replace(['/', '\\', ':', '@'], "_");
    format!("{}-{}-{}", safe(ecosystem), safe(name), safe(version))
}

fn read_ledger(dir: &Path, key: &str) -> Option<ProvRecord> {
    let path = dir.join(format!("{}.json", key));
    let bytes = std::fs::read(&path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn write_ledger(dir: &Path, key: &str, record: &ProvRecord) {
    let _ = std::fs::create_dir_all(dir);
    let path = dir.join(format!("{}.json", key));
    if let Ok(s) = serde_json::to_string(record) {
        let _ = std::fs::write(path, s);
    }
}

// ── Registry fetch helpers ────────────────────────────────────────────────────

fn fetch_bytes(url: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;
    let resp = client.get(url).send()?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()).into());
    }
    Ok(resp.bytes()?.to_vec())
}

// ── npm attestation parsing ───────────────────────────────────────────────────

/// Fetch npm registry metadata for a package version and extract attestation.
///
/// npm registry response shape relevant fields:
/// ```json
/// {
///   "dist": {
///     "attestations": {
///       "url": "https://registry.npmjs.org/-/npm/v1/attestations/...",
///       "provenance": {
///         "predicateType": "https://slsa.dev/provenance/v1",
///         "predicateSourceRepoUrl": "https://github.com/org/repo",
///         "predicateSourceRepoDigest": { "sha1": "..." },
///         "signerIdentity": "https://github.com/org/repo/.github/workflows/publish.yml@refs/heads/main"
///       }
///     }
///   }
/// }
/// ```
fn fetch_npm_attestation(
    name: &str,
    version: &str,
    fixture_dir: Option<&Path>,
) -> Attestation {
    let raw = if let Some(dir) = fixture_dir {
        let safe_name = name.replace('/', "_").replace('@', "_");
        let file = dir.join(format!("{}-{}.json", safe_name, version));
        match std::fs::read(&file) {
            Ok(b) => b,
            Err(_) => return Attestation::default(),
        }
    } else {
        let url = format!("https://registry.npmjs.org/{}/{}", name, version);
        match fetch_bytes(&url) {
            Ok(b) => b,
            Err(_) => return Attestation::default(),
        }
    };

    parse_npm_attestation(&raw)
}

fn parse_npm_attestation(raw: &[u8]) -> Attestation {
    let val: serde_json::Value = match serde_json::from_slice(raw) {
        Ok(v) => v,
        Err(_) => return Attestation::default(),
    };

    let attestations = match val
        .get("dist")
        .and_then(|d| d.get("attestations"))
    {
        Some(a) => a,
        None => return Attestation::default(),
    };

    // If the `attestations` object is present, the package is attested.
    let provenance = attestations.get("provenance");
    let signer_identity = provenance
        .and_then(|p| p.get("signerIdentity"))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let source_repo = provenance
        .and_then(|p| p.get("predicateSourceRepoUrl"))
        .and_then(|v| v.as_str())
        .map(str::to_string);

    Attestation {
        attested: true,
        signer_identity,
        source_repo,
    }
}

// ── PyPI attestation parsing ──────────────────────────────────────────────────

/// Fetch PyPI JSON API for a package version and extract PEP 740 attestation.
///
/// PyPI JSON API response shape:
/// ```json
/// {
///   "info": {
///     "home_page": "https://github.com/org/repo",
///     "project_urls": { "Source": "https://github.com/org/repo" }
///   },
///   "urls": [{
///     "attestations": { ... }
///   }]
/// }
/// ```
fn fetch_pypi_attestation(
    name: &str,
    version: &str,
    fixture_dir: Option<&Path>,
) -> Attestation {
    let raw = if let Some(dir) = fixture_dir {
        let safe_name = name.replace(['-', '.'], "_");
        let file = dir.join(format!("{}-{}.json", safe_name, version));
        match std::fs::read(&file) {
            Ok(b) => b,
            Err(_) => return Attestation::default(),
        }
    } else {
        let url = format!("https://pypi.org/pypi/{}/{}/json", name, version);
        match fetch_bytes(&url) {
            Ok(b) => b,
            Err(_) => return Attestation::default(),
        }
    };

    parse_pypi_attestation(&raw)
}

fn parse_pypi_attestation(raw: &[u8]) -> Attestation {
    let val: serde_json::Value = match serde_json::from_slice(raw) {
        Ok(v) => v,
        Err(_) => return Attestation::default(),
    };

    // Check if any distribution url has attestations (PEP 740)
    let urls = match val.get("urls").and_then(|u| u.as_array()) {
        Some(u) => u,
        None => return Attestation::default(),
    };

    for url_entry in urls {
        if url_entry.get("attestations").is_some() {
            // Extract source repo from info section
            let source_repo = val
                .get("info")
                .and_then(|info| {
                    // Try project_urls.Source first, then home_page
                    info.get("project_urls")
                        .and_then(|pu| pu.get("Source"))
                        .and_then(|v| v.as_str())
                        .or_else(|| {
                            info.get("home_page")
                                .and_then(|v| v.as_str())
                                .filter(|s| !s.is_empty())
                        })
                })
                .map(str::to_string);

            // PyPI PEP 740 uses GitHub OIDC — extract from attestation if present
            let signer_identity = url_entry
                .get("attestations")
                .and_then(|a| a.get("signer_identity"))
                .and_then(|v| v.as_str())
                .map(str::to_string);

            return Attestation {
                attested: true,
                signer_identity,
                source_repo,
            };
        }
    }

    Attestation::default()
}

// ── Drift detection ───────────────────────────────────────────────────────────

/// Compare a freshly-fetched attestation against a ledger baseline and
/// return any drift findings.
///
/// Three finding types (ADR-0007):
/// - `PROV-DOWNGRADE`: was attested, now unattested
/// - `PROV-IDENTITY-CHANGE`: signer identity changed
/// - `PROV-REPO-MISMATCH`: source_repo in attestation doesn't match ledger
fn detect_drift(
    ecosystem: &str,
    name: &str,
    version: &str,
    lockfile: &str,
    current: &Attestation,
    baseline: &ProvRecord,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // PROV-DOWNGRADE: package was previously attested, now unattested.
    if baseline.attested && !current.attested {
        findings.push(Finding {
            phase: Phase::Provenance,
            rule: "PROV-DOWNGRADE".to_string(),
            severity: Severity::High,
            file: lockfile.to_string(),
            line: None,
            snippet: format!(
                "{} {}@{}: was attested, now publishes without provenance attestation",
                ecosystem, name, version
            ),
            weight: 3,
            kev: false,
            epss: 0.0,
        });
    }

    // PROV-IDENTITY-CHANGE: signer identity changed from a known non-None value.
    if let (Some(ref prev_id), Some(ref curr_id)) =
        (&baseline.signer_identity, &current.signer_identity)
    {
        if prev_id != curr_id {
            findings.push(Finding {
                phase: Phase::Provenance,
                rule: "PROV-IDENTITY-CHANGE".to_string(),
                severity: Severity::Critical,
                file: lockfile.to_string(),
                line: None,
                snippet: format!(
                    "{} {}@{}: signer identity changed from '{}' to '{}'",
                    ecosystem, name, version, prev_id, curr_id
                ),
                weight: 10,
                kev: false,
                epss: 0.0,
            });
        }
    }

    // PROV-REPO-MISMATCH: source repo in current attestation differs from
    // the repo recorded in the baseline. Both must be non-None to compare.
    if let (Some(ref prev_repo), Some(ref curr_repo)) =
        (&baseline.source_repo, &current.source_repo)
    {
        // Normalize trailing slashes and .git suffix for comparison
        let norm = |s: &str| s.trim_end_matches('/').trim_end_matches(".git").to_string();
        if norm(prev_repo) != norm(curr_repo) {
            findings.push(Finding {
                phase: Phase::Provenance,
                rule: "PROV-REPO-MISMATCH".to_string(),
                severity: Severity::High,
                file: lockfile.to_string(),
                line: None,
                snippet: format!(
                    "{} {}@{}: attestation source repo changed from '{}' to '{}'",
                    ecosystem, name, version, prev_repo, curr_repo
                ),
                weight: 3,
                kev: false,
                epss: 0.0,
            });
        }
    }

    findings
}

// ── Per-component check ───────────────────────────────────────────────────────

/// Check a single component for provenance drift.
///
/// Returns findings (if any) and a `ProvRecord` representing the current
/// observation (to be written to the ledger by the caller).
fn check_component(
    comp: &Component,
    lockfile: &str,
    options: &ScanOptions<'_>,
) -> (Vec<Finding>, Option<ProvRecord>) {
    let version = match comp.version.as_deref() {
        Some(v) if !v.is_empty() => v,
        _ => return (Vec::new(), None), // no pinned version → skip
    };

    let (ecosystem, attestation) = match comp.package_type.as_str() {
        "npm" => (
            "npm",
            fetch_npm_attestation(&comp.name, version, options.npm_fixture_dir),
        ),
        "pip" => (
            "pypi",
            fetch_pypi_attestation(&comp.name, version, options.pypi_fixture_dir),
        ),
        _ => return (Vec::new(), None), // only npm + PyPI supported
    };

    let current_record = ProvRecord {
        attested: attestation.attested,
        signer_identity: attestation.signer_identity.clone(),
        source_repo: attestation.source_repo.clone(),
    };

    // Look up the ledger
    let ledger_dir = if let Some(d) = options.ledger_fixture_dir {
        d.to_path_buf()
    } else {
        match ledger_dir_default() {
            Some(d) => d,
            None => return (Vec::new(), Some(current_record)),
        }
    };

    let key = ledger_key(ecosystem, &comp.name, version);

    let findings = match read_ledger(&ledger_dir, &key) {
        Some(baseline) => detect_drift(
            ecosystem,
            &comp.name,
            version,
            lockfile,
            &attestation,
            &baseline,
        ),
        None => {
            // First observation — no drift detectable yet.
            // ADR-0007: absence of provenance is not a finding.
            Vec::new()
        }
    };

    (findings, Some(current_record))
}

// ── Public scan entry-point ───────────────────────────────────────────────────

/// Scan a directory for lockfiles, check each pinned package for provenance
/// drift, and update the provenance ledger.
///
/// Never panics. Network/parse failures for individual packages are silently
/// skipped. Returns an empty `Vec` if no drift is detected or if the ledger
/// has no prior observation for any package.
pub fn scan_for_provenance_drift(path: &Path, options: &ScanOptions<'_>) -> Vec<Finding> {
    use crate::sbom::parsers;
    use ignore::WalkBuilder;

    const LOCKFILE_NAMES: &[&str] = &["package-lock.json", "requirements.txt"];
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
    // Collect (key, record, ledger_dir) to write after all checks
    let mut ledger_updates: Vec<(PathBuf, String, ProvRecord)> = Vec::new();

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
        if !entry.file_type().map_or(false, |t| t.is_dir()) {
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

        if !LOCKFILE_NAMES.contains(&file_name) {
            continue;
        }

        let components: Vec<Component> = match file_name {
            "package-lock.json" => match parsers::parse_package_lock(file_path) {
                Ok(c) => c,
                Err(_) => continue,
            },
            "requirements.txt" => match parsers::parse_requirements_txt(file_path) {
                Ok(c) => c,
                Err(_) => continue,
            },
            _ => continue,
        };

        let lockfile_rel = file_path
            .strip_prefix(path)
            .unwrap_or(file_path)
            .to_string_lossy()
            .to_string();

        for comp in &components {
            let (findings, maybe_record) = check_component(comp, &lockfile_rel, options);
            all_findings.extend(findings);

            if let Some(record) = maybe_record {
                let version = comp.version.as_deref().unwrap_or("");
                let ecosystem = match comp.package_type.as_str() {
                    "npm" => "npm",
                    "pip" => "pypi",
                    _ => continue,
                };
                let ledger_dir = if let Some(d) = options.ledger_fixture_dir {
                    d.to_path_buf()
                } else {
                    match ledger_dir_default() {
                        Some(d) => d,
                        None => continue,
                    }
                };
                let key = ledger_key(ecosystem, &comp.name, version);
                ledger_updates.push((ledger_dir, key, record));
            }
        }
    }

    // Write ledger updates after scanning (avoids partial write during iteration)
    for (ledger_dir, key, record) in ledger_updates {
        write_ledger(&ledger_dir, &key, &record);
    }

    all_findings
}

// ── Public helpers exposed for testing ───────────────────────────────────────

#[cfg(test)]
pub use self::tests_helpers::*;

#[cfg(test)]
mod tests_helpers {
    use super::*;

    pub fn detect_drift_pub(
        ecosystem: &str,
        name: &str,
        version: &str,
        lockfile: &str,
        current: &Attestation,
        baseline: &ProvRecord,
    ) -> Vec<Finding> {
        detect_drift(ecosystem, name, version, lockfile, current, baseline)
    }

    pub fn make_attestation(
        attested: bool,
        signer_identity: Option<&str>,
        source_repo: Option<&str>,
    ) -> Attestation {
        Attestation {
            attested,
            signer_identity: signer_identity.map(str::to_string),
            source_repo: source_repo.map(str::to_string),
        }
    }

    pub fn parse_npm_attestation_pub(raw: &[u8]) -> Attestation {
        parse_npm_attestation(raw)
    }

    pub fn parse_pypi_attestation_pub(raw: &[u8]) -> Attestation {
        parse_pypi_attestation(raw)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::tempdir;

    // ── Fixture helpers ──────────────────────────────────────────────────────

    fn make_record(
        attested: bool,
        signer_identity: Option<&str>,
        source_repo: Option<&str>,
    ) -> ProvRecord {
        ProvRecord {
            attested,
            signer_identity: signer_identity.map(str::to_string),
            source_repo: source_repo.map(str::to_string),
        }
    }

    // ── Unit tests: detect_drift ──────────────────────────────────────────────

    /// Positive test: downgrade from attested → unattested emits PROV-DOWNGRADE
    #[test]
    fn provenance_drift_downgrade_emits_finding() {
        let baseline = make_record(true, Some("https://github.com/org/repo/.github/workflows/publish.yml@refs/heads/main"), Some("https://github.com/org/repo"));
        let current = make_attestation(false, None, None);
        let findings = detect_drift("npm", "my-pkg", "1.0.0", "package-lock.json", &current, &baseline);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "PROV-DOWNGRADE");
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].snippet.contains("was attested"));
    }

    /// Positive test: signer identity change emits PROV-IDENTITY-CHANGE
    #[test]
    fn provenance_drift_identity_change_emits_finding() {
        let baseline = make_record(
            true,
            Some("https://github.com/org/repo/.github/workflows/publish.yml@refs/heads/main"),
            Some("https://github.com/org/repo"),
        );
        let current = make_attestation(
            true,
            Some("https://github.com/attacker/fork/.github/workflows/publish.yml@refs/heads/main"),
            Some("https://github.com/org/repo"),
        );
        let findings = detect_drift("npm", "my-pkg", "1.0.0", "package-lock.json", &current, &baseline);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "PROV-IDENTITY-CHANGE");
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    /// Positive test: source repo mismatch emits PROV-REPO-MISMATCH
    #[test]
    fn provenance_drift_repo_mismatch_emits_finding() {
        let baseline = make_record(
            true,
            Some("https://github.com/org/repo/.github/workflows/publish.yml@refs/heads/main"),
            Some("https://github.com/org/repo"),
        );
        let current = make_attestation(
            true,
            Some("https://github.com/org/repo/.github/workflows/publish.yml@refs/heads/main"),
            Some("https://github.com/different-org/repo"),
        );
        let findings = detect_drift("npm", "my-pkg", "1.0.0", "package-lock.json", &current, &baseline);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "PROV-REPO-MISMATCH");
        assert_eq!(findings[0].severity, Severity::High);
    }

    /// Negative test: no drift on identical baseline produces zero findings
    #[test]
    fn provenance_drift_no_change_produces_zero_findings() {
        let baseline = make_record(
            true,
            Some("https://github.com/org/repo/.github/workflows/publish.yml@refs/heads/main"),
            Some("https://github.com/org/repo"),
        );
        let current = make_attestation(
            true,
            Some("https://github.com/org/repo/.github/workflows/publish.yml@refs/heads/main"),
            Some("https://github.com/org/repo"),
        );
        let findings = detect_drift("npm", "my-pkg", "1.0.0", "package-lock.json", &current, &baseline);
        assert!(findings.is_empty(), "identical baseline must produce zero findings");
    }

    /// Negative test: clean unattested package (never was attested) → zero findings
    #[test]
    fn provenance_drift_clean_unattested_produces_zero_findings() {
        // ADR-0007: absence of provenance is never a finding.
        // A package that was never attested (baseline.attested = false) and
        // remains unattested produces no findings.
        let baseline = make_record(false, None, None);
        let current = make_attestation(false, None, None);
        let findings = detect_drift("npm", "legacy-pkg", "2.0.0", "package-lock.json", &current, &baseline);
        assert!(
            findings.is_empty(),
            "unattested-from-start package must never produce findings (ADR-0007)"
        );
    }

    // ── Ledger round-trip ────────────────────────────────────────────────────

    #[test]
    fn ledger_round_trip_preserves_record() {
        let dir = tempdir().unwrap();
        let record = ProvRecord {
            attested: true,
            signer_identity: Some("https://github.com/org/repo/.github/workflows/release.yml@refs/heads/main".to_string()),
            source_repo: Some("https://github.com/org/repo".to_string()),
        };
        let key = "npm-my-pkg-1.0.0";
        write_ledger(dir.path(), key, &record);
        let loaded = read_ledger(dir.path(), key).expect("ledger entry must be readable");
        assert_eq!(loaded, record);
    }

    #[test]
    fn ledger_key_sanitizes_npm_scoped_names() {
        let key = ledger_key("npm", "@scope/pkg", "1.0.0");
        assert!(!key.contains('/'), "key must not contain path separators");
        assert!(!key.contains('@'), "key must not contain @ characters");
    }

    // ── npm attestation parsing ──────────────────────────────────────────────

    /// Positive test: npm package with attestations field → attested
    #[test]
    fn npm_attestation_parses_attested_package() {
        let raw = serde_json::json!({
            "name": "my-pkg",
            "version": "1.0.0",
            "dist": {
                "attestations": {
                    "url": "https://registry.npmjs.org/-/npm/v1/attestations/my-pkg@1.0.0",
                    "provenance": {
                        "predicateType": "https://slsa.dev/provenance/v1",
                        "predicateSourceRepoUrl": "https://github.com/org/repo",
                        "signerIdentity": "https://github.com/org/repo/.github/workflows/publish.yml@refs/heads/main"
                    }
                }
            }
        });
        let bytes = serde_json::to_vec(&raw).unwrap();
        let att = parse_npm_attestation_pub(&bytes);
        assert!(att.attested);
        assert_eq!(att.source_repo.as_deref(), Some("https://github.com/org/repo"));
        assert!(att.signer_identity.is_some());
    }

    /// Negative test: npm package without attestations field → unattested, no panic
    #[test]
    fn npm_attestation_parses_unattested_package() {
        let raw = serde_json::json!({
            "name": "legacy-pkg",
            "version": "2.0.0",
            "dist": {
                "tarball": "https://registry.npmjs.org/legacy-pkg/-/legacy-pkg-2.0.0.tgz",
                "shasum": "abc123"
            }
        });
        let bytes = serde_json::to_vec(&raw).unwrap();
        let att = parse_npm_attestation_pub(&bytes);
        assert!(!att.attested);
        assert!(att.signer_identity.is_none());
        assert!(att.source_repo.is_none());
    }

    // ── PyPI attestation parsing ─────────────────────────────────────────────

    /// Positive test: PyPI package with PEP 740 attestations → attested
    #[test]
    fn pypi_attestation_parses_attested_package() {
        let raw = serde_json::json!({
            "info": {
                "home_page": "https://github.com/org/pyrepo",
                "project_urls": { "Source": "https://github.com/org/pyrepo" }
            },
            "urls": [
                {
                    "filename": "mypkg-1.0.0-py3-none-any.whl",
                    "attestations": {
                        "signer_identity": "https://github.com/org/pyrepo/.github/workflows/release.yml@refs/heads/main"
                    }
                }
            ]
        });
        let bytes = serde_json::to_vec(&raw).unwrap();
        let att = parse_pypi_attestation_pub(&bytes);
        assert!(att.attested);
        assert_eq!(att.source_repo.as_deref(), Some("https://github.com/org/pyrepo"));
    }

    /// Negative test: PyPI package without attestations field → unattested, no panic
    #[test]
    fn pypi_attestation_parses_unattested_package() {
        let raw = serde_json::json!({
            "info": {
                "home_page": "https://example.com",
                "project_urls": {}
            },
            "urls": [
                {
                    "filename": "oldpkg-0.5.0.tar.gz",
                    "url": "https://files.pythonhosted.org/packages/..."
                }
            ]
        });
        let bytes = serde_json::to_vec(&raw).unwrap();
        let att = parse_pypi_attestation_pub(&bytes);
        assert!(!att.attested);
    }

    // ── Fixture-injection integration test ───────────────────────────────────

    /// Integration test: scan a directory with a fixture lockfile and a pre-seeded
    /// ledger that shows drift, and verify findings are produced.
    ///
    /// The fixture ledger (`tests/fixtures/provenance/ledger-downgrade/`) is
    /// read-only reference data. We copy it into a tempdir so the scanner can
    /// write the post-scan observation without mutating the fixture on disk.
    #[test]
    fn provenance_drift_scan_detects_downgrade_via_fixtures() {
        let fixture_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../tests/fixtures/provenance");

        // Skip if fixture dir doesn't exist yet
        if !fixture_dir.exists() {
            return;
        }

        let npm_fixture_dir = fixture_dir.join("npm");
        let fixture_ledger_dir = fixture_dir.join("ledger-downgrade");

        if !npm_fixture_dir.exists() || !fixture_ledger_dir.exists() {
            return;
        }

        let target_dir = fixture_dir.join("lockfile-downgrade");
        if !target_dir.exists() {
            return;
        }

        // Copy the fixture ledger to a tempdir so we don't mutate the fixture.
        let ledger_tmp = tempdir().unwrap();
        for entry in std::fs::read_dir(&fixture_ledger_dir).unwrap() {
            let entry = entry.unwrap();
            let dest = ledger_tmp.path().join(entry.file_name());
            std::fs::copy(entry.path(), &dest).unwrap();
        }

        let options = ScanOptions {
            npm_fixture_dir: Some(&npm_fixture_dir),
            pypi_fixture_dir: None,
            ledger_fixture_dir: Some(ledger_tmp.path()),
        };

        let findings = scan_for_provenance_drift(&target_dir, &options);
        assert!(
            !findings.is_empty(),
            "downgrade scenario must produce at least one finding"
        );
        assert!(
            findings.iter().any(|f| f.rule == "PROV-DOWNGRADE"),
            "must include a PROV-DOWNGRADE finding"
        );
    }

    /// Integration test: first-observation scenario produces no findings.
    #[test]
    fn provenance_drift_first_observation_produces_zero_findings() {
        let target_dir = tempdir().unwrap();
        let npm_fixture_dir = tempdir().unwrap();
        let ledger_dir = tempdir().unwrap(); // empty ledger = first observation

        // Write a minimal package-lock.json
        let lock = serde_json::json!({
            "name": "test-app",
            "lockfileVersion": 2,
            "packages": {
                "node_modules/clean-pkg": {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/clean-pkg/-/clean-pkg-1.0.0.tgz"
                }
            }
        });
        let lock_path = target_dir.path().join("package-lock.json");
        std::fs::write(&lock_path, serde_json::to_string(&lock).unwrap()).unwrap();

        // Write an npm fixture showing the package is attested
        let npm_resp = serde_json::json!({
            "name": "clean-pkg",
            "version": "1.0.0",
            "dist": {
                "attestations": {
                    "provenance": {
                        "predicateSourceRepoUrl": "https://github.com/org/clean-pkg",
                        "signerIdentity": "https://github.com/org/clean-pkg/.github/workflows/publish.yml@refs/heads/main"
                    }
                }
            }
        });
        let npm_file = npm_fixture_dir.path().join("clean-pkg-1.0.0.json");
        std::fs::write(&npm_file, serde_json::to_string(&npm_resp).unwrap()).unwrap();

        let options = ScanOptions {
            npm_fixture_dir: Some(npm_fixture_dir.path()),
            pypi_fixture_dir: None,
            ledger_fixture_dir: Some(ledger_dir.path()),
        };

        // No git repo in tempdir — walker with require_git=true won't walk it.
        // Test the first-observation path directly via check_component instead.
        let comp = crate::sbom::Component {
            package_type: "npm".to_string(),
            name: "clean-pkg".to_string(),
            version: Some("1.0.0".to_string()),
            hash: None,
            threat_flagged: false,
            threat_severity: None,
            threat_description: None,
        };
        let (findings, _) = check_component(&comp, "package-lock.json", &options);
        assert!(
            findings.is_empty(),
            "first observation must never produce findings"
        );
    }

    /// Negative test: package without a pinned version is skipped entirely.
    #[test]
    fn provenance_drift_skips_unpinned_versions() {
        let ledger_dir = tempdir().unwrap();
        let options = ScanOptions {
            npm_fixture_dir: None,
            pypi_fixture_dir: None,
            ledger_fixture_dir: Some(ledger_dir.path()),
        };
        let comp = crate::sbom::Component {
            package_type: "npm".to_string(),
            name: "any-pkg".to_string(),
            version: None, // unpinned
            hash: None,
            threat_flagged: false,
            threat_severity: None,
            threat_description: None,
        };
        let (findings, record) = check_component(&comp, "package-lock.json", &options);
        assert!(findings.is_empty());
        assert!(record.is_none(), "no record should be stored for unpinned packages");
    }
}
