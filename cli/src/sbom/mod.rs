pub mod parsers;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use walkdir::WalkDir;

/// A single dependency component
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Component {
    /// Package manager: "pip", "npm", "cargo"
    pub package_type: String,
    /// Package name
    pub name: String,
    /// Version (if resolved)
    pub version: Option<String>,
    /// SHA256 hash if available
    pub hash: Option<String>,
    /// Whether this component is flagged as a known threat
    pub threat_flagged: bool,
    /// Threat severity if flagged
    pub threat_severity: Option<String>,
    /// Threat description if flagged
    pub threat_description: Option<String>,
}

/// SBOM output for a project
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sbom {
    /// SBOM format version
    pub spec_version: String,
    /// Tool that generated this
    pub tool: String,
    /// Project path
    pub project: String,
    /// When generated
    pub timestamp: String,
    /// All components discovered
    pub components: Vec<Component>,
    /// Count of flagged threats
    pub threat_count: usize,
    /// Total components
    pub total_count: usize,
}

/// Threat info loaded from known_threats.json
#[derive(Debug, Clone)]
pub struct ThreatInfo {
    pub severity: String,
    pub description: String,
    pub version: Option<String>,
}

/// Load known threats from the threat database JSON file.
///
/// Returns a map keyed by lowercase package name. Each name may map to
/// multiple threat entries (different versions), but we store the highest
/// severity one for simple cross-referencing.
pub fn load_known_threats(path: &Path) -> HashMap<String, ThreatInfo> {
    let mut map = HashMap::new();

    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return map,
    };

    let json: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return map,
    };

    if let Some(threats) = json.get("threats").and_then(|t| t.as_array()) {
        for threat in threats {
            let package_name = match threat.get("package_name").and_then(|n| n.as_str()) {
                Some(n) => n.to_lowercase(),
                None => continue,
            };
            let severity = threat
                .get("severity")
                .and_then(|s| s.as_str())
                .unwrap_or("UNKNOWN")
                .to_string();
            let description = threat
                .get("description")
                .and_then(|d| d.as_str())
                .unwrap_or("")
                .to_string();
            let version = threat
                .get("version")
                .and_then(|v| v.as_str())
                .map(String::from);

            // Keep higher severity entries (CRITICAL > HIGH > MEDIUM > LOW)
            let dominated = map.get(&package_name).map_or(false, |existing: &ThreatInfo| {
                severity_rank(&existing.severity) >= severity_rank(&severity)
            });
            if !dominated {
                map.insert(
                    package_name,
                    ThreatInfo {
                        severity,
                        description,
                        version,
                    },
                );
            }
        }
    }

    map
}

fn severity_rank(s: &str) -> u8 {
    match s.to_uppercase().as_str() {
        "CRITICAL" => 4,
        "HIGH" => 3,
        "MEDIUM" => 2,
        "LOW" => 1,
        _ => 0,
    }
}

/// Walk the project directory, find lockfiles, parse them, and cross-reference
/// against known threats.
pub fn generate_sbom(
    path: &Path,
    threats_db: Option<&Path>,
) -> Result<Sbom, Box<dyn std::error::Error>> {
    let threats = if let Some(db_path) = threats_db {
        load_known_threats(db_path)
    } else {
        // Try default location relative to the binary or project
        let default_path = Path::new("api/data/known_threats.json");
        if default_path.exists() {
            load_known_threats(default_path)
        } else {
            HashMap::new()
        }
    };

    let mut all_components: Vec<Component> = Vec::new();

    // Walk the directory looking for dependency files
    let lockfile_names = [
        "package-lock.json",
        "requirements.txt",
        "Cargo.lock",
    ];

    for entry in WalkDir::new(path)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let file_path = entry.path();
        let file_name = match file_path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };

        // Skip node_modules and target directories
        let path_str = file_path.to_string_lossy();
        if path_str.contains("node_modules") || path_str.contains("/target/") {
            continue;
        }

        if !lockfile_names.contains(&file_name) {
            continue;
        }

        let parsed = match file_name {
            "package-lock.json" => parsers::parse_package_lock(file_path),
            "requirements.txt" => parsers::parse_requirements_txt(file_path),
            "Cargo.lock" => parsers::parse_cargo_lock(file_path),
            _ => continue,
        };

        match parsed {
            Ok(mut components) => all_components.append(&mut components),
            Err(e) => {
                eprintln!(
                    "Warning: failed to parse {}: {}",
                    file_path.display(),
                    e
                );
            }
        }
    }

    // Cross-reference against known threats
    let mut threat_count = 0;
    for component in &mut all_components {
        let key = component.name.to_lowercase();
        if let Some(info) = threats.get(&key) {
            component.threat_flagged = true;
            component.threat_severity = Some(info.severity.clone());
            component.threat_description = Some(info.description.clone());
            threat_count += 1;
        }
    }

    let total_count = all_components.len();
    let timestamp = chrono::Utc::now().to_rfc3339();

    Ok(Sbom {
        spec_version: "1.5".to_string(),
        tool: "sigil".to_string(),
        project: path.to_string_lossy().to_string(),
        timestamp,
        components: all_components,
        threat_count,
        total_count,
    })
}

/// Format the SBOM as a human-readable table.
pub fn format_table(sbom: &Sbom) -> String {
    let mut out = String::new();

    out.push_str(&format!(
        "Sigil SBOM — {} ({} components, {} threats)\n",
        sbom.project, sbom.total_count, sbom.threat_count
    ));
    out.push_str(&format!("Generated: {}\n\n", sbom.timestamp));

    if sbom.components.is_empty() {
        out.push_str("No dependency files found.\n");
        return out;
    }

    // Header
    out.push_str(&format!(
        "{:<8} {:<40} {:<16} {:<10} {}\n",
        "TYPE", "NAME", "VERSION", "THREAT", "DETAILS"
    ));
    out.push_str(&format!("{}\n", "-".repeat(100)));

    for comp in &sbom.components {
        let version = comp.version.as_deref().unwrap_or("-");
        let threat = if comp.threat_flagged {
            comp.threat_severity.as_deref().unwrap_or("YES")
        } else {
            ""
        };
        let details = if comp.threat_flagged {
            comp.threat_description.as_deref().unwrap_or("")
        } else {
            ""
        };
        // Truncate details to 40 chars for table display
        let details_trunc = if details.len() > 40 {
            format!("{}...", &details[..37])
        } else {
            details.to_string()
        };

        out.push_str(&format!(
            "{:<8} {:<40} {:<16} {:<10} {}\n",
            comp.package_type, comp.name, version, threat, details_trunc
        ));
    }

    if sbom.threat_count > 0 {
        out.push_str(&format!(
            "\n!! {} known threat(s) detected in dependencies !!\n",
            sbom.threat_count
        ));
    }

    out
}

/// Format the SBOM as CycloneDX 1.5 JSON (simplified).
pub fn format_cyclonedx(sbom: &Sbom) -> String {
    let components: Vec<serde_json::Value> = sbom
        .components
        .iter()
        .map(|c| {
            let mut comp = serde_json::json!({
                "type": "library",
                "name": c.name,
                "purl": format!("pkg:{}/{}@{}", c.package_type, c.name, c.version.as_deref().unwrap_or("unknown")),
            });

            if let Some(ref version) = c.version {
                comp["version"] = serde_json::json!(version);
            }

            if let Some(ref hash) = c.hash {
                comp["hashes"] = serde_json::json!([
                    {
                        "alg": "SHA-256",
                        "content": hash,
                    }
                ]);
            }

            comp
        })
        .collect();

    let cdx = serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": sbom.timestamp,
            "tools": [{
                "vendor": "sigil",
                "name": "sigil-cli",
                "version": env!("CARGO_PKG_VERSION"),
            }],
            "component": {
                "type": "application",
                "name": sbom.project,
            }
        },
        "components": components,
    });

    serde_json::to_string_pretty(&cdx).unwrap_or_else(|_| "{}".to_string())
}
