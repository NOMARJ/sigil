use super::Component;
use std::path::Path;

/// Parse `package-lock.json` and return npm components.
pub fn parse_package_lock(path: &Path) -> Result<Vec<Component>, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    let json: serde_json::Value = serde_json::from_str(&content)?;

    let mut components = Vec::new();

    // lockfile v2/v3 uses "packages" key
    if let Some(packages) = json.get("packages").and_then(|p| p.as_object()) {
        for (key, value) in packages {
            // Skip the root "" entry
            if key.is_empty() {
                continue;
            }
            // Key is like "node_modules/foo" or "node_modules/foo/node_modules/bar"
            let name = key
                .rsplit("node_modules/")
                .next()
                .unwrap_or(key)
                .to_string();
            if name.is_empty() {
                continue;
            }
            let version = value
                .get("version")
                .and_then(|v| v.as_str())
                .map(String::from);
            components.push(Component {
                package_type: "npm".to_string(),
                name,
                version,
                hash: None,
                threat_flagged: false,
                threat_severity: None,
                threat_description: None,
            });
        }
    }
    // lockfile v1 uses "dependencies" key (fallback)
    else if let Some(deps) = json.get("dependencies").and_then(|d| d.as_object()) {
        parse_npm_dependencies_recursive(deps, &mut components);
    }

    Ok(components)
}

fn parse_npm_dependencies_recursive(
    deps: &serde_json::Map<String, serde_json::Value>,
    components: &mut Vec<Component>,
) {
    for (name, value) in deps {
        let version = value
            .get("version")
            .and_then(|v| v.as_str())
            .map(String::from);
        components.push(Component {
            package_type: "npm".to_string(),
            name: name.clone(),
            version,
            hash: None,
            threat_flagged: false,
            threat_severity: None,
            threat_description: None,
        });
        // Recurse into nested dependencies
        if let Some(nested) = value.get("dependencies").and_then(|d| d.as_object()) {
            parse_npm_dependencies_recursive(nested, components);
        }
    }
}

/// Parse `requirements.txt` and return pip components.
pub fn parse_requirements_txt(path: &Path) -> Result<Vec<Component>, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    let mut components = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        // Skip blank lines and comments
        if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
            continue;
        }

        // Handle: package==version, package>=version, package~=version, package!=version, package<=version, package
        let (name, version) = if let Some(pos) = line.find("==") {
            (
                line[..pos].trim().to_string(),
                Some(line[pos + 2..].trim().to_string()),
            )
        } else if let Some(pos) = line.find(">=") {
            (
                line[..pos].trim().to_string(),
                Some(line[pos + 2..].trim().to_string()),
            )
        } else if let Some(pos) = line.find("<=") {
            (
                line[..pos].trim().to_string(),
                Some(line[pos + 2..].trim().to_string()),
            )
        } else if let Some(pos) = line.find("~=") {
            (
                line[..pos].trim().to_string(),
                Some(line[pos + 2..].trim().to_string()),
            )
        } else if let Some(pos) = line.find("!=") {
            (
                line[..pos].trim().to_string(),
                Some(line[pos + 2..].trim().to_string()),
            )
        } else {
            (line.to_string(), None)
        };

        if !name.is_empty() {
            components.push(Component {
                package_type: "pip".to_string(),
                name,
                version,
                hash: None,
                threat_flagged: false,
                threat_severity: None,
                threat_description: None,
            });
        }
    }

    Ok(components)
}

/// Parse `Cargo.lock` using line-based parsing (no TOML crate needed).
pub fn parse_cargo_lock(path: &Path) -> Result<Vec<Component>, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    let mut components = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_version: Option<String> = None;
    let mut current_hash: Option<String> = None;
    let mut in_package = false;

    for line in content.lines() {
        let line = line.trim();

        if line == "[[package]]" {
            // Flush previous package if any
            if in_package {
                if let Some(name) = current_name.take() {
                    components.push(Component {
                        package_type: "cargo".to_string(),
                        name,
                        version: current_version.take(),
                        hash: current_hash.take(),
                        threat_flagged: false,
                        threat_severity: None,
                        threat_description: None,
                    });
                }
            }
            in_package = true;
            current_name = None;
            current_version = None;
            current_hash = None;
        } else if in_package {
            if let Some(val) = line.strip_prefix("name = ") {
                current_name = Some(val.trim_matches('"').to_string());
            } else if let Some(val) = line.strip_prefix("version = ") {
                current_version = Some(val.trim_matches('"').to_string());
            } else if let Some(val) = line.strip_prefix("checksum = ") {
                current_hash = Some(val.trim_matches('"').to_string());
            } else if line.is_empty() || line.starts_with('[') {
                // End of package block — flush
                if let Some(name) = current_name.take() {
                    components.push(Component {
                        package_type: "cargo".to_string(),
                        name,
                        version: current_version.take(),
                        hash: current_hash.take(),
                        threat_flagged: false,
                        threat_severity: None,
                        threat_description: None,
                    });
                }
                in_package = line == "[[package]]";
                if in_package {
                    current_name = None;
                    current_version = None;
                    current_hash = None;
                }
            }
        }
    }

    // Flush last package
    if in_package {
        if let Some(name) = current_name.take() {
            components.push(Component {
                package_type: "cargo".to_string(),
                name,
                version: current_version.take(),
                hash: current_hash.take(),
                threat_flagged: false,
                threat_severity: None,
                threat_description: None,
            });
        }
    }

    Ok(components)
}
