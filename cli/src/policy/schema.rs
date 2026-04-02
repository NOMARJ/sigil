use serde::{Deserialize, Serialize};

/// A complete Sigil sandbox policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigilPolicy {
    /// Policy format version
    pub version: String, // "1.0"
    /// Human-readable policy name
    pub name: String,
    /// Optional description
    #[serde(default)]
    pub description: Option<String>,
    /// Filesystem access controls (immutable at sandbox creation)
    #[serde(default)]
    pub filesystem: FilesystemPolicy,
    /// Network egress controls (hot-reloadable)
    #[serde(default)]
    pub network: NetworkPolicy,
    /// Process restrictions (immutable at sandbox creation)
    #[serde(default)]
    pub process: ProcessPolicy,
    /// Credential/environment variable controls
    #[serde(default)]
    pub credentials: CredentialPolicy,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FilesystemPolicy {
    /// Paths with read-only access
    #[serde(default)]
    pub read_only: Vec<String>,
    /// Paths with read-write access
    #[serde(default)]
    pub read_write: Vec<String>,
    /// Include the working directory as read-write
    #[serde(default = "default_true")]
    pub include_workdir: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkPolicy {
    /// Default action when no rule matches: "deny" or "log"
    #[serde(default = "default_deny")]
    pub default_action: String,
    /// Allowed endpoint rules
    #[serde(default)]
    pub rules: Vec<NetworkRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkRule {
    /// Human-readable rule name
    pub name: String,
    /// Allowed hostname or IP
    pub host: String,
    /// Allowed port (default 443)
    #[serde(default = "default_port")]
    pub port: u16,
    /// Access level: "read-only" (GET/HEAD/OPTIONS) or "read-write" (all methods)
    #[serde(default = "default_read_only")]
    pub access: String,
    /// Enforcement mode: "enforce" or "log"
    #[serde(default = "default_enforce")]
    pub enforcement: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcessPolicy {
    /// Run as this user inside sandbox
    #[serde(default)]
    pub run_as_user: Option<String>,
    /// Run as this group inside sandbox
    #[serde(default)]
    pub run_as_group: Option<String>,
    /// Deny these syscall categories (e.g., "privilege_escalation", "dangerous_io")
    #[serde(default)]
    pub deny_syscall_categories: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CredentialPolicy {
    /// Explicitly allowed environment variable names/patterns
    #[serde(default)]
    pub allowed_env: Vec<String>,
    /// Explicitly denied environment variable patterns
    #[serde(default)]
    pub denied_env: Vec<String>,
    /// Named credential provider bundles to include
    #[serde(default)]
    pub providers: Vec<String>,
}

fn default_true() -> bool {
    true
}
fn default_deny() -> String {
    "deny".to_string()
}
fn default_port() -> u16 {
    443
}
fn default_read_only() -> String {
    "read-only".to_string()
}
fn default_enforce() -> String {
    "enforce".to_string()
}

impl SigilPolicy {
    /// Load a policy from a YAML file
    pub fn from_file(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let policy: Self = serde_yaml::from_str(&content)?;
        policy.validate()?;
        Ok(policy)
    }

    /// Load a built-in preset policy
    pub fn preset(name: &str) -> Option<Self> {
        match name {
            "strict" => Some(Self::strict_preset()),
            "standard" => Some(Self::standard_preset()),
            "permissive" => Some(Self::permissive_preset()),
            _ => None,
        }
    }

    /// Validate policy for correctness
    pub fn validate(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self.version != "1.0" {
            return Err(format!("unsupported policy version: {}", self.version).into());
        }
        if self.name.is_empty() {
            return Err("policy name cannot be empty".into());
        }
        for rule in &self.network.rules {
            if rule.host.is_empty() {
                return Err(format!("network rule '{}' has empty host", rule.name).into());
            }
            if !["read-only", "read-write"].contains(&rule.access.as_str()) {
                return Err(format!(
                    "invalid access '{}' in rule '{}'",
                    rule.access, rule.name
                )
                .into());
            }
            if !["enforce", "log"].contains(&rule.enforcement.as_str()) {
                return Err(format!(
                    "invalid enforcement '{}' in rule '{}'",
                    rule.enforcement, rule.name
                )
                .into());
            }
        }
        Ok(())
    }

    fn strict_preset() -> Self {
        SigilPolicy {
            version: "1.0".into(),
            name: "strict".into(),
            description: Some("No network access, minimal filesystem, no credentials".into()),
            filesystem: FilesystemPolicy {
                read_only: vec!["/usr".into(), "/lib".into(), "/etc".into()],
                read_write: vec!["/tmp".into()],
                include_workdir: true,
            },
            network: NetworkPolicy {
                default_action: "deny".into(),
                rules: vec![],
            },
            process: ProcessPolicy {
                run_as_user: Some("sandbox".into()),
                run_as_group: Some("sandbox".into()),
                deny_syscall_categories: vec!["privilege_escalation".into()],
            },
            credentials: CredentialPolicy {
                allowed_env: vec![],
                denied_env: vec!["*".into()],
                providers: vec![],
            },
        }
    }

    fn standard_preset() -> Self {
        SigilPolicy {
            version: "1.0".into(),
            name: "standard".into(),
            description: Some("Common endpoints allowed, working credentials".into()),
            filesystem: FilesystemPolicy {
                read_only: vec![
                    "/usr".into(),
                    "/lib".into(),
                    "/etc".into(),
                    "/proc".into(),
                ],
                read_write: vec!["/tmp".into()],
                include_workdir: true,
            },
            network: NetworkPolicy {
                default_action: "deny".into(),
                rules: vec![
                    NetworkRule {
                        name: "github".into(),
                        host: "api.github.com".into(),
                        port: 443,
                        access: "read-write".into(),
                        enforcement: "enforce".into(),
                    },
                    NetworkRule {
                        name: "pypi".into(),
                        host: "pypi.org".into(),
                        port: 443,
                        access: "read-only".into(),
                        enforcement: "enforce".into(),
                    },
                    NetworkRule {
                        name: "npm".into(),
                        host: "registry.npmjs.org".into(),
                        port: 443,
                        access: "read-only".into(),
                        enforcement: "enforce".into(),
                    },
                ],
            },
            process: ProcessPolicy {
                run_as_user: Some("sandbox".into()),
                run_as_group: Some("sandbox".into()),
                deny_syscall_categories: vec!["privilege_escalation".into()],
            },
            credentials: CredentialPolicy {
                allowed_env: vec!["GITHUB_TOKEN".into(), "GH_TOKEN".into()],
                denied_env: vec![],
                providers: vec![],
            },
        }
    }

    fn permissive_preset() -> Self {
        SigilPolicy {
            version: "1.0".into(),
            name: "permissive".into(),
            description: Some("Log-only mode, no enforcement — for auditing".into()),
            filesystem: FilesystemPolicy {
                read_only: vec![],
                read_write: vec![],
                include_workdir: true,
            },
            network: NetworkPolicy {
                default_action: "log".into(),
                rules: vec![],
            },
            process: ProcessPolicy {
                run_as_user: None,
                run_as_group: None,
                deny_syscall_categories: vec![],
            },
            credentials: CredentialPolicy {
                allowed_env: vec!["*".into()],
                denied_env: vec![],
                providers: vec![],
            },
        }
    }

    /// Serialize to YAML string
    pub fn to_yaml(&self) -> Result<String, serde_yaml::Error> {
        serde_yaml::to_string(self)
    }
}
