use regex::Regex;
use std::path::Path;
use walkdir::DirEntry;

use super::{Finding, Phase, Severity};

// ---------------------------------------------------------------------------
// Helper: build a finding
// ---------------------------------------------------------------------------

fn make_finding(
    phase: Phase,
    rule: &str,
    severity: Severity,
    file: &str,
    line: Option<usize>,
    snippet: &str,
    weight: u32,
) -> Finding {
    Finding {
        phase,
        rule: rule.to_string(),
        severity,
        file: file.to_string(),
        line,
        snippet: snippet.to_string(),
        weight,
    }
}

/// Helper: scan each line of a file against a set of (regex, rule, severity, description) patterns.
fn scan_lines(
    file: &str,
    contents: &str,
    phase: Phase,
    weight: u32,
    patterns: &[(Regex, &str, Severity, &str)],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (line_num, line) in contents.lines().enumerate() {
        for (re, rule, severity, description) in patterns {
            if re.is_match(line) {
                let snippet = if line.len() > 200 {
                    format!("{} ...", &line[..200])
                } else {
                    line.to_string()
                };
                findings.push(make_finding(
                    phase,
                    rule,
                    *severity,
                    file,
                    Some(line_num + 1),
                    &format!("{}: {}", description, snippet.trim()),
                    weight,
                ));
            }
        }
    }

    findings
}

// ---------------------------------------------------------------------------
// Phase 1: Install Hooks (Critical, 10x weight)
// ---------------------------------------------------------------------------

/// Detect install-time hooks that execute code: setup.py cmdclass overrides,
/// npm postinstall/preinstall scripts, and Makefile install targets.
pub fn scan_install_hooks(file: &str, contents: &str) -> Vec<Finding> {
    let filename = Path::new(file)
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_default();

    let mut patterns: Vec<(Regex, &str, Severity, &str)> = Vec::new();

    // setup.py / setup.cfg install hooks
    if filename == "setup.py" || filename == "setup.cfg" {
        patterns.push((
            Regex::new(r"cmdclass").unwrap(),
            "INSTALL-001",
            Severity::Critical,
            "setup.py cmdclass override (code runs at install time)",
        ));
        patterns.push((
            Regex::new(r"(?i)(pre_install|post_install|install_scripts)").unwrap(),
            "INSTALL-002",
            Severity::Critical,
            "setup.py custom install hook",
        ));
    }

    // package.json lifecycle scripts
    if filename == "package.json" {
        patterns.push((
            Regex::new(r#""(preinstall|postinstall|preuninstall|postuninstall)""#).unwrap(),
            "INSTALL-003",
            Severity::Critical,
            "npm lifecycle script (runs automatically on install)",
        ));
        patterns.push((
            Regex::new(r#""(prepare|prepublish|prepublishOnly)""#).unwrap(),
            "INSTALL-004",
            Severity::High,
            "npm publish lifecycle script",
        ));
    }

    // Makefile install targets
    if filename == "Makefile" || filename == "makefile" || filename.ends_with(".mk") {
        patterns.push((
            Regex::new(r"^install\s*:").unwrap(),
            "INSTALL-005",
            Severity::Medium,
            "Makefile install target",
        ));
        patterns.push((
            Regex::new(r"^\.(PHONY|ONESHELL).*install").unwrap(),
            "INSTALL-006",
            Severity::Low,
            "Makefile install phony target",
        ));
    }

    // pyproject.toml build hooks
    if filename == "pyproject.toml" {
        patterns.push((
            Regex::new(r"\[tool\.setuptools\.cmdclass\]").unwrap(),
            "INSTALL-007",
            Severity::Critical,
            "pyproject.toml cmdclass override",
        ));
        patterns.push((
            Regex::new(r"build-backend\s*=").unwrap(),
            "INSTALL-008",
            Severity::Low,
            "Custom build backend declared",
        ));
    }

    // MCP configuration files
    patterns.push((
        Regex::new(r"claude_desktop_config|mcp_config\.json|\.mcp\.json").unwrap(),
        "INSTALL-MCP-001",
        Severity::Medium,
        "MCP configuration file detected",
    ));
    patterns.push((
        Regex::new(r"mcpServers|mcp_servers").unwrap(),
        "INSTALL-MCP-002",
        Severity::Low,
        "MCP server registry entry",
    ));

    scan_lines(file, contents, Phase::InstallHooks, 10, &patterns)
}

// ---------------------------------------------------------------------------
// Phase 2: Code Patterns (High, 5x weight)
// ---------------------------------------------------------------------------

/// Detect dangerous code patterns: eval/exec, pickle deserialization,
/// child_process spawning, dynamic imports, and code generation.
pub fn scan_code_patterns(file: &str, contents: &str) -> Vec<Finding> {
    let patterns = vec![
        // Python dangerous builtins
        (
            Regex::new(r"\beval\s*\(").unwrap(),
            "CODE-001",
            Severity::High,
            "eval() call — arbitrary code execution",
        ),
        (
            Regex::new(r"\bexec\s*\(").unwrap(),
            "CODE-002",
            Severity::High,
            "exec() call — arbitrary code execution",
        ),
        (
            Regex::new(r"\bcompile\s*\(").unwrap(),
            "CODE-003",
            Severity::Medium,
            "compile() call — dynamic code compilation",
        ),
        // Python pickle / marshal
        (
            Regex::new(r"pickle\.(loads?|Unpickler)").unwrap(),
            "CODE-004",
            Severity::Critical,
            "pickle deserialization — arbitrary code execution",
        ),
        (
            Regex::new(r"marshal\.(loads?)").unwrap(),
            "CODE-005",
            Severity::High,
            "marshal deserialization — code execution risk",
        ),
        (
            Regex::new(r"yaml\.(unsafe_)?load\s*\(").unwrap(),
            "CODE-006",
            Severity::High,
            "YAML unsafe load — potential code execution",
        ),
        // JavaScript / Node dangerous patterns
        (
            Regex::new(r"\bchild_process\b").unwrap(),
            "CODE-007",
            Severity::High,
            "child_process usage — command execution",
        ),
        (
            Regex::new(r"\bFunction\s*\(").unwrap(),
            "CODE-008",
            Severity::High,
            "Function constructor — dynamic code execution",
        ),
        (
            Regex::new(r"new\s+Function\s*\(").unwrap(),
            "CODE-009",
            Severity::High,
            "new Function() — dynamic code execution",
        ),
        // Dynamic imports / requires
        (
            Regex::new(r"__import__\s*\(").unwrap(),
            "CODE-010",
            Severity::High,
            "__import__() — dynamic import",
        ),
        (
            Regex::new(r"importlib\.import_module\s*\(").unwrap(),
            "CODE-011",
            Severity::Medium,
            "importlib.import_module — dynamic import",
        ),
        (
            Regex::new(r#"require\s*\(\s*[^'"]"#).unwrap(),
            "CODE-012",
            Severity::Medium,
            "dynamic require() — variable module loading",
        ),
        // Subprocess / OS commands
        (
            Regex::new(r"subprocess\.(call|run|Popen|check_output)\s*\(").unwrap(),
            "CODE-013",
            Severity::Medium,
            "subprocess invocation — command execution",
        ),
        (
            Regex::new(r"os\.(system|popen|exec[lv]?[pe]?)\s*\(").unwrap(),
            "CODE-014",
            Severity::High,
            "os command execution",
        ),
        // Shell injection patterns
        (
            Regex::new(r"shell\s*=\s*True").unwrap(),
            "CODE-015",
            Severity::High,
            "shell=True — shell injection risk",
        ),
        // MCP server patterns
        (
            Regex::new(r"mcp[_-]?server|MCPServer|create_mcp_server").unwrap(),
            "CODE-MCP-001",
            Severity::Medium,
            "MCP server creation detected",
        ),
        (
            Regex::new(r"tool_call|execute_tool|run_tool").unwrap(),
            "CODE-MCP-002",
            Severity::Medium,
            "MCP tool execution pattern",
        ),
        (
            Regex::new(r"allow_dangerous|skip_confirmation|auto_approve.*true").unwrap(),
            "CODE-MCP-003",
            Severity::High,
            "MCP dangerous permission bypass",
        ),
    ];

    scan_lines(file, contents, Phase::CodePatterns, 5, &patterns)
}

// ---------------------------------------------------------------------------
// Phase 3: Network / Exfiltration (High, 3x weight)
// ---------------------------------------------------------------------------

/// Detect outbound network activity: HTTP requests, webhook calls,
/// raw socket connections, DNS exfiltration, and data upload patterns.
pub fn scan_network_exfil(file: &str, contents: &str) -> Vec<Finding> {
    let patterns = vec![
        // HTTP client usage
        (
            Regex::new(r"requests\.(get|post|put|delete|patch|head)\s*\(").unwrap(),
            "NET-001",
            Severity::Medium,
            "HTTP request via requests library",
        ),
        (
            Regex::new(r"urllib\.(request\.)?urlopen\s*\(").unwrap(),
            "NET-002",
            Severity::Medium,
            "HTTP request via urllib",
        ),
        (
            Regex::new(r"http\.client\.HTTP").unwrap(),
            "NET-003",
            Severity::Medium,
            "HTTP client connection",
        ),
        (
            Regex::new(r#"fetch\s*\(\s*['"]https?://"#).unwrap(),
            "NET-004",
            Severity::Medium,
            "fetch() to external URL",
        ),
        (
            Regex::new(r"axios\.(get|post|put|delete|patch)\s*\(").unwrap(),
            "NET-005",
            Severity::Medium,
            "HTTP request via axios",
        ),
        // Webhook / callback URLs
        (
            Regex::new(r"(?i)(webhook|callback|notify).*https?://").unwrap(),
            "NET-006",
            Severity::High,
            "Webhook / callback URL detected",
        ),
        (
            Regex::new(r"https?://[^\s]*\.(ngrok|pipedream|requestbin|hookbin)").unwrap(),
            "NET-007",
            Severity::Critical,
            "Known exfiltration / tunneling service URL",
        ),
        // Raw socket usage
        (
            Regex::new(r"socket\.socket\s*\(").unwrap(),
            "NET-008",
            Severity::High,
            "Raw socket creation",
        ),
        (
            Regex::new(r#"\.connect\s*\(\s*\(?\s*['"]"#).unwrap(),
            "NET-009",
            Severity::Medium,
            "Socket connect to address",
        ),
        // DNS exfiltration
        (
            Regex::new(r"dns\.(resolver|query)|getaddrinfo").unwrap(),
            "NET-010",
            Severity::Medium,
            "DNS resolution — possible DNS exfiltration",
        ),
        // Data encoding before send (exfil pattern)
        (
            Regex::new(r"(base64|b64)(encode|\.b64encode)\s*\(.*\.(read|getenv|environ)").unwrap(),
            "NET-011",
            Severity::High,
            "Data encoding before potential exfiltration",
        ),
        // Curl / wget in code
        (
            Regex::new(r"(curl|wget)\s+.*(https?://)").unwrap(),
            "NET-012",
            Severity::Medium,
            "curl/wget command in code",
        ),
        // MCP transport patterns
        (
            Regex::new(r"stdio_transport|sse_transport|StreamableHTTPTransport").unwrap(),
            "NET-MCP-001",
            Severity::Low,
            "MCP transport configuration",
        ),
        (
            Regex::new(r"mcp.*proxy|proxy.*mcp").unwrap(),
            "NET-MCP-002",
            Severity::High,
            "MCP proxy configuration - potential MITM",
        ),
    ];

    scan_lines(file, contents, Phase::NetworkExfil, 3, &patterns)
}

// ---------------------------------------------------------------------------
// Phase 4: Credentials (Medium, 2x weight)
// ---------------------------------------------------------------------------

/// Detect credential access patterns: ENV variable reads, AWS/GCP/Azure
/// credentials, SSH keys, API key patterns, and hardcoded secrets.
pub fn scan_credentials(file: &str, contents: &str) -> Vec<Finding> {
    let patterns = vec![
        // Environment variable access for secrets
        (
            Regex::new(r#"os\.(environ|getenv)\s*[\[\(]\s*['"](AWS_|SECRET_|API_KEY|TOKEN|PASSWORD|DATABASE_URL|PRIVATE)"#).unwrap(),
            "CRED-001",
            Severity::High,
            "Environment variable access for sensitive key",
        ),
        (
            Regex::new(r"process\.env\.(AWS_|SECRET_|API_KEY|TOKEN|PASSWORD|DATABASE_URL|PRIVATE)").unwrap(),
            "CRED-002",
            Severity::High,
            "Node process.env access for sensitive key",
        ),
        // AWS credential files
        (
            Regex::new(r"\.aws/(credentials|config)").unwrap(),
            "CRED-003",
            Severity::Critical,
            "AWS credentials file access",
        ),
        (
            Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
            "CRED-004",
            Severity::Critical,
            "Hardcoded AWS access key ID",
        ),
        // SSH keys
        (
            Regex::new(r"\.ssh/(id_rsa|id_ed25519|id_ecdsa|authorized_keys)").unwrap(),
            "CRED-005",
            Severity::Critical,
            "SSH key file access",
        ),
        (
            Regex::new(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----").unwrap(),
            "CRED-006",
            Severity::Critical,
            "Embedded private key",
        ),
        // API key patterns
        (
            Regex::new(r#"(?i)(api[_-]?key|api[_-]?secret|access[_-]?token)\s*[:=]\s*['"][a-zA-Z0-9]{16,}"#).unwrap(),
            "CRED-007",
            Severity::High,
            "Hardcoded API key or secret",
        ),
        // Generic secret patterns
        (
            Regex::new(r#"(?i)(password|passwd|pwd)\s*[:=]\s*['"][^'"]{8,}"#).unwrap(),
            "CRED-008",
            Severity::High,
            "Hardcoded password",
        ),
        // GCP service account
        (
            Regex::new(r#""type"\s*:\s*"service_account""#).unwrap(),
            "CRED-009",
            Severity::Critical,
            "GCP service account JSON key",
        ),
        // GitHub tokens
        (
            Regex::new(r"gh[pousr]_[A-Za-z0-9_]{36,}").unwrap(),
            "CRED-010",
            Severity::Critical,
            "GitHub personal access token",
        ),
        // Generic token patterns
        (
            Regex::new(r#"(?i)(bearer|authorization)\s*[:=]\s*['"][a-zA-Z0-9._\-]{20,}"#).unwrap(),
            "CRED-011",
            Severity::High,
            "Authorization / bearer token",
        ),
        // MCP credential patterns
        (
            Regex::new(r"MCP_API_KEY|MCP_SECRET|MCP_TOKEN|mcp_auth").unwrap(),
            "CRED-MCP-001",
            Severity::Medium,
            "MCP credential reference",
        ),
    ];

    scan_lines(file, contents, Phase::Credentials, 2, &patterns)
}

// ---------------------------------------------------------------------------
// Phase 5: Obfuscation (High, 5x weight)
// ---------------------------------------------------------------------------

/// Detect obfuscation techniques: base64 encoded payloads, String.fromCharCode,
/// hex-encoded strings, and other encoding patterns.
pub fn scan_obfuscation(file: &str, contents: &str) -> Vec<Finding> {
    let patterns = vec![
        // Base64 decode + execute
        (
            Regex::new(r"base64\.(b64)?decode\s*\(").unwrap(),
            "OBFUSC-001",
            Severity::High,
            "Base64 decoding (potential obfuscated payload)",
        ),
        (
            Regex::new(r"atob\s*\(").unwrap(),
            "OBFUSC-002",
            Severity::High,
            "JavaScript atob() — base64 decoding",
        ),
        (
            Regex::new(r#"Buffer\.from\s*\([^)]*,\s*['"]base64['"]"#).unwrap(),
            "OBFUSC-003",
            Severity::High,
            "Node Buffer.from base64 decoding",
        ),
        // String.fromCharCode obfuscation
        (
            Regex::new(r"String\.fromCharCode\s*\(").unwrap(),
            "OBFUSC-004",
            Severity::High,
            "String.fromCharCode — character code obfuscation",
        ),
        (
            Regex::new(r"chr\s*\(\s*\d+\s*\)").unwrap(),
            "OBFUSC-005",
            Severity::Medium,
            "chr() — character code construction",
        ),
        // Hex-encoded strings (long hex sequences)
        (
            Regex::new(r"\x[0-9a-fA-F]{2}(\x[0-9a-fA-F]{2}){7,}").unwrap(),
            "OBFUSC-006",
            Severity::High,
            "Long hex-encoded string (likely obfuscated)",
        ),
        (
            Regex::new(r"0x[0-9a-fA-F]{2}\s*,\s*(0x[0-9a-fA-F]{2}\s*,?\s*){7,}").unwrap(),
            "OBFUSC-007",
            Severity::High,
            "Hex byte array (likely obfuscated payload)",
        ),
        // Unicode escape obfuscation
        (
            Regex::new(r"\u[0-9a-fA-F]{4}(\u[0-9a-fA-F]{4}){5,}").unwrap(),
            "OBFUSC-008",
            Severity::Medium,
            "Long unicode escape sequence",
        ),
        // Python codecs decode
        (
            Regex::new(r"codecs\.(decode|encode)\s*\(").unwrap(),
            "OBFUSC-009",
            Severity::Medium,
            "codecs decode/encode — potential obfuscation",
        ),
        // ROT13 / Caesar cipher
        (
            Regex::new(r#"(?i)(rot13|rot_13|caesar|cipher)\s*[\(\.]"#).unwrap(),
            "OBFUSC-010",
            Severity::Medium,
            "ROT13 / cipher usage — text obfuscation",
        ),
        // Zlib / gzip decompress of inline data
        (
            Regex::new(r"(zlib|gzip)\.(decompress|inflate)\s*\(").unwrap(),
            "OBFUSC-011",
            Severity::Medium,
            "Inline decompression — potential obfuscated payload",
        ),
        // MCP tool definition obfuscation
        (
            Regex::new(r"tool_description.*base64|encoded_tool|obfuscated_prompt").unwrap(),
            "OBFUSC-MCP-001",
            Severity::High,
            "Obfuscated MCP tool definition",
        ),
    ];

    scan_lines(file, contents, Phase::Obfuscation, 5, &patterns)
}

// ---------------------------------------------------------------------------
// Phase 6: Provenance (Low, 1-3x weight)
// ---------------------------------------------------------------------------

/// Detect provenance issues: hidden files, binary files in unexpected locations,
/// git history anomalies, and suspicious file names.
pub fn scan_provenance(base_path: &std::path::Path, entries: &[DirEntry]) -> Vec<Finding> {
    let mut findings = Vec::new();

    for entry in entries {
        let file_path = entry.path();
        let rel_path = file_path
            .strip_prefix(base_path)
            .unwrap_or(file_path)
            .to_string_lossy()
            .to_string();

        // Skip .git directory internals (they are expected)
        if rel_path.starts_with(".git/") || rel_path == ".git" {
            continue;
        }

        let filename = file_path
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_default();

        // Hidden files (dotfiles outside .git)
        if filename.starts_with('.') && filename != ".gitignore" && filename != ".gitkeep" && filename != ".gitattributes" && filename != ".editorconfig" {
            findings.push(make_finding(
                Phase::Provenance,
                "PROV-001",
                Severity::Low,
                &rel_path,
                None,
                &format!("Hidden file: {}", filename),
                1,
            ));
        }

        // Binary files in unexpected locations (not in known binary dirs)
        if is_binary_extension(&filename) {
            let is_expected = rel_path.starts_with("bin/")
                || rel_path.starts_with("dist/")
                || rel_path.starts_with("build/")
                || rel_path.starts_with("node_modules/")
                || rel_path.starts_with("target/")
                || rel_path.starts_with("__pycache__/");

            if !is_expected {
                findings.push(make_finding(
                    Phase::Provenance,
                    "PROV-002",
                    Severity::Medium,
                    &rel_path,
                    None,
                    &format!("Binary file in unexpected location: {}", filename),
                    2,
                ));
            }
        }

        // Suspicious file names
        if is_suspicious_filename(&filename) {
            findings.push(make_finding(
                Phase::Provenance,
                "PROV-003",
                Severity::High,
                &rel_path,
                None,
                &format!("Suspicious filename: {}", filename),
                3,
            ));
        }

        // Very large files (> 5MB)
        if let Ok(metadata) = entry.metadata() {
            if metadata.len() > 5_000_000 {
                findings.push(make_finding(
                    Phase::Provenance,
                    "PROV-004",
                    Severity::Low,
                    &rel_path,
                    None,
                    &format!("Large file: {} bytes", metadata.len()),
                    1,
                ));
            }
        }
    }

    // Check for .git directory presence (squashed / shallow clone detection)
    let git_dir = base_path.join(".git");
    if git_dir.exists() {
        // Check for shallow clone
        let shallow_file = git_dir.join("shallow");
        if shallow_file.exists() {
            findings.push(make_finding(
                Phase::Provenance,
                "PROV-005",
                Severity::Low,
                ".git/shallow",
                None,
                "Shallow clone detected — limited git history available",
                1,
            ));
        }
    } else if base_path.join("package.json").exists() || base_path.join("setup.py").exists() {
        findings.push(make_finding(
            Phase::Provenance,
            "PROV-006",
            Severity::Medium,
            ".",
            None,
            "No .git directory — provenance cannot be verified via git history",
            2,
        ));
    }

    findings
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Check if a filename has a known binary extension.
fn is_binary_extension(filename: &str) -> bool {
    let binary_extensions = [
        ".exe", ".dll", ".so", ".dylib", ".bin", ".dat", ".o", ".a",
        ".pyc", ".pyo", ".class", ".jar", ".war", ".ear",
        ".wasm", ".node",
    ];
    let lower = filename.to_lowercase();
    binary_extensions.iter().any(|ext| lower.ends_with(ext))
}

/// Check if a filename looks suspicious.
fn is_suspicious_filename(filename: &str) -> bool {
    let suspicious_patterns = [
        "backdoor",
        "exploit",
        "payload",
        "reverse_shell",
        "keylogger",
        "stealer",
        "trojan",
        "rootkit",
        "c2_",
        "c2-",
        "rat_",
        "rat-",
    ];
    let lower = filename.to_lowercase();
    suspicious_patterns.iter().any(|p| lower.contains(p))
}
