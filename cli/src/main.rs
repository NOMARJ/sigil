mod api;
mod cache;
mod diff;
mod output;
mod policy;
mod provider;
mod quarantine;
mod sandbox;
mod sbom;
mod scanner;

use clap::{Parser, Subcommand};
use colored::Colorize;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process;

/// Sigil -- Automated security auditing for AI agent code.
///
/// Scans repositories, packages, and agent tooling for malicious patterns
/// using a quarantine-first workflow.
#[derive(Parser)]
#[command(name = "sigil", version, about, long_about = None)]
struct Cli {
    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Output format (text, json)
    #[arg(short, long, global = true, default_value = "text")]
    format: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Clone a git repository into quarantine and scan it
    Clone {
        /// Git repository URL to clone
        url: String,

        /// Branch to clone
        #[arg(short, long)]
        branch: Option<String>,

        /// Automatically approve if scan passes
        #[arg(long)]
        auto_approve: bool,
    },

    /// Download and scan a pip package
    Pip {
        /// Package name (optionally with version, e.g. package==1.0.0)
        package: String,

        /// Specific version to download
        #[arg(short = 'V', long)]
        version: Option<String>,

        /// Automatically approve if scan passes
        #[arg(long)]
        auto_approve: bool,
    },

    /// Download and scan an npm package
    Npm {
        /// Package name (optionally with version, e.g. package@1.0.0)
        package: String,

        /// Specific version to download
        #[arg(short = 'V', long)]
        version: Option<String>,

        /// Automatically approve if scan passes
        #[arg(long)]
        auto_approve: bool,
    },

    /// Scan an existing directory or file
    Scan {
        /// Path to scan
        path: PathBuf,

        /// Phases to run (comma-separated, or "all")
        #[arg(short, long, default_value = "all")]
        phases: String,

        /// Minimum severity to report (low, medium, high, critical)
        #[arg(short, long, default_value = "low")]
        severity: String,

        /// Submit results to Sigil cloud
        #[arg(long)]
        submit: bool,

        /// Disable cache (force a fresh scan even if content is unchanged)
        #[arg(long)]
        no_cache: bool,

        /// Enrich scan with cloud threat intelligence (hash lookup)
        #[arg(long)]
        enrich: bool,

        /// Use enhanced LLM-powered analysis (Pro feature, requires authentication)
        #[arg(long)]
        enhanced: bool,
    },

    /// Clear all cached scan results
    ClearCache,

    /// Fetch latest threat signatures from Sigil cloud
    Fetch {
        /// Force re-download even if signatures are fresh
        #[arg(short, long)]
        force: bool,
    },

    /// Approve a quarantined item
    Approve {
        /// Quarantine ID to approve
        id: String,

        /// Reason for approval
        #[arg(short, long)]
        reason: Option<String>,
    },

    /// Reject a quarantined item and remove it
    Reject {
        /// Quarantine ID to reject
        id: String,

        /// Reason for rejection
        #[arg(short, long)]
        reason: Option<String>,
    },

    /// List quarantined items
    List {
        /// Filter by status (pending, approved, rejected)
        #[arg(short, long)]
        status: Option<String>,

        /// Show detailed information
        #[arg(short, long)]
        detailed: bool,
    },

    /// Install sigil to system PATH
    Install {
        /// Installation directory
        #[arg(short, long)]
        path: Option<PathBuf>,
    },

    /// Authenticate with Sigil cloud
    Login {
        /// API token (if not provided, interactive login is used)
        #[arg(short, long)]
        token: Option<String>,

        /// API endpoint URL
        #[arg(long, default_value = "https://api.sigilsec.ai")]
        endpoint: String,
    },

    /// Report a threat to the Sigil cloud
    Report {
        /// SHA256 hash of the malicious file
        hash: String,

        /// Type of threat (e.g. malware, backdoor, exfil)
        #[arg(short = 't', long)]
        threat_type: String,

        /// Description of the threat
        #[arg(short, long)]
        description: String,
    },

    /// Compare a scan against a baseline to find new/resolved findings
    Diff {
        /// Path to baseline scan result JSON file
        #[arg(long)]
        baseline: String,

        /// Path to scan (runs a fresh scan and compares)
        path: PathBuf,
    },

    /// View or modify configuration
    Config {
        /// Configuration key to get or set
        key: Option<String>,

        /// Value to set (if omitted, prints current value)
        value: Option<String>,

        /// List all configuration values
        #[arg(short, long)]
        list: bool,
    },

    /// Manage credential providers for sandboxed execution
    Provider {
        #[command(subcommand)]
        action: ProviderAction,
    },

    /// Generate or inspect security policies
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },

    /// Run a command in a sandboxed environment with policy enforcement
    Run {
        /// Policy file or preset name (strict, standard, permissive)
        #[arg(short, long, default_value = "standard")]
        policy: String,
        /// Credential providers to include (comma-separated)
        #[arg(long)]
        providers: Option<String>,
        /// Show detailed sandbox configuration
        #[arg(short, long)]
        verbose: bool,
        /// Command and arguments to run (after --)
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },

    /// Generate Software Bill of Materials for a project
    Sbom {
        /// Project path to analyze
        path: PathBuf,

        /// Output format: table, cyclonedx, json
        #[arg(short = 'F', long, default_value = "table")]
        sbom_format: String,

        /// Path to known_threats.json for cross-referencing
        #[arg(long)]
        threats_db: Option<PathBuf>,

        /// Output to file instead of stdout
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Scan a path, generate a security policy, and run a command in a sandbox
    SafeRun {
        /// Path to scan and use as working directory
        path: PathBuf,

        /// Credential providers (comma-separated)
        #[arg(long)]
        providers: Option<String>,

        /// Auto-approve HIGH risk (skip confirmation prompt)
        #[arg(long)]
        auto_approve: bool,

        /// Show detailed output
        #[arg(short, long)]
        verbose: bool,

        /// Command to run (after --)
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
}

#[derive(Subcommand)]
enum ProviderAction {
    /// Create a new credential provider
    Create {
        /// Provider name
        #[arg(short, long)]
        name: String,
        /// Comma-separated env var names
        #[arg(short, long)]
        vars: String,
        /// Description
        #[arg(short, long)]
        description: Option<String>,
    },
    /// List all saved providers
    List,
    /// Show details of a provider
    Show {
        /// Provider name
        name: String,
    },
    /// Delete a provider
    Delete {
        /// Provider name
        name: String,
    },
    /// Auto-discover credentials in current environment
    Discover,
}

#[derive(Subcommand)]
enum PolicyAction {
    /// Generate a policy from scan results
    Generate {
        /// Path to scan
        path: PathBuf,
        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Show the scan results alongside the policy
        #[arg(long)]
        verbose: bool,
    },
    /// Validate a policy file
    Validate {
        /// Path to policy YAML file
        file: PathBuf,
    },
    /// Show a built-in preset policy
    Preset {
        /// Preset name: strict, standard, permissive
        name: String,
    },
}

#[tokio::main]
async fn main() {
    // Set up global panic handler to prevent crashes during scanning
    std::panic::set_hook(Box::new(|panic_info| {
        use colored::Colorize;
        eprintln!(
            "{} SCAN_ERROR: Panic occurred during scanning",
            "sigil:".bold().red()
        );

        if let Some(location) = panic_info.location() {
            eprintln!(
                "  Location: {}:{}:{}",
                location.file(),
                location.line(),
                location.column()
            );
        }

        if let Some(msg) = panic_info.payload().downcast_ref::<&str>() {
            eprintln!("  Message: {}", msg);
        } else if let Some(msg) = panic_info.payload().downcast_ref::<String>() {
            eprintln!("  Message: {}", msg);
        }

        eprintln!("  This is likely a Unicode boundary error in file processing.");
        eprintln!("  Continuing scan with remaining files...");
    }));

    let cli = Cli::parse();

    if cli.verbose {
        eprintln!("{} verbose mode enabled", "sigil:".bold().cyan());
    }

    let exit_code = match cli.command {
        Commands::Clone {
            url,
            branch,
            auto_approve,
        } => {
            cmd_clone(
                &url,
                branch.as_deref(),
                auto_approve,
                &cli.format,
                cli.verbose,
            )
            .await
        }

        Commands::Pip {
            package,
            version,
            auto_approve,
        } => {
            cmd_pip(
                &package,
                version.as_deref(),
                auto_approve,
                &cli.format,
                cli.verbose,
            )
            .await
        }

        Commands::Npm {
            package,
            version,
            auto_approve,
        } => {
            cmd_npm(
                &package,
                version.as_deref(),
                auto_approve,
                &cli.format,
                cli.verbose,
            )
            .await
        }

        Commands::Scan {
            path,
            phases,
            severity,
            submit,
            no_cache,
            enrich,
            enhanced,
        } => {
            cmd_scan(
                &path,
                &phases,
                &severity,
                submit,
                no_cache,
                enrich,
                enhanced,
                &cli.format,
                cli.verbose,
            )
            .await
        }

        Commands::ClearCache => cmd_clear_cache().await,

        Commands::Fetch { force } => cmd_fetch(force, cli.verbose).await,

        Commands::Approve { id, reason } => cmd_approve(&id, reason.as_deref(), cli.verbose).await,

        Commands::Reject { id, reason } => cmd_reject(&id, reason.as_deref(), cli.verbose).await,

        Commands::List { status, detailed } => {
            cmd_list(status.as_deref(), detailed, &cli.format, cli.verbose).await
        }

        Commands::Install { path } => cmd_install(path.as_deref(), cli.verbose).await,

        Commands::Login { token, endpoint } => {
            cmd_login(token.as_deref(), &endpoint, cli.verbose).await
        }

        Commands::Report {
            hash,
            threat_type,
            description,
        } => cmd_report(&hash, &threat_type, &description, cli.verbose).await,

        Commands::Diff { baseline, path } => {
            cmd_diff(&baseline, &path, &cli.format, cli.verbose).await
        }

        Commands::Config { key, value, list } => {
            cmd_config(key.as_deref(), value.as_deref(), list, cli.verbose).await
        }

        Commands::Run {
            policy,
            providers,
            verbose,
            command,
        } => cmd_run(&policy, providers.as_deref(), verbose, command).await,

        Commands::Provider { action } => cmd_provider(action).await,

        Commands::Policy { action } => cmd_policy(action).await,

        Commands::Sbom {
            path,
            sbom_format,
            threats_db,
            output,
        } => {
            cmd_sbom(
                &path,
                &sbom_format,
                threats_db.as_deref(),
                output.as_deref(),
                cli.verbose,
            )
            .await
        }

        Commands::SafeRun {
            path,
            providers,
            auto_approve,
            verbose,
            command,
        } => {
            let provider_list: Option<Vec<String>> =
                providers.map(|p| p.split(',').map(|s| s.trim().to_string()).collect());
            match sandbox::safe_run::safe_run(
                &path,
                &command,
                provider_list.as_deref(),
                auto_approve,
                verbose,
            ) {
                Ok(code) => code,
                Err(e) => {
                    eprintln!("error: {}", e);
                    1
                }
            }
        }
    };

    process::exit(exit_code);
}

// ---------------------------------------------------------------------------
// Archive extraction helper
// ---------------------------------------------------------------------------

/// Extract .whl/.zip and .tar.gz/.tgz archives in a directory so the scanner
/// can inspect the actual source files inside packages.
fn extract_archives(dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let entries: Vec<_> = std::fs::read_dir(dir)?.filter_map(|e| e.ok()).collect();

    for entry in entries {
        let path = entry.path();
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        if name.ends_with(".whl") || name.ends_with(".zip") {
            // Extract zip archives (.whl files are zip format)
            let file = std::fs::File::open(&path)?;
            let mut archive = zip::ZipArchive::new(file)?;
            let extract_dir = dir.join(name.trim_end_matches(".whl").trim_end_matches(".zip"));
            std::fs::create_dir_all(&extract_dir)?;
            archive.extract(&extract_dir)?;
            std::fs::remove_file(&path)?;
        } else if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
            // Extract gzipped tar archives
            let file = std::fs::File::open(&path)?;
            let gz = flate2::read::GzDecoder::new(file);
            let mut archive = tar::Archive::new(gz);
            let extract_dir = dir.join(name.trim_end_matches(".tar.gz").trim_end_matches(".tgz"));
            std::fs::create_dir_all(&extract_dir)?;
            archive.unpack(&extract_dir)?;
            std::fs::remove_file(&path)?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Command implementations
// ---------------------------------------------------------------------------

async fn cmd_clone(
    url: &str,
    branch: Option<&str>,
    auto_approve: bool,
    format: &str,
    verbose: bool,
) -> i32 {
    println!(
        "{} cloning {} into quarantine...",
        "sigil:".bold().cyan(),
        url.bold()
    );

    // 1. Create quarantine entry
    let entry = match quarantine::add(url, "git") {
        Ok(e) => e,
        Err(err) => {
            eprintln!(
                "{} failed to create quarantine entry: {}",
                "error:".bold().red(),
                err
            );
            return 1;
        }
    };

    if verbose {
        eprintln!("quarantine id: {}", entry.id);
        eprintln!("quarantine path: {}", entry.path.display());
    }

    // 2. Clone repo into quarantine path
    let mut cmd = std::process::Command::new("git");
    cmd.arg("clone").arg("--depth").arg("1");
    if let Some(b) = branch {
        cmd.arg("--branch").arg(b);
    }
    cmd.arg(url).arg(&entry.path);

    let status = cmd.status();
    match status {
        Ok(s) if s.success() => {}
        _ => {
            eprintln!("{} git clone failed", "error:".bold().red());
            return 1;
        }
    }

    // 3. Scan the cloned repo
    let result = scanner::run_scan(&entry.path, None, None);
    output::print_scan_summary(&result, format);
    output::print_findings(&result.findings, format);
    output::print_verdict(&result.verdict, format);

    // 4. Auto-approve if requested and scan is low risk
    if auto_approve && result.verdict == scanner::Verdict::LowRisk {
        if let Err(err) = quarantine::approve(&entry.id, Some("auto-approved: low risk scan")) {
            eprintln!(
                "{} failed to auto-approve: {}",
                "warning:".bold().yellow(),
                err
            );
        } else {
            println!("{} auto-approved (low risk)", "sigil:".bold().green());
        }
    }

    match result.verdict {
        scanner::Verdict::LowRisk => 0,
        scanner::Verdict::MediumRisk => 1,
        _ => 2,
    }
}

async fn cmd_pip(
    package: &str,
    version: Option<&str>,
    auto_approve: bool,
    format: &str,
    verbose: bool,
) -> i32 {
    let pkg_spec = match version {
        Some(v) => format!("{}=={}", package, v),
        None => package.to_string(),
    };

    println!(
        "{} downloading pip package {} into quarantine...",
        "sigil:".bold().cyan(),
        pkg_spec.bold()
    );

    let entry = match quarantine::add(&pkg_spec, "pip") {
        Ok(e) => e,
        Err(err) => {
            eprintln!(
                "{} failed to create quarantine entry: {}",
                "error:".bold().red(),
                err
            );
            return 1;
        }
    };

    if verbose {
        eprintln!("quarantine id: {}", entry.id);
    }

    // Download pip package into quarantine
    let status = std::process::Command::new("pip")
        .arg("download")
        .arg("--no-deps")
        .arg("--dest")
        .arg(&entry.path)
        .arg(&pkg_spec)
        .status();

    match status {
        Ok(s) if s.success() => {}
        _ => {
            eprintln!("{} pip download failed", "error:".bold().red());
            return 1;
        }
    }

    // Extract .whl (zip) and .tar.gz files so the scanner sees actual source
    if let Err(err) = extract_archives(&entry.path) {
        eprintln!(
            "{} failed to extract archives: {} (scanning raw archives instead)",
            "warning:".bold().yellow(),
            err
        );
    }

    let result = scanner::run_scan(&entry.path, None, None);
    output::print_scan_summary(&result, format);
    output::print_findings(&result.findings, format);
    output::print_verdict(&result.verdict, format);

    if auto_approve && result.verdict == scanner::Verdict::LowRisk {
        if let Err(err) = quarantine::approve(&entry.id, Some("auto-approved: low risk scan")) {
            eprintln!(
                "{} failed to auto-approve: {}",
                "warning:".bold().yellow(),
                err
            );
        } else {
            println!("{} auto-approved (low risk)", "sigil:".bold().green());
        }
    }

    match result.verdict {
        scanner::Verdict::LowRisk => 0,
        scanner::Verdict::MediumRisk => 1,
        _ => 2,
    }
}

async fn cmd_npm(
    package: &str,
    version: Option<&str>,
    auto_approve: bool,
    format: &str,
    verbose: bool,
) -> i32 {
    let pkg_spec = match version {
        Some(v) => format!("{}@{}", package, v),
        None => package.to_string(),
    };

    println!(
        "{} downloading npm package {} into quarantine...",
        "sigil:".bold().cyan(),
        pkg_spec.bold()
    );

    let entry = match quarantine::add(&pkg_spec, "npm") {
        Ok(e) => e,
        Err(err) => {
            eprintln!(
                "{} failed to create quarantine entry: {}",
                "error:".bold().red(),
                err
            );
            return 1;
        }
    };

    if verbose {
        eprintln!("quarantine id: {}", entry.id);
    }

    // Download npm package into quarantine
    let status = std::process::Command::new("npm")
        .arg("pack")
        .arg(&pkg_spec)
        .current_dir(&entry.path)
        .status();

    match status {
        Ok(s) if s.success() => {}
        _ => {
            eprintln!("{} npm pack failed", "error:".bold().red());
            return 1;
        }
    }

    // Extract .tgz files so the scanner sees actual source
    if let Err(err) = extract_archives(&entry.path) {
        eprintln!(
            "{} failed to extract archives: {} (scanning raw archives instead)",
            "warning:".bold().yellow(),
            err
        );
    }

    let result = scanner::run_scan(&entry.path, None, None);
    output::print_scan_summary(&result, format);
    output::print_findings(&result.findings, format);
    output::print_verdict(&result.verdict, format);

    if auto_approve && result.verdict == scanner::Verdict::LowRisk {
        if let Err(err) = quarantine::approve(&entry.id, Some("auto-approved: low risk scan")) {
            eprintln!(
                "{} failed to auto-approve: {}",
                "warning:".bold().yellow(),
                err
            );
        } else {
            println!("{} auto-approved (low risk)", "sigil:".bold().green());
        }
    }

    match result.verdict {
        scanner::Verdict::LowRisk => 0,
        scanner::Verdict::MediumRisk => 1,
        _ => 2,
    }
}

#[allow(clippy::too_many_arguments)]
async fn cmd_scan(
    path: &Path,
    phases: &str,
    severity: &str,
    submit: bool,
    no_cache: bool,
    enrich: bool,
    enhanced: bool,
    format: &str,
    verbose: bool,
) -> i32 {
    if !path.exists() {
        eprintln!(
            "{} path does not exist: {}",
            "error:".bold().red(),
            path.display()
        );
        return 1;
    }

    println!(
        "{} scanning {}...",
        "sigil:".bold().cyan(),
        path.display().to_string().bold()
    );

    // --- Cache: only use when running a full unfiltered scan ---
    let use_cache = !no_cache && phases == "all" && severity == "low";

    // Try loading from cache
    if use_cache {
        if let Some(cached) = cache::load_cached(path) {
            println!("{} using cached result", "sigil:".bold().green(),);
            output::print_scan_summary(&cached, format);
            output::print_findings(&cached.findings, format);
            output::print_verdict(&cached.verdict, format);
            return match cached.verdict {
                scanner::Verdict::LowRisk => 0,
                _ => 2,
            };
        } else if verbose {
            eprintln!("no cache entry found, scanning fresh");
        }
    }

    // Parse phase filter
    let phase_filter: Option<Vec<String>> = if phases == "all" {
        None
    } else {
        Some(phases.split(',').map(|s| s.trim().to_string()).collect())
    };

    // Parse severity filter
    let min_severity: Option<&str> = if severity == "low" {
        None // "low" is the default minimum, meaning show everything
    } else {
        Some(severity)
    };

    let result = scanner::run_scan(path, phase_filter.as_deref(), min_severity);

    if format == "sarif" {
        output::print_scan_sarif(&result, &path.to_string_lossy());
    } else {
        output::print_scan_summary(&result, format);
        output::print_findings(&result.findings, format);
        output::print_verdict(&result.verdict, format);
    }

    // Save to cache
    if use_cache {
        if let Err(err) = cache::save_to_cache(path, &result) {
            if verbose {
                eprintln!("cache save failed: {}", err);
            }
        } else if verbose {
            eprintln!("result cached successfully");
        }
    }

    // --- Cloud threat enrichment -------------------------------------------
    if enrich {
        let dir_hash = compute_directory_hash(path);
        if verbose {
            eprintln!("directory hash: {}", dir_hash);
            eprintln!("checking hash against cloud threat database...");
        }

        let client = api::SigilClient::new(None);
        match client.lookup_threat(&dir_hash).await {
            Ok(info) => {
                if info.known_malicious {
                    println!(
                        "\n  {} {} is a known threat: {}",
                        "THREAT INTEL:".bold().red(),
                        path.display(),
                        info.description.as_deref().unwrap_or("no description")
                    );
                    if let Some(threat_type) = &info.threat_type {
                        println!("  Type: {}", threat_type);
                    }
                } else if verbose {
                    eprintln!("no threat intel match for this target");
                }
            }
            Err(err) => {
                if verbose {
                    eprintln!(
                        "{} cloud enrichment unavailable: {}",
                        "warning:".bold().yellow(),
                        err
                    );
                }
            }
        }
    }

    // --- Enhanced LLM analysis (Pro feature) -------------------------------
    if enhanced {
        let client = api::SigilClient::new(None);

        if !client.is_authenticated() {
            eprintln!(
                "{} Enhanced scanning requires authentication. Run: sigil login",
                "error:".bold().red()
            );
            return 1;
        }

        if verbose {
            eprintln!("collecting file contents for LLM analysis...");
        }

        // Collect file contents for LLM analysis (limit to reasonable size)
        let file_contents = collect_file_contents(path, 50, verbose);

        if file_contents.is_empty() {
            eprintln!(
                "{} no readable files found for LLM analysis",
                "warning:".bold().yellow()
            );
        } else {
            if verbose {
                eprintln!(
                    "submitting {} files for enhanced LLM analysis...",
                    file_contents.len()
                );
            }

            match client.submit_enhanced_scan(&result, file_contents).await {
                Ok(response) => {
                    println!(
                        "\n{} Enhanced LLM analysis completed",
                        "sigil:".bold().green()
                    );
                    if verbose {
                        eprintln!("  Scan ID: {}", response.id);
                        if let Some(msg) = response.message {
                            eprintln!("  Message: {}", msg);
                        }
                    }
                }
                Err(err) => {
                    eprintln!(
                        "{} Enhanced analysis failed: {}",
                        "warning:".bold().yellow(),
                        err
                    );
                    eprintln!("  Continuing with static analysis results only");
                }
            }
        }
    }

    if submit {
        if verbose {
            eprintln!("submitting results to Sigil cloud...");
        }
        let client = api::SigilClient::new(None);
        match client.submit_scan(&result).await {
            Ok(_) => println!(
                "{} results submitted to Sigil cloud",
                "sigil:".bold().green()
            ),
            Err(err) => eprintln!(
                "{} failed to submit results: {} (continuing offline)",
                "warning:".bold().yellow(),
                err
            ),
        }
    }

    match result.verdict {
        scanner::Verdict::LowRisk => 0,
        _ => 2,
    }
}

// ---------------------------------------------------------------------------
// Hash computation
// ---------------------------------------------------------------------------

/// Compute a SHA-256 hash of a directory's contents (file paths + sizes).
/// Used for threat intel lookups and cache invalidation.
fn compute_directory_hash(path: &Path) -> String {
    use sha2::{Digest, Sha256};
    use walkdir::WalkDir;

    let mut hasher = Sha256::new();

    let mut entries: Vec<_> = WalkDir::new(path)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .collect();

    // Sort for deterministic hashing
    entries.sort_by_key(|e| e.path().to_path_buf());

    for entry in &entries {
        let rel_path = entry
            .path()
            .strip_prefix(path)
            .unwrap_or(entry.path())
            .to_string_lossy();
        hasher.update(rel_path.as_bytes());

        if let Ok(metadata) = entry.metadata() {
            hasher.update(metadata.len().to_le_bytes());
        }
    }

    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// File contents collection for LLM analysis
// ---------------------------------------------------------------------------

/// Collect file contents for LLM analysis.
/// Limits the number of files and skips binary/large files for cost control.
fn collect_file_contents(
    path: &Path,
    max_files: usize,
    verbose: bool,
) -> std::collections::HashMap<String, String> {
    use walkdir::WalkDir;

    let mut file_contents = std::collections::HashMap::new();
    let mut files_collected = 0;

    // Common text file extensions to prioritize
    let text_extensions = [
        "py", "js", "ts", "jsx", "tsx", "rs", "go", "java", "c", "cpp", "h", "hpp", "rb", "php",
        "sh", "bash", "zsh", "ps1", "yaml", "yml", "json", "toml", "xml", "md", "txt", "sql", "r",
        "scala", "kt", "swift", "m", "cs", "vb", "pl", "lua",
    ];

    let entries: Vec<_> = WalkDir::new(path)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .collect();

    for entry in entries {
        if files_collected >= max_files {
            if verbose {
                eprintln!("Reached max file limit ({}) for LLM analysis", max_files);
            }
            break;
        }

        let file_path = entry.path();

        // Check if file has a text extension
        let has_text_ext = file_path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| text_extensions.contains(&ext))
            .unwrap_or(false);

        if !has_text_ext {
            continue;
        }

        // Skip files larger than 100KB to control costs
        if let Ok(metadata) = entry.metadata() {
            if metadata.len() > 100_000 {
                if verbose {
                    eprintln!(
                        "Skipping large file: {} ({} bytes)",
                        file_path.display(),
                        metadata.len()
                    );
                }
                continue;
            }
        }

        // Try to read file contents with lossy UTF-8 handling
        match std::fs::read(file_path) {
            Ok(bytes) => {
                // Check for binary content (contains null bytes)
                if bytes.contains(&0) {
                    if verbose {
                        eprintln!("Skipping binary file: {}", file_path.display());
                    }
                    continue;
                }

                let contents = String::from_utf8_lossy(&bytes).into_owned();
                let rel_path = file_path
                    .strip_prefix(path)
                    .unwrap_or(file_path)
                    .to_string_lossy()
                    .to_string();

                file_contents.insert(rel_path, contents);
                files_collected += 1;
            }
            Err(_) => {
                // Skip unreadable files
                continue;
            }
        }
    }

    if verbose && files_collected > 0 {
        eprintln!("Collected {} files for LLM analysis", files_collected);
    }

    file_contents
}

async fn cmd_diff(baseline_path: &str, scan_path: &Path, format: &str, verbose: bool) -> i32 {
    // Load baseline
    let baseline_data = match std::fs::read_to_string(baseline_path) {
        Ok(data) => data,
        Err(err) => {
            eprintln!(
                "{} failed to read baseline file '{}': {}",
                "error:".bold().red(),
                baseline_path,
                err
            );
            return 1;
        }
    };

    let baseline_result: scanner::ScanResult = match serde_json::from_str(&baseline_data) {
        Ok(result) => result,
        Err(err) => {
            eprintln!(
                "{} failed to parse baseline JSON: {}",
                "error:".bold().red(),
                err
            );
            return 1;
        }
    };

    if verbose {
        eprintln!(
            "loaded baseline: {} findings, score {}",
            baseline_result.findings.len(),
            baseline_result.score
        );
    }

    // Run current scan
    let current_result = scanner::run_scan(scan_path, None, None);

    let diff_result = diff::diff_scans(&baseline_result, &current_result);

    if format == "json" {
        println!("{}", serde_json::to_string_pretty(&diff_result).unwrap());
    } else {
        println!("\n  {} {}", "Scan Diff:".bold(), diff_result.summary);

        if !diff_result.new_findings.is_empty() {
            println!(
                "\n  {} ({}):",
                "NEW FINDINGS".bold().red(),
                diff_result.new_findings.len()
            );
            for f in &diff_result.new_findings {
                println!(
                    "    {} [{}] {:?} in {} (line {})",
                    "+".green(),
                    f.rule,
                    f.severity,
                    f.file,
                    f.line.unwrap_or(0)
                );
            }
        }

        if !diff_result.resolved_findings.is_empty() {
            println!(
                "\n  {} ({}):",
                "RESOLVED".bold().green(),
                diff_result.resolved_findings.len()
            );
            for f in &diff_result.resolved_findings {
                println!(
                    "    {} [{}] {:?} in {} (line {})",
                    "-".red(),
                    f.rule,
                    f.severity,
                    f.file,
                    f.line.unwrap_or(0)
                );
            }
        }

        if diff_result.new_findings.is_empty() && diff_result.resolved_findings.is_empty() {
            println!("  {}", "No changes detected.".dimmed());
        }
    }

    // Exit with non-zero if new findings were introduced
    if !diff_result.new_findings.is_empty() {
        2
    } else {
        0
    }
}

async fn cmd_clear_cache() -> i32 {
    match cache::clear_cache() {
        Ok(count) => {
            println!(
                "{} cleared {} cached scan result(s)",
                "sigil:".bold().green(),
                count
            );
            0
        }
        Err(err) => {
            eprintln!("{} failed to clear cache: {}", "error:".bold().red(), err);
            1
        }
    }
}

async fn cmd_fetch(force: bool, verbose: bool) -> i32 {
    println!(
        "{} fetching latest threat signatures...",
        "sigil:".bold().cyan()
    );

    let client = api::SigilClient::new(None);
    match client.get_signatures(force).await {
        Ok(count) => {
            println!("{} fetched {} signatures", "sigil:".bold().green(), count);
            0
        }
        Err(err) => {
            eprintln!(
                "{} failed to fetch signatures: {}",
                "error:".bold().red(),
                err
            );
            if verbose {
                eprintln!("hint: check your network connection or API token");
            }
            1
        }
    }
}

async fn cmd_approve(id: &str, reason: Option<&str>, verbose: bool) -> i32 {
    if verbose {
        eprintln!("approving quarantine entry: {}", id);
    }

    match quarantine::approve(id, reason) {
        Ok(entry) => {
            println!(
                "{} approved {} ({})",
                "sigil:".bold().green(),
                entry.id,
                entry.source
            );
            0
        }
        Err(err) => {
            eprintln!("{} {}", "error:".bold().red(), err);
            1
        }
    }
}

async fn cmd_reject(id: &str, reason: Option<&str>, verbose: bool) -> i32 {
    if verbose {
        eprintln!("rejecting quarantine entry: {}", id);
    }

    match quarantine::reject(id, reason) {
        Ok(entry) => {
            println!(
                "{} rejected {} ({})",
                "sigil:".bold().red(),
                entry.id,
                entry.source
            );
            0
        }
        Err(err) => {
            eprintln!("{} {}", "error:".bold().red(), err);
            1
        }
    }
}

async fn cmd_list(status: Option<&str>, detailed: bool, format: &str, _verbose: bool) -> i32 {
    match quarantine::list(status) {
        Ok(entries) => {
            if entries.is_empty() {
                println!("{} no quarantined items found", "sigil:".bold().cyan());
                return 0;
            }

            output::print_quarantine_list(&entries, detailed, format);
            0
        }
        Err(err) => {
            eprintln!("{} {}", "error:".bold().red(), err);
            1
        }
    }
}

async fn cmd_install(path: Option<&std::path::Path>, verbose: bool) -> i32 {
    let install_dir = path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("/usr/local/bin"));

    println!(
        "{} installing sigil to {}...",
        "sigil:".bold().cyan(),
        install_dir.display()
    );

    let target = install_dir.join("sigil");

    // Get the path of the currently running binary
    let current_exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(err) => {
            eprintln!(
                "{} cannot determine current binary path: {}",
                "error:".bold().red(),
                err
            );
            return 1;
        }
    };

    if verbose {
        eprintln!("copying {} -> {}", current_exe.display(), target.display());
    }

    match std::fs::copy(&current_exe, &target) {
        Ok(_) => {
            println!(
                "{} installed successfully to {}",
                "sigil:".bold().green(),
                target.display()
            );
            0
        }
        Err(err) => {
            eprintln!("{} installation failed: {}", "error:".bold().red(), err);
            eprintln!("hint: you may need to run with sudo");
            1
        }
    }
}

async fn cmd_login(token: Option<&str>, endpoint: &str, verbose: bool) -> i32 {
    if verbose {
        eprintln!("authenticating with {}", endpoint);
    }

    let client = api::SigilClient::new(Some(endpoint.to_string()));

    match token {
        Some(t) => match client.login_with_token(t).await {
            Ok(_) => {
                println!("{} authenticated successfully", "sigil:".bold().green());
                0
            }
            Err(err) => {
                eprintln!("{} authentication failed: {}", "error:".bold().red(), err);
                1
            }
        },
        None => {
            // Interactive login: prompt for email and password
            print!("Email: ");
            if io::stdout().flush().is_err() {
                eprintln!("{} failed to flush stdout", "error:".bold().red());
                return 1;
            }
            let mut email = String::new();
            if io::stdin().read_line(&mut email).is_err() {
                eprintln!("{} failed to read email", "error:".bold().red());
                return 1;
            }
            let email = email.trim();

            print!("Password: ");
            if io::stdout().flush().is_err() {
                eprintln!("{} failed to flush stdout", "error:".bold().red());
                return 1;
            }
            let mut password = String::new();
            if io::stdin().read_line(&mut password).is_err() {
                eprintln!("{} failed to read password", "error:".bold().red());
                return 1;
            }
            let password = password.trim();

            match client.login(email, password).await {
                Ok(_) => {
                    println!("{} logged in successfully", "sigil:".bold().green());
                    0
                }
                Err(err) => {
                    eprintln!("{} login failed: {}", "error:".bold().red(), err);
                    1
                }
            }
        }
    }
}

async fn cmd_report(hash: &str, threat_type: &str, description: &str, verbose: bool) -> i32 {
    if verbose {
        eprintln!("reporting threat: hash={}", hash);
    }

    let client = api::SigilClient::new(None);

    if !client.is_authenticated() {
        eprintln!(
            "{} you must be logged in to report threats (run: sigil login)",
            "error:".bold().red()
        );
        return 1;
    }

    match client.report_threat(hash, threat_type, description).await {
        Ok(response) => {
            println!(
                "{} threat reported successfully (id: {})",
                "sigil:".bold().green(),
                response.id
            );
            0
        }
        Err(err) => {
            eprintln!("{} failed to report threat: {}", "error:".bold().red(), err);
            1
        }
    }
}

async fn cmd_run(
    policy_name: &str,
    providers: Option<&str>,
    verbose: bool,
    command: Vec<String>,
) -> i32 {
    use std::collections::HashMap;

    // 1. Load policy: try as file path first, then as preset name
    let policy_path = std::path::Path::new(policy_name);
    let policy = if policy_path.exists() {
        match policy::schema::SigilPolicy::from_file(policy_path) {
            Ok(p) => p,
            Err(err) => {
                eprintln!(
                    "{} failed to load policy file '{}': {}",
                    "error:".bold().red(),
                    policy_name,
                    err
                );
                return 1;
            }
        }
    } else {
        match policy::schema::SigilPolicy::preset(policy_name) {
            Some(p) => p,
            None => {
                eprintln!(
                    "{} unknown policy '{}'. Use: strict, standard, permissive, or a file path.",
                    "error:".bold().red(),
                    policy_name
                );
                return 1;
            }
        }
    };

    // 2. Resolve credentials
    let env_vars: HashMap<String, String> = if let Some(provider_list) = providers {
        // Explicit --providers flag: use provider::resolve_env()
        let provider_names: Vec<String> = provider_list
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();
        provider::resolve_env(&provider_names)
    } else {
        // No explicit providers: filter current env by policy's allowed_env list
        let mut filtered = HashMap::new();
        for pattern in &policy.credentials.allowed_env {
            if pattern == "*" {
                // Wildcard: include all env vars
                for (key, value) in std::env::vars() {
                    // Still respect denied list
                    if !policy.credentials.denied_env.contains(&key)
                        && !policy.credentials.denied_env.contains(&"*".to_string())
                    {
                        filtered.insert(key, value);
                    }
                }
            } else if let Ok(value) = std::env::var(pattern) {
                filtered.insert(pattern.clone(), value);
            }
        }
        filtered
    };

    if verbose {
        println!(
            "{} policy: {} ({})",
            "sigil:".bold().cyan(),
            policy.name.bold(),
            policy.description.as_deref().unwrap_or("no description")
        );
        println!(
            "  {} environment variables injected",
            env_vars.len().to_string().bold()
        );
        for key in env_vars.keys() {
            println!("    - {}", key);
        }
    }

    let workdir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

    // 3. Run sandboxed
    match sandbox::container::run_sandboxed(&policy, &workdir, &command, &env_vars, verbose) {
        Ok(exit_code) => exit_code,
        Err(err) => {
            eprintln!(
                "{} sandbox execution failed: {}",
                "error:".bold().red(),
                err
            );
            1
        }
    }
}

async fn cmd_provider(action: ProviderAction) -> i32 {
    match action {
        ProviderAction::Create {
            name,
            vars,
            description,
        } => {
            let var_list: Vec<String> = vars.split(',').map(|s| s.trim().to_string()).collect();

            if var_list.is_empty() || var_list.iter().all(|v| v.is_empty()) {
                eprintln!(
                    "{} no environment variable names provided",
                    "error:".bold().red()
                );
                return 1;
            }

            let p = provider::Provider::new(&name, var_list, description);
            match provider::save(&p) {
                Ok(_) => {
                    println!(
                        "{} created provider '{}' with {} var(s)",
                        "sigil:".bold().green(),
                        p.name.bold(),
                        p.vars.len()
                    );
                    for v in &p.vars {
                        println!("  - {}", v.yellow());
                    }
                    0
                }
                Err(err) => {
                    eprintln!("{} failed to save provider: {}", "error:".bold().red(), err);
                    1
                }
            }
        }

        ProviderAction::List => {
            let providers = provider::list_providers();
            if providers.is_empty() {
                println!(
                    "{} no credential providers configured",
                    "sigil:".bold().cyan()
                );
                println!(
                    "  hint: run {} to detect available credentials",
                    "sigil provider discover".bold()
                );
                return 0;
            }

            println!(
                "{} {} provider(s):\n",
                "sigil:".bold().cyan(),
                providers.len()
            );
            for p in &providers {
                println!(
                    "  {} ({} var{})",
                    p.name.bold().green(),
                    p.vars.len(),
                    if p.vars.len() == 1 { "" } else { "s" }
                );
                if let Some(desc) = &p.description {
                    println!("    {}", desc.dimmed());
                }
            }
            0
        }

        ProviderAction::Show { name } => match provider::load(&name) {
            Ok(p) => {
                println!("{} provider '{}'", "sigil:".bold().cyan(), p.name.bold());
                if let Some(desc) = &p.description {
                    println!("  Description: {}", desc);
                }
                println!("  Created: {}", p.created_at);
                println!("  Variables:");
                for v in &p.vars {
                    let status = if std::env::var(v).is_ok() {
                        "SET".green()
                    } else {
                        "NOT SET".yellow()
                    };
                    println!("    {} [{}]", v, status);
                }
                0
            }
            Err(err) => {
                eprintln!("{} {}", "error:".bold().red(), err);
                1
            }
        },

        ProviderAction::Delete { name } => match provider::delete(&name) {
            Ok(_) => {
                println!(
                    "{} deleted provider '{}'",
                    "sigil:".bold().green(),
                    name.bold()
                );
                0
            }
            Err(err) => {
                eprintln!("{} {}", "error:".bold().red(), err);
                1
            }
        },

        ProviderAction::Discover => {
            let discovered = provider::auto_discover();
            if discovered.is_empty() {
                println!(
                    "{} no well-known agent credentials detected in environment",
                    "sigil:".bold().yellow()
                );
                return 0;
            }

            println!(
                "{} detected {} credential bundle(s):\n",
                "sigil:".bold().green(),
                discovered.len()
            );
            for (name, vars) in &discovered {
                println!("  {} {}", "+".green(), name.bold());
                for v in vars {
                    println!("    - {}", v.yellow());
                }
            }
            println!(
                "\n  To create a provider, run: {}",
                "sigil provider create --name <name> --vars <VARS>".bold()
            );
            0
        }
    }
}

async fn cmd_config(key: Option<&str>, value: Option<&str>, list: bool, _verbose: bool) -> i32 {
    let config_path = dirs::home_dir()
        .map(|h| h.join(".sigil").join("config.json"))
        .unwrap_or_else(|| PathBuf::from(".sigil/config.json"));

    if list {
        match std::fs::read_to_string(&config_path) {
            Ok(contents) => {
                println!("{}", contents);
                0
            }
            Err(_) => {
                println!("{} no configuration file found", "sigil:".bold().cyan());
                0
            }
        }
    } else if let Some(k) = key {
        if let Some(v) = value {
            // Set a config value
            let mut config: serde_json::Value = std::fs::read_to_string(&config_path)
                .ok()
                .and_then(|c| serde_json::from_str(&c).ok())
                .unwrap_or_else(|| serde_json::json!({}));

            config[k] = serde_json::Value::String(v.to_string());

            if let Some(parent) = config_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }

            match std::fs::write(&config_path, serde_json::to_string_pretty(&config).unwrap()) {
                Ok(_) => {
                    println!("{} {} = {}", "sigil:".bold().green(), k, v);
                    0
                }
                Err(err) => {
                    eprintln!("{} failed to write config: {}", "error:".bold().red(), err);
                    1
                }
            }
        } else {
            // Get a config value
            match std::fs::read_to_string(&config_path) {
                Ok(contents) => {
                    if let Ok(config) = serde_json::from_str::<serde_json::Value>(&contents) {
                        match config.get(k) {
                            Some(v) => {
                                println!("{}", v);
                                0
                            }
                            None => {
                                eprintln!("{} key '{}' not found", "sigil:".bold().yellow(), k);
                                1
                            }
                        }
                    } else {
                        eprintln!("{} corrupt config file", "error:".bold().red());
                        1
                    }
                }
                Err(_) => {
                    eprintln!("{} no configuration file found", "sigil:".bold().cyan());
                    1
                }
            }
        }
    } else {
        eprintln!("{} specify a key or use --list", "sigil:".bold().yellow());
        1
    }
}

// ---------------------------------------------------------------------------
// sbom command
// ---------------------------------------------------------------------------

async fn cmd_sbom(
    path: &Path,
    format: &str,
    threats_db: Option<&Path>,
    output: Option<&Path>,
    verbose: bool,
) -> i32 {
    if verbose {
        eprintln!(
            "{} generating SBOM for {}",
            "sigil:".bold().cyan(),
            path.display()
        );
    }

    if !path.exists() {
        eprintln!(
            "{} path does not exist: {}",
            "error:".bold().red(),
            path.display()
        );
        return 1;
    }

    let sbom = match sbom::generate_sbom(path, threats_db) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{} failed to generate SBOM: {}", "error:".bold().red(), e);
            return 1;
        }
    };

    if verbose {
        eprintln!(
            "{} found {} components, {} threats",
            "sigil:".bold().cyan(),
            sbom.total_count,
            sbom.threat_count
        );
    }

    let formatted = match format {
        "table" => sbom::format_table(&sbom),
        "cyclonedx" => sbom::format_cyclonedx(&sbom),
        "json" => serde_json::to_string_pretty(&sbom).unwrap_or_else(|_| "{}".to_string()),
        _ => {
            eprintln!(
                "{} unknown format '{}', use table, cyclonedx, or json",
                "error:".bold().red(),
                format
            );
            return 1;
        }
    };

    if let Some(out_path) = output {
        match std::fs::write(out_path, &formatted) {
            Ok(_) => {
                eprintln!(
                    "{} SBOM written to {}",
                    "sigil:".bold().green(),
                    out_path.display()
                );
            }
            Err(e) => {
                eprintln!("{} failed to write output: {}", "error:".bold().red(), e);
                return 1;
            }
        }
    } else {
        print!("{}", formatted);
    }

    if sbom.threat_count > 0 {
        1
    } else {
        0
    }
}

// ---------------------------------------------------------------------------
// Policy command
// ---------------------------------------------------------------------------

async fn cmd_policy(action: PolicyAction) -> i32 {
    match action {
        PolicyAction::Generate {
            path,
            output,
            verbose,
        } => {
            println!(
                "{} scanning {} to generate policy...",
                "sigil:".bold().cyan(),
                path.display().to_string().bold()
            );

            let (policy_result, scan) = match policy::generate::generate_for_path(&path) {
                Ok(result) => result,
                Err(e) => {
                    eprintln!("{} failed to generate policy: {}", "error:".bold().red(), e);
                    return 1;
                }
            };

            if verbose {
                eprintln!(
                    "{} scan complete: {} findings, score {}, verdict {}",
                    "sigil:".bold().cyan(),
                    scan.findings.len(),
                    scan.score,
                    scan.verdict
                );
                for finding in &scan.findings {
                    eprintln!(
                        "  [{}] {} — {} ({}:{})",
                        finding.severity,
                        finding.phase,
                        finding.rule,
                        finding.file,
                        finding.line.map(|l| l.to_string()).unwrap_or_default()
                    );
                }
                eprintln!();
            }

            let yaml = match policy_result.to_yaml() {
                Ok(y) => y,
                Err(e) => {
                    eprintln!(
                        "{} failed to serialize policy: {}",
                        "error:".bold().red(),
                        e
                    );
                    return 1;
                }
            };

            if let Some(out_path) = output {
                match std::fs::write(&out_path, &yaml) {
                    Ok(_) => {
                        println!(
                            "{} policy written to {}",
                            "sigil:".bold().green(),
                            out_path.display()
                        );
                    }
                    Err(e) => {
                        eprintln!("{} failed to write policy: {}", "error:".bold().red(), e);
                        return 1;
                    }
                }
            } else {
                print!("{}", yaml);
            }

            0
        }

        PolicyAction::Validate { file } => match policy::SigilPolicy::from_file(&file) {
            Ok(_policy) => {
                println!(
                    "{} policy {} is valid",
                    "sigil:".bold().green(),
                    file.display()
                );
                0
            }
            Err(e) => {
                eprintln!("{} policy validation failed: {}", "error:".bold().red(), e);
                1
            }
        },

        PolicyAction::Preset { name } => match policy::SigilPolicy::preset(&name) {
            Some(policy) => match policy.to_yaml() {
                Ok(yaml) => {
                    print!("{}", yaml);
                    0
                }
                Err(e) => {
                    eprintln!(
                        "{} failed to serialize preset: {}",
                        "error:".bold().red(),
                        e
                    );
                    1
                }
            },
            None => {
                eprintln!(
                    "{} unknown preset '{}'. Available: strict, standard, permissive",
                    "error:".bold().red(),
                    name
                );
                1
            }
        },
    }
}
