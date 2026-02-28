mod api;
mod cache;
mod diff;
mod output;
mod quarantine;
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
}

#[tokio::main]
async fn main() {
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
        } => {
            cmd_scan(
                &path,
                &phases,
                &severity,
                submit,
                no_cache,
                enrich,
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
