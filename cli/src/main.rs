mod api;
mod output;
mod quarantine;
mod scanner;

use clap::{Parser, Subcommand};
use colored::Colorize;
use std::path::PathBuf;
use std::process;

/// Sigil — Automated security auditing for AI agent code.
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
    },

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
        #[arg(long, default_value = "https://api.sigil.dev")]
        endpoint: String,
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
        eprintln!(
            "{} verbose mode enabled",
            "sigil:".bold().cyan()
        );
    }

    let exit_code = match cli.command {
        Commands::Clone {
            url,
            branch,
            auto_approve,
        } => cmd_clone(&url, branch.as_deref(), auto_approve, &cli.format, cli.verbose).await,

        Commands::Pip {
            package,
            version,
            auto_approve,
        } => cmd_pip(&package, version.as_deref(), auto_approve, &cli.format, cli.verbose).await,

        Commands::Npm {
            package,
            version,
            auto_approve,
        } => cmd_npm(&package, version.as_deref(), auto_approve, &cli.format, cli.verbose).await,

        Commands::Scan {
            path,
            phases,
            severity,
            submit,
        } => cmd_scan(&path, &phases, &severity, submit, &cli.format, cli.verbose).await,

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

        Commands::Config { key, value, list } => {
            cmd_config(key.as_deref(), value.as_deref(), list, cli.verbose).await
        }
    };

    process::exit(exit_code);
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
            eprintln!("{} failed to create quarantine entry: {}", "error:".bold().red(), err);
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
    let result = scanner::run_scan(&entry.path);
    output::print_scan_summary(&result, format);
    output::print_findings(&result.findings, format);
    output::print_verdict(&result.verdict, format);

    // 4. Auto-approve if requested and scan is clean
    if auto_approve && result.verdict == scanner::Verdict::Clean {
        if let Err(err) = quarantine::approve(&entry.id, Some("auto-approved: clean scan")) {
            eprintln!("{} failed to auto-approve: {}", "warning:".bold().yellow(), err);
        } else {
            println!("{} auto-approved (clean scan)", "sigil:".bold().green());
        }
    }

    match result.verdict {
        scanner::Verdict::Clean | scanner::Verdict::LowRisk => 0,
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
            eprintln!("{} failed to create quarantine entry: {}", "error:".bold().red(), err);
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

    let result = scanner::run_scan(&entry.path);
    output::print_scan_summary(&result, format);
    output::print_findings(&result.findings, format);
    output::print_verdict(&result.verdict, format);

    if auto_approve && result.verdict == scanner::Verdict::Clean {
        if let Err(err) = quarantine::approve(&entry.id, Some("auto-approved: clean scan")) {
            eprintln!("{} failed to auto-approve: {}", "warning:".bold().yellow(), err);
        } else {
            println!("{} auto-approved (clean scan)", "sigil:".bold().green());
        }
    }

    match result.verdict {
        scanner::Verdict::Clean | scanner::Verdict::LowRisk => 0,
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
            eprintln!("{} failed to create quarantine entry: {}", "error:".bold().red(), err);
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

    let result = scanner::run_scan(&entry.path);
    output::print_scan_summary(&result, format);
    output::print_findings(&result.findings, format);
    output::print_verdict(&result.verdict, format);

    if auto_approve && result.verdict == scanner::Verdict::Clean {
        if let Err(err) = quarantine::approve(&entry.id, Some("auto-approved: clean scan")) {
            eprintln!("{} failed to auto-approve: {}", "warning:".bold().yellow(), err);
        } else {
            println!("{} auto-approved (clean scan)", "sigil:".bold().green());
        }
    }

    match result.verdict {
        scanner::Verdict::Clean | scanner::Verdict::LowRisk => 0,
        _ => 2,
    }
}

async fn cmd_scan(
    path: &PathBuf,
    _phases: &str,
    _severity: &str,
    submit: bool,
    format: &str,
    verbose: bool,
) -> i32 {
    if !path.exists() {
        eprintln!("{} path does not exist: {}", "error:".bold().red(), path.display());
        return 1;
    }

    println!(
        "{} scanning {}...",
        "sigil:".bold().cyan(),
        path.display().to_string().bold()
    );

    let result = scanner::run_scan(path);

    output::print_scan_summary(&result, format);
    output::print_findings(&result.findings, format);
    output::print_verdict(&result.verdict, format);

    if submit {
        if verbose {
            eprintln!("submitting results to Sigil cloud...");
        }
        let client = api::SigilClient::new(None);
        match client.submit_scan(&result).await {
            Ok(_) => println!("{} results submitted to Sigil cloud", "sigil:".bold().green()),
            Err(err) => eprintln!(
                "{} failed to submit results: {} (continuing offline)",
                "warning:".bold().yellow(),
                err
            ),
        }
    }

    match result.verdict {
        scanner::Verdict::Clean | scanner::Verdict::LowRisk => 0,
        _ => 2,
    }
}

async fn cmd_fetch(force: bool, verbose: bool) -> i32 {
    println!("{} fetching latest threat signatures...", "sigil:".bold().cyan());

    let client = api::SigilClient::new(None);
    match client.get_signatures(force).await {
        Ok(count) => {
            println!(
                "{} fetched {} signatures",
                "sigil:".bold().green(),
                count
            );
            0
        }
        Err(err) => {
            eprintln!("{} failed to fetch signatures: {}", "error:".bold().red(), err);
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
            eprintln!("{} cannot determine current binary path: {}", "error:".bold().red(), err);
            return 1;
        }
    };

    if verbose {
        eprintln!("copying {} -> {}", current_exe.display(), target.display());
    }

    match std::fs::copy(&current_exe, &target) {
        Ok(_) => {
            println!("{} installed successfully to {}", "sigil:".bold().green(), target.display());
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
            eprintln!(
                "{} interactive login not yet implemented; use --token",
                "warning:".bold().yellow()
            );
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
            let mut config: serde_json::Value =
                std::fs::read_to_string(&config_path)
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
