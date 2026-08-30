mod api;
mod cache;
mod corpus;
mod diff;
mod explain;
mod feeds;
mod hook;
mod knowngood;
mod ledger;
mod output;
mod policy;
mod provenance;
mod provider;
mod quarantine;
mod sandbox;
mod sbom;
mod scanner;
mod setup;

use clap::{Parser, Subcommand};
use colored::Colorize;
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

        /// Exit 1 when a finding at or above this severity is present
        /// (low, medium, high, critical). Default: high.
        #[arg(long, default_value = "high")]
        fail_on: String,

        /// Disable trust-ledger allowlisting (report findings even when the
        /// content digest-matches an approved ledger pin)
        #[arg(long)]
        ignore_ledger: bool,
    },

    /// Show the active detection corpus: which packs are loaded, from where
    Corpus,

    /// Known-good corpus (ADR-0011): recognise published code instead of
    /// re-judging it
    KnownGood {
        #[command(subcommand)]
        action: KnownGoodAction,
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

    /// Explain a scan finding with AI adjudication (Pro feature, server-side)
    Explain {
        /// Path to a scan JSON file (from `sigil scan -f json`)
        scan_json: PathBuf,

        /// Index of the finding to explain
        #[arg(long, default_value_t = 0)]
        finding: usize,

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

    /// Inspect the content-pinning trust ledger (rug-pull detection baseline)
    Ledger {
        #[command(subcommand)]
        action: LedgerAction,
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

    /// Respond to a Claude Code hook event (reads the hook JSON from stdin)
    Hook {
        /// Hook event to handle (currently: pretooluse)
        event: String,
    },

    /// Wire Sigil into AI agent and developer workflows
    Setup {
        /// What to set up: claude, shell, git, or all
        target: String,
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
enum LedgerAction {
    /// Show the pinned content hashes for an approved quarantine id
    Show {
        /// Quarantine id whose approval pin to display
        id: String,
    },
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
            fail_on,
            ignore_ledger,
        } => {
            cmd_scan(
                &path,
                &phases,
                &severity,
                submit,
                no_cache,
                enrich,
                enhanced,
                &fail_on,
                ignore_ledger,
                &cli.format,
                cli.verbose,
            )
            .await
        }

        Commands::Corpus => cmd_corpus(&cli.format),
        Commands::KnownGood { action } => cmd_known_good(action, &cli.format),
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

        Commands::Explain {
            scan_json,
            finding,
            endpoint,
        } => explain::cmd_explain(&scan_json, finding, &endpoint, cli.verbose).await,

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

        Commands::Ledger { action } => cmd_ledger(action).await,

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

        Commands::Hook { event } => hook::cmd_hook(&event),

        Commands::Setup { target } => setup::cmd_setup(&target),
    };

    process::exit(exit_code);
}

// ---------------------------------------------------------------------------
// Archive extraction helper
// ---------------------------------------------------------------------------

/// Maximum total bytes written while unpacking one quarantined artifact.
///
/// Path escape is already handled by the archive crates — `zip`'s `extract`
/// resolves every entry through `enclosed_name()` and errors on escape, and
/// `tar`'s `unpack_in` validates entries against the destination. What
/// neither bounds is *volume*: a small archive that expands to tens of
/// gigabytes fills the disk during what the user believes is a read-only
/// scan. 2 GiB is far above any real package and far below a bomb.
const MAX_EXTRACTED_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Maximum number of entries unpacked from one artifact. Guards inode
/// exhaustion from an archive of very many tiny files.
const MAX_EXTRACTED_ENTRIES: usize = 200_000;

/// What unpacking an artifact produced, including any cap that was hit.
#[derive(Debug, Default, Clone)]
pub struct ExtractionReport {
    pub bytes: u64,
    pub entries: usize,
    /// Set when a cap stopped extraction. Carries a human-readable reason.
    pub capped: Option<String>,
}

impl ExtractionReport {
    /// A cap hit is itself a signal, not merely an error: an archive that
    /// expands past any plausible package size is the shape of a
    /// decompression bomb, so it is reported as a finding rather than
    /// silently aborting the unpack.
    fn finding(&self, artifact: &str) -> Option<scanner::Finding> {
        let reason = self.capped.as_ref()?;
        Some(scanner::Finding {
            phase: scanner::Phase::Provenance,
            rule: "ARCHIVE-BOMB-001".to_string(),
            severity: scanner::Severity::High,
            file: artifact.to_string(),
            line: None,
            snippet: format!("Archive expansion cap exceeded: {reason}"),
            weight: 5,
            kev: false,
            epss: 0.0,
            fingerprint: String::new(),
            locator: None,
        })
    }
}

/// Extract .whl/.zip and .tar.gz/.tgz archives in a directory so the scanner
/// can inspect the actual source files inside packages.
///
/// Extraction is bounded by [`MAX_EXTRACTED_BYTES`] and
/// [`MAX_EXTRACTED_ENTRIES`] across all archives in the directory. Hitting
/// either stops extraction and is reported in the returned
/// [`ExtractionReport`]; whatever was already written is still scanned.
fn extract_archives(dir: &Path) -> Result<ExtractionReport, Box<dyn std::error::Error>> {
    let entries: Vec<_> = std::fs::read_dir(dir)?.filter_map(|e| e.ok()).collect();
    let mut report = ExtractionReport::default();

    for entry in entries {
        if report.capped.is_some() {
            break;
        }
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
            extract_zip_bounded(&mut archive, &extract_dir, &mut report)?;
            std::fs::remove_file(&path)?;
        } else if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
            // Extract gzipped tar archives
            let file = std::fs::File::open(&path)?;
            let gz = flate2::read::GzDecoder::new(file);
            let mut archive = tar::Archive::new(gz);
            let extract_dir = dir.join(name.trim_end_matches(".tar.gz").trim_end_matches(".tgz"));
            std::fs::create_dir_all(&extract_dir)?;
            extract_tar_bounded(&mut archive, &extract_dir, &mut report)?;
            std::fs::remove_file(&path)?;
        }
    }

    Ok(report)
}

#[derive(Subcommand, Debug)]
enum KnownGoodAction {
    /// Show the installed known-good corpus
    Status,
    /// Build an index by hashing a directory of published files
    Build {
        /// Directory to hash (the unpacked release)
        path: String,
        /// Ecosystem, e.g. npm or pypi
        #[arg(long, default_value = "npm")]
        ecosystem: String,
        /// Package name
        #[arg(long)]
        name: String,
        /// Package version
        #[arg(long)]
        version: String,
        /// Write the index here (default: stdout)
        #[arg(long)]
        out: Option<String>,
    },
}

/// Known-good corpus commands.
fn cmd_known_good(action: KnownGoodAction, format: &str) -> i32 {
    match action {
        KnownGoodAction::Status => {
            let kg = match knowngood::load_installed() {
                Ok(kg) => kg,
                Err(e) => {
                    eprintln!("{} {}", "error:".bold().red(), e);
                    return EXIT_ERROR;
                }
            };
            let dir = knowngood::known_good_dir()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "~/.sigil/known-good/".to_string());

            if format == "json" {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "directory": dir,
                        "releases": kg.release_count(),
                        "files": kg.file_count(),
                    }))
                    .unwrap_or_default()
                );
                return EXIT_CLEAN;
            }

            println!();
            println!("  {} known-good corpus", "sigil".bold().cyan());
            println!("  directory: {dir}");
            println!(
                "  {} release(s), {} file(s) indexed",
                kg.release_count(),
                kg.file_count()
            );
            if kg.is_empty() {
                println!();
                println!("  No index installed. Files are scanned and reported normally —");
                println!("  an absent corpus never creates false confidence (ADR-0011).");
                println!(
                    "  Build one with: sigil known-good build <dir> --name <pkg> --version <v>"
                );
            }
            println!();
            EXIT_CLEAN
        }

        KnownGoodAction::Build {
            path,
            ecosystem,
            name,
            version,
            out,
        } => {
            let index = match knowngood::build_index(Path::new(&path), &ecosystem, &name, &version)
            {
                Ok(i) => i,
                Err(e) => {
                    eprintln!("{} {}", "error:".bold().red(), e);
                    return EXIT_ERROR;
                }
            };
            let json = serde_json::to_string_pretty(&index).unwrap_or_default();
            match out {
                Some(dest) => {
                    if let Err(e) = std::fs::write(&dest, &json) {
                        eprintln!("{} failed to write {dest}: {e}", "error:".bold().red());
                        return EXIT_ERROR;
                    }
                    let files = index.releases.first().map(|r| r.files.len()).unwrap_or(0);
                    eprintln!(
                        "{} indexed {} file(s) for {}:{}@{} -> {}",
                        "sigil:".bold().green(),
                        files,
                        ecosystem,
                        name,
                        version,
                        dest
                    );
                }
                None => println!("{json}"),
            }
            EXIT_CLEAN
        }
    }
}

/// Show the active detection corpus.
///
/// Makes the data plane inspectable: which packs are live, what version, and
/// whether each came from the binary, the released corpus, or a user pack.
/// Without this there is no way to answer "which rules did that scan actually
/// run" short of reading a scan report.
fn cmd_corpus(format: &str) -> i32 {
    let packs = match corpus::loader::load_all_packs_with_origin() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{} {}", "error:".bold().red(), e);
            return EXIT_ERROR;
        }
    };
    let compiled = corpus::compiled::corpus();

    if format == "json" {
        let doc = serde_json::json!({
            "corpus_digest": compiled.digest(),
            "rule_count": compiled.rule_count(),
            "packs": packs.iter().map(|(p, origin)| serde_json::json!({
                "id": p.meta.id,
                "name": p.meta.name,
                "version": p.meta.version,
                "updated_at": p.meta.updated_at,
                "origin": origin.to_string(),
                "rules": p.rules.len(),
                "provenance_rules": p.provenance_rules.len(),
            })).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&doc).unwrap_or_default());
        return EXIT_CLEAN;
    }

    println!();
    println!("  {} detection corpus", "sigil".bold().cyan());
    println!("  digest: {}", compiled.digest());
    println!(
        "  {} content rules across {} packs",
        compiled.rule_count(),
        packs.len()
    );
    println!();
    println!(
        "  {:<34} {:<9} {:<10} {:>6}",
        "PACK".bold(),
        "VERSION".bold(),
        "ORIGIN".bold(),
        "RULES".bold()
    );
    for (pack, origin) in &packs {
        let origin_label = match origin {
            corpus::loader::PackOrigin::Embedded => origin.to_string().dimmed().to_string(),
            corpus::loader::PackOrigin::Released => origin.to_string().green().to_string(),
            corpus::loader::PackOrigin::User => origin.to_string().yellow().to_string(),
        };
        println!(
            "  {:<34} {:<9} {:<19} {:>6}",
            pack.meta.id,
            pack.meta.version,
            origin_label,
            pack.rules.len() + pack.provenance_rules.len()
        );
    }
    println!();
    println!(
        "  Released packs load from {}",
        corpus::loader::released_corpus_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "~/.sigil/corpus/".to_string())
    );
    println!(
        "  User packs load from     {}",
        corpus::loader::user_packs_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "~/.sigil/packs/".to_string())
    );
    println!("  A pack supersedes an embedded pack with the same id.");
    println!();

    EXIT_CLEAN
}

/// Stamp findings with a composable locator naming the artifact they came
/// from.
///
/// Modelled on Ghidra's FSRL: segments compose with `|`, so a finding inside
/// an unpacked package reads
/// `npm://left-pad-1.3.0|file://package/dist/index.js` rather than a path
/// into a temporary extraction directory that says nothing about which
/// artifact produced it.
fn apply_container_locator(result: &mut scanner::ScanResult, ecosystem: &str, artifact: &str) {
    for f in result
        .findings
        .iter_mut()
        .chain(result.suppressed_findings.iter_mut())
    {
        f.locator = Some(format!("{ecosystem}://{artifact}|file://{}", f.file));
    }
}

/// Fold an extraction cap hit into the scan result.
///
/// The finding is added before scoring so the verdict reflects it — an
/// artifact that tried to expand past the cap should not come back
/// `LOW RISK` just because the scanner refused to unpack the rest of it.
fn apply_extraction_report(
    result: &mut scanner::ScanResult,
    report: &ExtractionReport,
    artifact: &str,
) {
    let Some(finding) = report.finding(artifact) else {
        return;
    };
    eprintln!(
        "{} {}",
        "warning:".bold().yellow(),
        finding.snippet.as_str()
    );
    result.findings.push(finding);
    result.score = scanner::scoring::calculate_score(&result.findings);
    result.verdict = scanner::scoring::determine_verdict(&result.findings, result.score);
}

/// Record one entry against the caps. Returns `false` once a cap is hit.
fn admit_entry(report: &mut ExtractionReport, declared: u64) -> bool {
    if report.capped.is_some() {
        return false;
    }
    if report.entries + 1 > MAX_EXTRACTED_ENTRIES {
        report.capped = Some(format!("more than {MAX_EXTRACTED_ENTRIES} entries"));
        return false;
    }
    if report.bytes.saturating_add(declared) > MAX_EXTRACTED_BYTES {
        report.capped = Some(format!(
            "expanded past {} MiB",
            MAX_EXTRACTED_BYTES / (1024 * 1024)
        ));
        return false;
    }
    report.entries += 1;
    report.bytes = report.bytes.saturating_add(declared);
    true
}

/// Unpack a zip under the extraction caps.
///
/// Entry paths go through `enclosed_name()`, the same sanitisation
/// `ZipArchive::extract` applies, so an entry that escapes the destination is
/// skipped rather than written.
fn extract_zip_bounded(
    archive: &mut zip::ZipArchive<std::fs::File>,
    dest: &Path,
    report: &mut ExtractionReport,
) -> Result<(), Box<dyn std::error::Error>> {
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let Some(rel) = file.enclosed_name() else {
            continue; // path escapes the destination — skip it
        };
        if !admit_entry(report, file.size()) {
            break;
        }
        let out = dest.join(rel);
        if file.name().ends_with('/') {
            std::fs::create_dir_all(&out)?;
            continue;
        }
        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut sink = std::fs::File::create(&out)?;
        // Bound the copy itself: the declared size in the header is
        // attacker-controlled, so a lying header must not be able to write
        // past the cap.
        let budget = MAX_EXTRACTED_BYTES.saturating_sub(report.bytes) + file.size();
        let mut bounded = std::io::Read::take(&mut file, budget);
        let written = std::io::copy(&mut bounded, &mut sink)?;
        if written > file.size() {
            report.bytes = report.bytes.saturating_add(written - file.size());
        }
    }
    Ok(())
}

/// Unpack a gzipped tar under the extraction caps.
///
/// `tar`'s own `unpack_in` validation is retained per entry, so path escape
/// and symlink handling behave exactly as before.
fn extract_tar_bounded<R: std::io::Read>(
    archive: &mut tar::Archive<R>,
    dest: &Path,
    report: &mut ExtractionReport,
) -> Result<(), Box<dyn std::error::Error>> {
    for entry in archive.entries()? {
        let mut entry = entry?;
        let declared = entry.header().size().unwrap_or(0);
        if !admit_entry(report, declared) {
            break;
        }
        // unpack_in performs the destination-containment check and returns
        // false when it refuses the entry.
        entry.unpack_in(dest)?;
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
    print_progress(
        format,
        format!(
            "{} cloning {} into quarantine...",
            "sigil:".bold().cyan(),
            url.bold()
        ),
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
            return EXIT_ERROR;
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
            return EXIT_ERROR;
        }
    }

    // 3. Scan the cloned repo
    let mut result = scanner::run_scan(&entry.path, None, None);
    apply_container_locator(&mut result, "git", url);
    print_scan_output(&result, &entry.path, format);

    // 4. Auto-approve if requested and scan is low risk
    if auto_approve && result.verdict == scanner::Verdict::LowRisk {
        if let Err(err) = approve_with_ledger(&entry.id, Some("auto-approved: low risk scan")) {
            eprintln!(
                "{} failed to auto-approve: {}",
                "warning:".bold().yellow(),
                err
            );
        } else {
            print_progress(
                format,
                format!("{} auto-approved (low risk)", "sigil:".bold().green()),
            );
        }
    }

    acquisition_exit_code(result.verdict)
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

    print_progress(
        format,
        format!(
            "{} downloading pip package {} into quarantine...",
            "sigil:".bold().cyan(),
            pkg_spec.bold()
        ),
    );

    let entry = match quarantine::add(&pkg_spec, "pip") {
        Ok(e) => e,
        Err(err) => {
            eprintln!(
                "{} failed to create quarantine entry: {}",
                "error:".bold().red(),
                err
            );
            return EXIT_ERROR;
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
            return EXIT_ERROR;
        }
    }

    // Extract .whl (zip) and .tar.gz files so the scanner sees actual source
    let extraction = match extract_archives(&entry.path) {
        Ok(report) => report,
        Err(err) => {
            eprintln!(
                "{} failed to extract archives: {} (scanning raw archives instead)",
                "warning:".bold().yellow(),
                err
            );
            ExtractionReport::default()
        }
    };

    let mut result = scanner::run_scan(&entry.path, None, None);
    apply_extraction_report(&mut result, &extraction, &pkg_spec);
    apply_container_locator(&mut result, "pip", &pkg_spec);
    print_scan_output(&result, &entry.path, format);

    if auto_approve && result.verdict == scanner::Verdict::LowRisk {
        if let Err(err) = approve_with_ledger(&entry.id, Some("auto-approved: low risk scan")) {
            eprintln!(
                "{} failed to auto-approve: {}",
                "warning:".bold().yellow(),
                err
            );
        } else {
            print_progress(
                format,
                format!("{} auto-approved (low risk)", "sigil:".bold().green()),
            );
        }
    }

    acquisition_exit_code(result.verdict)
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

    print_progress(
        format,
        format!(
            "{} downloading npm package {} into quarantine...",
            "sigil:".bold().cyan(),
            pkg_spec.bold()
        ),
    );

    let entry = match quarantine::add(&pkg_spec, "npm") {
        Ok(e) => e,
        Err(err) => {
            eprintln!(
                "{} failed to create quarantine entry: {}",
                "error:".bold().red(),
                err
            );
            return EXIT_ERROR;
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
            return EXIT_ERROR;
        }
    }

    // Extract .tgz files so the scanner sees actual source
    let extraction = match extract_archives(&entry.path) {
        Ok(report) => report,
        Err(err) => {
            eprintln!(
                "{} failed to extract archives: {} (scanning raw archives instead)",
                "warning:".bold().yellow(),
                err
            );
            ExtractionReport::default()
        }
    };

    let mut result = scanner::run_scan(&entry.path, None, None);
    apply_extraction_report(&mut result, &extraction, &pkg_spec);
    apply_container_locator(&mut result, "npm", &pkg_spec);
    print_scan_output(&result, &entry.path, format);

    if auto_approve && result.verdict == scanner::Verdict::LowRisk {
        if let Err(err) = approve_with_ledger(&entry.id, Some("auto-approved: low risk scan")) {
            eprintln!(
                "{} failed to auto-approve: {}",
                "warning:".bold().yellow(),
                err
            );
        } else {
            print_progress(
                format,
                format!("{} auto-approved (low risk)", "sigil:".bold().green()),
            );
        }
    }

    acquisition_exit_code(result.verdict)
}

/// Exit codes, per ADR-0010. These are the CI interface and a compatibility
/// promise: `2` means *the scan did not produce a usable verdict*, never
/// "the verdict was bad".
pub const EXIT_CLEAN: i32 = 0;
pub const EXIT_FINDINGS: i32 = 1;
pub const EXIT_ERROR: i32 = 2;

#[allow(clippy::too_many_arguments)]
/// Exit-code contract (ADR-0010): 1 if any finding is at or above the fail
/// threshold, else 0. Scan errors (handled by the caller) are 2.
fn exit_code_for(findings: &[scanner::Finding], fail_threshold: scanner::Severity) -> i32 {
    if findings.iter().any(|f| f.severity >= fail_threshold) {
        EXIT_FINDINGS
    } else {
        EXIT_CLEAN
    }
}

/// Exit-code contract for the acquisition commands (`clone`, `pip`, `npm`).
///
/// These previously returned `2` for a High-or-Critical verdict, colliding
/// with the code ADR-0010 reserves for "the scan itself failed". A CI job
/// that treats `2` as an infrastructure failure and retries would have
/// silently passed a malicious package. Anything the caller should act on is
/// now `1`; `2` is reserved for the command failing.
fn acquisition_exit_code(verdict: scanner::Verdict) -> i32 {
    match verdict {
        scanner::Verdict::LowRisk => EXIT_CLEAN,
        _ => EXIT_FINDINGS,
    }
}

/// Print a progress/log line: stdout in text mode, stderr for machine-readable
/// formats (json, sarif) so stdout stays a single parseable document.
fn print_progress(format: &str, msg: String) {
    if format == "text" {
        println!("{}", msg);
    } else {
        eprintln!("{}", msg);
    }
}

/// Shared scan output: summary, findings, verdict, plus the ledger-suppression
/// attribution when active. In JSON mode everything is emitted as exactly one
/// JSON document on stdout (see `output::print_scan_result_json`).
fn print_scan_output(result: &scanner::ScanResult, path: &Path, format: &str) {
    if format == "sarif" {
        output::print_scan_sarif(result, &path.to_string_lossy());
        return;
    }
    if format == "json" {
        output::print_scan_result_json(result);
        return;
    }
    output::print_scan_summary(result);
    output::print_findings(&result.findings);
    if let Some(by) = &result.suppressed_by {
        println!(
            "  {} {} finding{} suppressed by ledger approval ({})",
            "[*]".green(),
            result.suppressed_findings.len(),
            if result.suppressed_findings.len() == 1 {
                ""
            } else {
                "s"
            },
            by
        );
    }
    output::print_verdict(&result.verdict);
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
    fail_on: &str,
    ignore_ledger: bool,
    format: &str,
    verbose: bool,
) -> i32 {
    // Exit-code contract (ADR-0010): 2 = scan error.
    if !path.exists() {
        eprintln!(
            "{} path does not exist: {}",
            "error:".bold().red(),
            path.display()
        );
        return 2;
    }

    // Threshold at/above which a finding makes the scan fail (exit 1).
    let fail_threshold = match fail_on.to_lowercase().as_str() {
        "low" => scanner::Severity::Low,
        "medium" => scanner::Severity::Medium,
        "high" => scanner::Severity::High,
        "critical" => scanner::Severity::Critical,
        other => {
            eprintln!(
                "{} invalid --fail-on '{}' (use low, medium, high, critical)",
                "error:".bold().red(),
                other
            );
            return 2;
        }
    };
    let exit_for =
        |findings: &[scanner::Finding]| -> i32 { exit_code_for(findings, fail_threshold) };

    print_progress(
        format,
        format!(
            "{} scanning {}...",
            "sigil:".bold().cyan(),
            path.display().to_string().bold()
        ),
    );

    // --- Cache: only use when running a full unfiltered scan ---
    let use_cache = !no_cache && phases == "all" && severity == "low";

    // Try loading from cache
    if use_cache {
        if let Some(mut cached) = cache::load_cached(path) {
            print_progress(
                format,
                format!("{} using cached result", "sigil:".bold().green()),
            );
            // Re-evaluate ledger suppression against the CURRENT ledger: a pin
            // approved or revoked since the cache was written must take effect.
            ledger::apply_suppression(&mut cached, path, ignore_ledger);
            print_scan_output(&cached, path, format);
            return exit_for(&cached.findings);
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

    let mut result = scanner::run_scan(path, phase_filter.as_deref(), min_severity);

    // OSV advisory feed (US-E1): append CVE/MAL- findings from lockfiles.
    // Runs whenever a full-phase scan is requested (phases == "all").
    // Network failures are handled inside scan_for_osv_findings — never fatal.
    if phases == "all" {
        // The three feeds make network round-trips (OSV detail fetches, npm/PyPI
        // registry lookups). --verbose reports each feed's wall-clock so a slow
        // scan can be attributed to a specific feed rather than guessed at.
        // The feeds use reqwest::blocking, which spins up its own tokio
        // runtime; calling that directly inside this async fn panics with
        // "Cannot drop a runtime in a context where blocking is not allowed"
        // as soon as a lockfile triggers an HTTP call. block_in_place moves
        // the call off the async worker so the nested runtime is legal.
        let t = std::time::Instant::now();
        let osv_findings = tokio::task::block_in_place(|| feeds::osv::scan_for_osv_findings(path));
        if verbose {
            eprintln!(
                "feed osv: {:?} ({} findings)",
                t.elapsed(),
                osv_findings.len()
            );
        }
        if !osv_findings.is_empty() {
            result.findings.extend(osv_findings);
        }

        // KEV/EPSS overlay (US-E2): enrich CVE findings with exploitation metadata.
        // Best-effort — network/parse failures leave findings unchanged.
        let t = std::time::Instant::now();
        tokio::task::block_in_place(|| {
            feeds::enrichment::enrich_findings_with_kev_epss(&mut result.findings, None, None)
        });
        if verbose {
            eprintln!("feed kev_epss: {:?}", t.elapsed());
        }

        // Provenance drift detection (US-E3): detect downgrade, identity-change,
        // and repo-mismatch for npm and PyPI packages against the ledger baseline.
        // ADR-0007: absence of provenance is never a finding. Network failures are
        // handled gracefully — never fatal.
        let t = std::time::Instant::now();
        let prov_findings = tokio::task::block_in_place(|| {
            provenance::scan_for_provenance_drift(path, &provenance::ScanOptions::default())
        });
        if verbose {
            eprintln!(
                "feed provenance: {:?} ({} findings)",
                t.elapsed(),
                prov_findings.len()
            );
        }
        if !prov_findings.is_empty() {
            result.findings.extend(prov_findings);
        }

        // Rug-pull check (US-E3→F2): if this path is a previously-approved
        // quarantine artifact, diff its current content against the pinned
        // baseline. Drift => Critical RUGPULL-001 and the entry is re-quarantined.
        let rugpull = check_rugpull_for_path(path, verbose);
        if !rugpull.is_empty() {
            result.findings.extend(rugpull);
        }

        // Recompute score and verdict with the enriched finding set.
        if !result.findings.is_empty() {
            result.score = scanner::scoring::calculate_score(&result.findings);
            result.verdict = scanner::scoring::determine_verdict(&result.findings, result.score);
        }
    }

    // Trust-ledger allowlisting (F-010 US-H2): content that digest-matches an
    // approved pin has its findings suppressed — moved out of score, verdict,
    // and exit code, but kept visible in the output. Runs after every phase
    // and feed so a RUGPULL-001 drift signal can veto suppression.
    let suppressed = ledger::apply_suppression(&mut result, path, ignore_ledger);
    if verbose && suppressed {
        eprintln!(
            "ledger: {} finding(s) suppressed ({})",
            result.suppressed_findings.len(),
            result.suppressed_by.as_deref().unwrap_or("")
        );
    }

    print_scan_output(&result, path, format);

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

    exit_for(&result.findings)
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

    let baseline_result: scanner::ScanResult = match diff::parse_baseline(&baseline_data) {
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

    let (entry, rec) = match approve_with_ledger(id, reason) {
        Ok(result) => result,
        Err(err) => {
            eprintln!("{} {}", "error:".bold().red(), err);
            return 1;
        }
    };

    println!(
        "{} approved {} ({})",
        "sigil:".bold().green(),
        entry.id,
        entry.source
    );
    println!("  code lives at {}", entry.path.display());
    println!(
        "  pinned {} files (digest {})",
        rec.pin.file_count,
        &rec.pin.artifact_digest[..rec.pin.artifact_digest.len().min(12)]
    );
    if !rec.pin.tool_definitions.is_empty() || !rec.pin.instruction_files.is_empty() {
        println!(
            "  watching {} tool-definition + {} instruction file(s) for drift",
            rec.pin.tool_definitions.len(),
            rec.pin.instruction_files.len()
        );
    }
    0
}

fn approve_with_ledger(
    id: &str,
    reason: Option<&str>,
) -> Result<(quarantine::QuarantineEntry, ledger::LedgerRecord), String> {
    let pending_entry = quarantine::get(id)?;
    let rec = ledger::record_approval(&pending_entry, reason)
        .map_err(|err| format!("approval blocked because ledger pin failed: {}", err))?;

    match quarantine::approve(id, reason) {
        Ok(entry) => Ok((entry, rec)),
        Err(err) => {
            if let Err(remove_err) = ledger::remove(id) {
                return Err(format!(
                    "approval failed after ledger pin and rollback failed: {}; rollback: {}",
                    err, remove_err
                ));
            }
            Err(err)
        }
    }
}

/// If `path` is a previously-approved quarantine artifact, diff its current
/// content against the pinned baseline and re-quarantine on drift. Returns the
/// rug-pull findings (empty for non-quarantine paths or unchanged content).
fn check_rugpull_for_path(path: &Path, verbose: bool) -> Vec<scanner::Finding> {
    let target = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let entries = match quarantine::list(None) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    for entry in entries {
        if entry.status != quarantine::QuarantineStatus::Approved {
            continue;
        }
        let entry_path = std::fs::canonicalize(&entry.path).unwrap_or_else(|_| entry.path.clone());
        if entry_path != target {
            continue;
        }
        let record = match ledger::get(&entry.id) {
            Some(r) => r,
            None => return Vec::new(),
        };
        let findings = ledger::detect_rugpull(path, &record);
        if !findings.is_empty() {
            if let Err(e) = quarantine::requarantine(&entry.id, Some("content drift (RUGPULL-001)"))
            {
                if verbose {
                    eprintln!("rug-pull: re-quarantine of {} failed: {}", entry.id, e);
                }
            } else if verbose {
                eprintln!("rug-pull: {} drifted — re-quarantined", entry.id);
            }
        }
        return findings;
    }
    Vec::new()
}

async fn cmd_ledger(action: LedgerAction) -> i32 {
    match action {
        LedgerAction::Show { id } => match ledger::get(&id) {
            Some(rec) => {
                println!("{} ledger pin for {}", "sigil:".bold().green(), rec.id);
                println!("  source:      {} ({})", rec.source, rec.source_type);
                if let Some(v) = &rec.pin.version {
                    println!("  version:     {}", v);
                }
                println!("  approved_at: {}", rec.approved_at.to_rfc3339());
                if let Some(r) = &rec.reason {
                    println!("  reason:      {}", r);
                }
                println!("  artifact:    sha256:{}", rec.pin.artifact_digest);
                println!("  files:       {}", rec.pin.file_count);
                if !rec.pin.tool_definitions.is_empty() {
                    println!("  tool definitions:");
                    for f in &rec.pin.tool_definitions {
                        if let Some(h) = rec.pin.files.get(f) {
                            println!("    {} sha256:{}", f, h);
                        }
                    }
                }
                if !rec.pin.instruction_files.is_empty() {
                    println!("  instruction files:");
                    for f in &rec.pin.instruction_files {
                        if let Some(h) = rec.pin.files.get(f) {
                            println!("    {} sha256:{}", f, h);
                        }
                    }
                }
                0
            }
            None => {
                eprintln!(
                    "{} no ledger pin for '{}' (approve it first)",
                    "error:".bold().red(),
                    id
                );
                1
            }
        },
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
            // Revoke any ledger pin (F-010): a rejected artifact must stop
            // suppressing findings via the allowlist immediately.
            match ledger::remove(&entry.id) {
                Ok(true) => println!("  ledger pin revoked"),
                Ok(false) => {}
                Err(e) => eprintln!(
                    "{} rejected but ledger revocation failed: {}",
                    "warning:".bold().yellow(),
                    e
                ),
            }
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
            // Browser-based device authorization flow (replaces password login).
            match client.login_device_flow().await {
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

#[cfg(test)]
mod exit_code_tests {
    use super::{approve_with_ledger, exit_code_for};
    use std::fs;
    use std::sync::Mutex;
    use tempfile::tempdir;

    use super::scanner::{Finding, Phase, Severity};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_isolated_home<T>(test: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let dir = tempdir().expect("tempdir");
        std::env::set_var("HOME", dir.path());
        std::env::set_var("SIGIL_QUARANTINE_DIR", dir.path().join("quarantine"));
        let result = test();
        std::env::remove_var("SIGIL_QUARANTINE_DIR");
        std::env::remove_var("HOME");
        result
    }

    fn finding(sev: Severity) -> Finding {
        Finding {
            phase: Phase::CodePatterns,
            rule: "TEST".into(),
            severity: sev,
            file: "x".into(),
            line: None,
            snippet: String::new(),
            weight: 1,
            kev: false,
            epss: 0.0,
            fingerprint: String::new(),
            locator: None,
        }
    }

    #[test]
    fn empty_findings_exit_zero() {
        assert_eq!(exit_code_for(&[], Severity::High), 0);
    }

    #[test]
    fn below_threshold_exit_zero() {
        let f = vec![finding(Severity::Medium), finding(Severity::Low)];
        assert_eq!(exit_code_for(&f, Severity::High), 0);
    }

    #[test]
    fn at_threshold_exit_one() {
        let f = vec![finding(Severity::Low), finding(Severity::High)];
        assert_eq!(exit_code_for(&f, Severity::High), 1);
    }

    #[test]
    fn above_threshold_exit_one() {
        let f = vec![finding(Severity::Critical)];
        assert_eq!(exit_code_for(&f, Severity::High), 1);
    }

    #[test]
    fn critical_threshold_ignores_high() {
        let f = vec![finding(Severity::High)];
        assert_eq!(exit_code_for(&f, Severity::Critical), 0);
    }

    /// The acquisition commands (`clone`/`pip`/`npm`) must never return 2 for
    /// a risky verdict. ADR-0010 reserves 2 for "the scan did not produce a
    /// usable verdict"; a CI job that treats 2 as an infrastructure failure
    /// and retries would otherwise silently pass a malicious package.
    #[test]
    fn acquisition_never_returns_error_code_for_a_bad_verdict() {
        use super::acquisition_exit_code;
        use crate::scanner::Verdict;
        for verdict in [
            Verdict::LowRisk,
            Verdict::MediumRisk,
            Verdict::HighRisk,
            Verdict::CriticalRisk,
        ] {
            assert_ne!(
                acquisition_exit_code(verdict),
                super::EXIT_ERROR,
                "{verdict:?} must not collide with the scan-error exit code"
            );
        }
    }

    #[test]
    fn extraction_caps_admit_normal_packages() {
        let mut r = super::ExtractionReport::default();
        // A realistic package: a few hundred files, a few MiB.
        for _ in 0..500 {
            assert!(admit(&mut r, 8 * 1024));
        }
        assert!(r.capped.is_none());
        assert_eq!(r.entries, 500);
    }

    #[test]
    fn extraction_caps_stop_a_size_bomb() {
        let mut r = super::ExtractionReport::default();
        // Each entry claims 512 MiB; the 2 GiB cap must stop it.
        let half_gig = 512 * 1024 * 1024;
        let mut admitted = 0;
        for _ in 0..100 {
            if admit(&mut r, half_gig) {
                admitted += 1;
            } else {
                break;
            }
        }
        assert!(r.capped.is_some(), "size cap did not fire");
        assert!(
            admitted <= 4,
            "admitted {admitted} x 512 MiB past a 2 GiB cap"
        );
        assert!(r.capped.as_ref().unwrap().contains("MiB"));
    }

    #[test]
    fn extraction_caps_stop_an_entry_bomb() {
        let mut r = super::ExtractionReport::default();
        // Zero-byte entries never trip the size cap, so only the entry cap
        // can stop inode exhaustion.
        for _ in 0..(super::MAX_EXTRACTED_ENTRIES + 10) {
            if !admit(&mut r, 0) {
                break;
            }
        }
        assert!(r.capped.is_some(), "entry cap did not fire");
        assert!(r.capped.as_ref().unwrap().contains("entries"));
        assert_eq!(r.entries, super::MAX_EXTRACTED_ENTRIES);
    }

    #[test]
    fn a_cap_hit_becomes_a_finding_and_moves_the_verdict() {
        let mut result = crate::scanner::ScanResult {
            findings: vec![],
            score: 0,
            verdict: crate::scanner::Verdict::LowRisk,
            files_scanned: 1,
            duration_ms: 0,
            suppressed_findings: vec![],
            suppressed_by: None,
            scanner: None,
        };
        let report = super::ExtractionReport {
            bytes: u64::MAX,
            entries: 1,
            capped: Some("expanded past 2048 MiB".to_string()),
        };
        super::apply_extraction_report(&mut result, &report, "evil@1.0.0");

        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].rule, "ARCHIVE-BOMB-001");
        assert!(result.score > 0, "a decompression bomb must not score zero");
    }

    #[test]
    fn no_cap_hit_leaves_the_result_untouched() {
        let mut result = crate::scanner::ScanResult {
            findings: vec![],
            score: 0,
            verdict: crate::scanner::Verdict::LowRisk,
            files_scanned: 1,
            duration_ms: 0,
            suppressed_findings: vec![],
            suppressed_by: None,
            scanner: None,
        };
        super::apply_extraction_report(
            &mut result,
            &super::ExtractionReport::default(),
            "fine@1.0.0",
        );
        assert!(result.findings.is_empty());
        assert_eq!(result.score, 0);
    }

    /// End-to-end: a real zip whose headers claim more than the cap must not
    /// write past it.
    #[test]
    fn zip_extraction_is_bounded_on_disk() {
        let dir = tempdir().expect("tempdir");
        let archive_path = dir.path().join("bomb.zip");
        {
            let f = fs::File::create(&archive_path).expect("create zip");
            let mut w = zip::ZipWriter::new(f);
            let opts = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            // Highly compressible: 8 MiB of zeros per entry, 40 entries.
            let payload = vec![0u8; 8 * 1024 * 1024];
            for i in 0..40 {
                w.start_file(format!("f{i}.bin"), opts).expect("start");
                std::io::Write::write_all(&mut w, &payload).expect("write");
            }
            w.finish().expect("finish");
        }

        let report = super::extract_archives(dir.path()).expect("extract");
        // 40 x 8 MiB = 320 MiB, under the 2 GiB cap, so this should complete.
        assert!(
            report.capped.is_none(),
            "320 MiB should be under the cap, got {:?}",
            report.capped
        );
        assert_eq!(report.entries, 40);

        // Everything that was admitted is accounted for in the byte total.
        assert_eq!(report.bytes, 40 * 8 * 1024 * 1024);
    }

    fn admit(r: &mut super::ExtractionReport, n: u64) -> bool {
        super::admit_entry(r, n)
    }

    #[test]
    fn acquisition_exit_code_contract() {
        use super::acquisition_exit_code;
        use crate::scanner::Verdict;
        assert_eq!(acquisition_exit_code(Verdict::LowRisk), super::EXIT_CLEAN);
        assert_eq!(
            acquisition_exit_code(Verdict::MediumRisk),
            super::EXIT_FINDINGS
        );
        assert_eq!(
            acquisition_exit_code(Verdict::HighRisk),
            super::EXIT_FINDINGS
        );
        assert_eq!(
            acquisition_exit_code(Verdict::CriticalRisk),
            super::EXIT_FINDINGS
        );
    }

    #[test]
    fn approve_with_ledger_pins_before_marking_approved() {
        with_isolated_home(|| {
            let entry = super::quarantine::add("pkg@1.0.0", "npm").expect("add entry");
            fs::write(entry.path.join("index.js"), "console.log(1);\n").expect("write file");

            let (approved, record) =
                approve_with_ledger(&entry.id, Some("reviewed")).expect("approve");

            assert_eq!(approved.id, entry.id);
            assert_eq!(record.id, entry.id);
            assert!(super::ledger::get(&entry.id).is_some());
        });
    }

    #[test]
    fn approve_with_ledger_rolls_back_pin_when_status_update_fails() {
        with_isolated_home(|| {
            let entry = super::quarantine::add("pkg@1.0.0", "npm").expect("add entry");
            fs::write(entry.path.join("index.js"), "console.log(1);\n").expect("write file");
            super::quarantine::approve(&entry.id, Some("pre-approved"))
                .expect("pre-approve without ledger");

            let error = approve_with_ledger(&entry.id, Some("reviewed"))
                .expect_err("already approved status must fail");

            assert!(error.contains("already approved"));
            assert!(super::ledger::get(&entry.id).is_none());
        });
    }
}
