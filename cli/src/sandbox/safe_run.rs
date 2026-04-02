use crate::policy::generate::generate_from_scan;
use crate::provider;
use crate::scanner::{self, Verdict};
use super::container;
use std::collections::HashMap;
use std::io::{self, Write};
use std::path::Path;

/// Run a safe execution: scan, generate policy, optionally confirm, then sandbox.
pub fn safe_run(
    path: &Path,
    command: &[String],
    providers: Option<&[String]>,
    auto_approve: bool,
    verbose: bool,
) -> Result<i32, Box<dyn std::error::Error>> {
    // Step 1: Scan
    eprintln!("Scanning {}...", path.display());
    let scan = scanner::run_scan(path, None, None);

    eprintln!(
        "Scan complete: {} files, {} findings, score {}, verdict {:?}",
        scan.files_scanned,
        scan.findings.len(),
        scan.score,
        scan.verdict
    );

    // Step 2: Check verdict — block CRITICAL
    match scan.verdict {
        Verdict::CriticalRisk => {
            eprintln!("CRITICAL RISK detected. Execution blocked.");
            eprintln!("Review findings with: sigil scan {}", path.display());
            return Ok(1);
        }
        Verdict::HighRisk if !auto_approve => {
            eprintln!("HIGH RISK detected. Proceed with sandboxed execution? [y/N]");
            io::stdout().flush()?;
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            if !input.trim().eq_ignore_ascii_case("y") {
                eprintln!("Aborted.");
                return Ok(1);
            }
        }
        _ => {}
    }

    // Step 3: Generate policy from scan results
    let policy = generate_from_scan(&scan);

    if verbose {
        if let Ok(yaml) = policy.to_yaml() {
            eprintln!("Generated policy:\n{}", yaml);
        }
    }

    // Step 4: Resolve credentials
    let env_vars = if let Some(provider_names) = providers {
        provider::resolve_env(&provider_names.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    } else {
        // Default: only pass PATH, HOME, TERM
        let mut env = HashMap::new();
        for key in &["PATH", "HOME", "TERM"] {
            if let Ok(val) = std::env::var(key) {
                env.insert(key.to_string(), val);
            }
        }
        env
    };

    // Step 5: Run in sandbox
    eprintln!("Launching sandboxed execution...");
    container::run_sandboxed(&policy, path, command, &env_vars, verbose)
}
