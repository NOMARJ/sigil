use super::container;
use crate::enforcement::{self, Gate};
use crate::policy::generate::generate_from_scan;
use crate::provider;
use crate::scanner;
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

    // Step 2: may we run this at all?
    //
    // Keyed on `enforcement::level_for`, not on `scan.verdict`. The verdict is a
    // report label that is cached, serialized and rewritten; the level is the max
    // of that label and the verdict recomputed from `scan.findings`, so a demotion
    // of the label alone cannot remove this prompt. See `crate::enforcement`.
    match enforcement::gate(enforcement::level_for(&scan), auto_approve) {
        Gate::Block => {
            eprintln!("CRITICAL RISK detected. Execution blocked.");
            eprintln!("Review findings with: sigil scan {}", path.display());
            return Ok(1);
        }
        Gate::Confirm => {
            eprintln!("HIGH RISK detected. Proceed with sandboxed execution? [y/N]");
            // Flush stderr, which is where the prompt went. Reading a
            // non-terminal stdin yields an empty line, which is not "y", so this
            // fails closed in a pipeline rather than hanging.
            io::stderr().flush()?;
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            if !input.trim().eq_ignore_ascii_case("y") {
                eprintln!("Aborted.");
                return Ok(1);
            }
        }
        Gate::Proceed => {}
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
        provider::resolve_env(
            &provider_names
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>(),
        )
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
