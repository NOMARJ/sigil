use crate::policy::schema::SigilPolicy;
use std::collections::HashMap;
use std::path::Path;

/// Run a command inside a sandboxed container governed by the given policy.
///
/// This is a stub implementation that will be completed in STORY-005.
/// For now it executes the command directly (unsandboxed) and returns the exit code.
pub fn run_sandboxed(
    _policy: &SigilPolicy,
    working_dir: &Path,
    command: &[String],
    env_vars: &HashMap<String, String>,
    verbose: bool,
) -> Result<i32, Box<dyn std::error::Error>> {
    if command.is_empty() {
        return Err("no command specified".into());
    }

    if verbose {
        eprintln!("sandbox: working_dir={}", working_dir.display());
        eprintln!("sandbox: command={:?}", command);
        eprintln!("sandbox: env_vars={:?}", env_vars.keys().collect::<Vec<_>>());
    }

    // TODO(STORY-005): Replace with actual container/sandbox execution.
    // For now, run the command directly so the pipeline is testable end-to-end.
    let status = std::process::Command::new(&command[0])
        .args(&command[1..])
        .current_dir(working_dir)
        .envs(env_vars)
        .status()?;

    Ok(status.code().unwrap_or(1))
}
