use crate::policy::schema::SigilPolicy;
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

/// Check if Docker or Podman is available on the system.
pub fn detect_runtime() -> Option<String> {
    for runtime in &["docker", "podman"] {
        if Command::new(runtime)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            return Some(runtime.to_string());
        }
    }
    None
}

fn ensure_network_policy_enforceable(
    policy: &SigilPolicy,
) -> Result<(), Box<dyn std::error::Error>> {
    if policy.network.default_action == "deny" && !policy.network.rules.is_empty() {
        return Err(
            "network allowlist rules are not enforceable by the current container sandbox; use strict/no-network policy or a policy with default_action: log"
                .into(),
        );
    }

    Ok(())
}

/// Build a docker/podman run command from a SigilPolicy.
pub fn build_run_command(
    runtime: &str,
    policy: &SigilPolicy,
    workdir: &Path,
    command: &[String],
    env_vars: &HashMap<String, String>,
) -> Result<Command, Box<dyn std::error::Error>> {
    ensure_network_policy_enforceable(policy)?;

    let mut cmd = Command::new(runtime);
    cmd.arg("run").arg("--rm").arg("-it");

    // Working directory mount
    if policy.filesystem.include_workdir {
        let abs_workdir = std::fs::canonicalize(workdir).unwrap_or_else(|_| workdir.to_path_buf());
        cmd.arg("-v")
            .arg(format!("{}:/workspace", abs_workdir.display()))
            .arg("-w")
            .arg("/workspace");
    }

    // Read-only mounts
    for ro_path in &policy.filesystem.read_only {
        cmd.arg("-v").arg(format!("{}:{}:ro", ro_path, ro_path));
    }

    // Read-write mounts (tmpfs for /tmp)
    for rw_path in &policy.filesystem.read_write {
        if rw_path == "/tmp" {
            cmd.arg("--tmpfs").arg("/tmp:rw,noexec,nosuid,size=512m");
        } else {
            cmd.arg("-v").arg(format!("{}:{}", rw_path, rw_path));
        }
    }

    // Network policy
    if policy.network.default_action == "deny" && policy.network.rules.is_empty() {
        cmd.arg("--network").arg("none");
    }

    // Process policy
    if let Some(ref user) = policy.process.run_as_user {
        if let Some(ref group) = policy.process.run_as_group {
            cmd.arg("--user").arg(format!("{}:{}", user, group));
        } else {
            cmd.arg("--user").arg(user);
        }
    }

    // Security options
    if policy
        .process
        .deny_syscall_categories
        .contains(&"privilege_escalation".to_string())
    {
        cmd.arg("--security-opt").arg("no-new-privileges");
        cmd.arg("--cap-drop").arg("ALL");
    }

    // Environment variables (only allowed ones)
    for (key, value) in env_vars {
        cmd.arg("-e").arg(format!("{}={}", key, value));
    }

    // Read-only root filesystem for strict policies
    if policy.name == "strict" {
        cmd.arg("--read-only");
    }

    // Base image
    cmd.arg("python:3.13-slim");

    // The command to run inside the container
    if !command.is_empty() {
        cmd.args(command);
    }

    Ok(cmd)
}

/// Execute a command in a sandboxed container.
///
pub fn run_sandboxed(
    policy: &SigilPolicy,
    workdir: &Path,
    command: &[String],
    env_vars: &HashMap<String, String>,
    verbose: bool,
) -> Result<i32, Box<dyn std::error::Error>> {
    run_sandboxed_with_runtime_detector(policy, workdir, command, env_vars, verbose, detect_runtime)
}

fn run_sandboxed_with_runtime_detector<F>(
    policy: &SigilPolicy,
    workdir: &Path,
    command: &[String],
    env_vars: &HashMap<String, String>,
    verbose: bool,
    detect_runtime: F,
) -> Result<i32, Box<dyn std::error::Error>>
where
    F: FnOnce() -> Option<String>,
{
    if command.is_empty() {
        return Err("no command specified".into());
    }

    match detect_runtime() {
        Some(runtime) => {
            if verbose {
                eprintln!("sandbox: using {} runtime", runtime);
                eprintln!(
                    "sandbox: policy={} ({})",
                    policy.name,
                    policy.description.as_deref().unwrap_or("")
                );
                eprintln!("sandbox: workdir={}", workdir.display());
                eprintln!("sandbox: command={:?}", command);
                eprintln!(
                    "sandbox: env_vars={:?}",
                    env_vars.keys().collect::<Vec<_>>()
                );
            }

            let mut cmd = build_run_command(&runtime, policy, workdir, command, env_vars)?;

            if verbose {
                eprintln!("sandbox: {:?}", cmd);
            }

            let status = cmd.status()?;
            Ok(status.code().unwrap_or(1))
        }
        None => {
            Err("no container runtime (docker/podman) found; refusing to run unsandboxed".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::schema::SigilPolicy;

    fn args(command: &Command) -> Vec<String> {
        command
            .get_args()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect()
    }

    #[test]
    fn fails_closed_when_runtime_is_missing() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let sentinel = tempdir.path().join("executed");
        let command = vec![
            "sh".to_string(),
            "-c".to_string(),
            format!("touch {}", sentinel.display()),
        ];

        let result = run_sandboxed_with_runtime_detector(
            &SigilPolicy::preset("strict").expect("strict policy"),
            tempdir.path(),
            &command,
            &HashMap::new(),
            false,
            || None,
        );

        assert!(result.is_err());
        assert!(!sentinel.exists(), "command must not run on the host");
    }

    #[test]
    fn strict_policy_disables_network() {
        let command = build_run_command(
            "docker",
            &SigilPolicy::preset("strict").expect("strict policy"),
            Path::new("."),
            &["true".to_string()],
            &HashMap::new(),
        )
        .expect("strict policy should be enforceable");

        assert!(args(&command)
            .windows(2)
            .any(|window| window == ["--network", "none"]));
    }

    #[test]
    fn allowlist_policy_does_not_run_with_unrestricted_network() {
        let result = build_run_command(
            "docker",
            &SigilPolicy::preset("standard").expect("standard policy"),
            Path::new("."),
            &["true".to_string()],
            &HashMap::new(),
        );

        assert!(result.is_err());
    }
}
