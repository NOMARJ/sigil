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

/// Build a docker/podman run command from a SigilPolicy.
pub fn build_run_command(
    runtime: &str,
    policy: &SigilPolicy,
    workdir: &Path,
    command: &[String],
    env_vars: &HashMap<String, String>,
) -> Command {
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

    cmd
}

/// Execute a command in a sandboxed container.
///
/// Falls back to direct execution if no container runtime is available.
pub fn run_sandboxed(
    policy: &SigilPolicy,
    workdir: &Path,
    command: &[String],
    env_vars: &HashMap<String, String>,
    verbose: bool,
) -> Result<i32, Box<dyn std::error::Error>> {
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

            let mut cmd = build_run_command(&runtime, policy, workdir, command, env_vars);

            if verbose {
                eprintln!("sandbox: {:?}", cmd);
            }

            let status = cmd.status()?;
            Ok(status.code().unwrap_or(1))
        }
        None => {
            eprintln!("warning: no container runtime (docker/podman) found, running unsandboxed");

            if verbose {
                eprintln!("sandbox: fallback direct execution");
                eprintln!("sandbox: workdir={}", workdir.display());
                eprintln!("sandbox: command={:?}", command);
            }

            let status = Command::new(&command[0])
                .args(&command[1..])
                .current_dir(workdir)
                .envs(env_vars)
                .status()?;

            Ok(status.code().unwrap_or(1))
        }
    }
}
