//! `sigil setup` — wire Sigil into AI agent and developer workflows.
//!
//! Targets:
//!   claude — register the Claude Code plugin marketplace and install the
//!            sigil-security plugin (requires the `claude` CLI on PATH)
//!   shell  — append gclone/safepip/safenpm aliases to the shell rc
//!   git    — install a pre-commit hook running `sigil scan --fail-on high`
//!   all    — claude + shell, plus git when run inside a git repository
//!
//! Every step is best-effort and idempotent: nothing here fails the overall
//! setup, and re-running never duplicates configuration. The alias marker
//! matches the one used by install.sh --with-aliases so the two installers
//! recognise each other's work.

use colored::Colorize;
use std::path::Path;
use std::process::Command;

const ALIAS_MARKER: &str = "# >>> sigil aliases >>>";
const HOOK_MARKER: &str = "# sigil pre-commit hook";

fn info(msg: &str) {
    println!("{} {msg}", "sigil:".bold().cyan());
}

fn ok(msg: &str) {
    println!("{} {msg}", "sigil:".bold().green());
}

fn warn(msg: &str) {
    eprintln!("{} {msg}", "sigil:".bold().yellow());
}

pub fn cmd_setup(target: &str) -> i32 {
    match target {
        "claude" => setup_claude(),
        "shell" => setup_shell(),
        "git" => setup_git(),
        "all" => {
            let mut rc = setup_claude();
            rc |= setup_shell();
            if Path::new(".git").is_dir() {
                rc |= setup_git();
            } else {
                info("Not inside a git repository — skipping pre-commit hook (run `sigil setup git` in a repo).");
            }
            rc
        }
        other => {
            eprintln!(
                "{} unknown setup target '{other}' (use claude, shell, git, or all)",
                "error:".bold().red()
            );
            2
        }
    }
}

fn setup_claude() -> i32 {
    if which("claude").is_none() {
        info("Claude Code CLI not found — skipping plugin setup.");
        info("To wire Sigil into AI agents later, see docs/ai-agent-integration.md");
        return 0;
    }

    info("Claude Code detected — setting up the Sigil plugin (best-effort)...");
    match run("claude", &["plugin", "marketplace", "add", "NOMARJ/sigil"]) {
        true => ok("Added plugin marketplace: NOMARJ/sigil"),
        false => warn("Could not add plugin marketplace NOMARJ/sigil (may already be added, or the command failed)"),
    }
    match run(
        "claude",
        &["plugin", "install", "sigil-security@sigil-marketplace"],
    ) {
        true => ok("Installed Claude Code plugin: sigil-security"),
        false => {
            warn("Could not install the sigil-security plugin. Run manually when ready:");
            warn("  claude plugin install sigil-security@sigil-marketplace");
        }
    }
    0
}

fn setup_shell() -> i32 {
    let shell = std::env::var("SHELL").unwrap_or_default();
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => {
            warn("Could not determine home directory — add aliases manually:");
            warn("  alias gclone='sigil clone' safepip='sigil pip' safenpm='sigil npm'");
            return 0;
        }
    };
    let rc_file = if shell.ends_with("/zsh") {
        home.join(".zshrc")
    } else if shell.ends_with("/bash") {
        home.join(".bashrc")
    } else {
        warn("Could not detect a bash/zsh rc file. Add aliases manually:");
        warn("  alias gclone='sigil clone' safepip='sigil pip' safenpm='sigil npm'");
        return 0;
    };

    let existing = std::fs::read_to_string(&rc_file).unwrap_or_default();
    if existing.contains(ALIAS_MARKER) {
        ok(&format!(
            "Sigil aliases already present in {} — nothing to do",
            rc_file.display()
        ));
        return 0;
    }

    let block = format!(
        "\n{ALIAS_MARKER}\nalias gclone='sigil clone'\nalias safepip='sigil pip'\nalias safenpm='sigil npm'\n# <<< sigil aliases <<<\n"
    );
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&rc_file)
        .and_then(|mut f| std::io::Write::write_all(&mut f, block.as_bytes()))
    {
        Ok(()) => {
            ok(&format!("Aliases installed to {}", rc_file.display()));
            info("Reload your shell (or `source` the rc file) to activate gclone / safepip / safenpm.");
            0
        }
        Err(err) => {
            warn(&format!(
                "Could not write aliases to {}: {err}",
                rc_file.display()
            ));
            1
        }
    }
}

fn setup_git() -> i32 {
    let hooks_dir = Path::new(".git/hooks");
    if !hooks_dir.is_dir() {
        eprintln!(
            "{} not a git repository (no .git/hooks directory here)",
            "error:".bold().red()
        );
        return 1;
    }

    let hook_path = hooks_dir.join("pre-commit");
    if let Ok(existing) = std::fs::read_to_string(&hook_path) {
        if existing.contains(HOOK_MARKER) {
            ok("Sigil pre-commit hook already installed — nothing to do");
            return 0;
        }
        warn(&format!(
            "A pre-commit hook already exists at {} and was not written by sigil — leaving it untouched.",
            hook_path.display()
        ));
        warn("Add `sigil scan . --fail-on high` to it manually, or use the pre-commit framework (.pre-commit-hooks.yaml).");
        return 0;
    }

    let hook = format!(
        "#!/bin/sh\n{HOOK_MARKER}\n# Scans the repository before each commit; blocks on HIGH/CRITICAL findings.\n# Bypass a single commit with: git commit --no-verify\nif ! command -v sigil >/dev/null 2>&1; then\n  echo \"sigil: binary not found on PATH — skipping pre-commit scan\" >&2\n  exit 0\nfi\nexec sigil scan . --fail-on high\n"
    );
    if let Err(err) = std::fs::write(&hook_path, hook) {
        eprintln!(
            "{} could not write {}: {err}",
            "error:".bold().red(),
            hook_path.display()
        );
        return 1;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&hook_path, std::fs::Permissions::from_mode(0o755));
    }
    ok(&format!(
        "Installed pre-commit hook to {}",
        hook_path.display()
    ));
    0
}

fn which(bin: &str) -> Option<std::path::PathBuf> {
    let paths = std::env::var_os("PATH")?;
    std::env::split_paths(&paths)
        .map(|dir| dir.join(bin))
        .find(|candidate| candidate.is_file())
}

fn run(bin: &str, args: &[&str]) -> bool {
    Command::new(bin)
        .args(args)
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}
