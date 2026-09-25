# Changelog

All notable changes to the Sigil Security plugin for Claude Code will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- The PreToolUse gate now also runs on Write, Edit and MultiEdit (matcher `Bash|Write|Edit|MultiEdit`). The native `sigil hook pretooluse` denies edits that plant a download-to-shell or an exfiltrating command in agent tooling (hooks, MCP configs, skills), and asks before hook or MCP-config edits.
- The shell fallback (`hooks/sigil-guard.sh`, used when the binary is not on PATH) now denies remote runners (`npx`, `bunx`, `uvx`, `pipx run`, `pnpm dlx`, `yarn dlx`) instead of asking, matching the native hook.
- The shell fallback now also has the native hook's remote-execution denies, with the same reasons:
  - a download piped through `tee`, into `bash -s …`, into `sudo -u <user> bash`, into python/node/perl/ruby/php/deno/bun or PowerShell `iex`, or substituted into one (`bash <(curl …)`, `sh -c "$(curl …)"`). This is never gated, and a `sigil` call elsewhere in the command no longer exempts it;
  - a file downloaded and run in one command (`curl -o i.sh URL && bash i.sh`, `wget …/x.sh; sh x.sh`, `curl … > i.sh && ./i.sh`), allowed when `sigil scan i.sh &&` comes between the download and the run;
  - a download saved into agent tooling (`curl … > ~/.claude/skills/x/SKILL.md`, `-o .mcp.json`, `wget -P ~/.codex/skills`, `.cursor/rules`, `.gemini/…` and the other paths the native hook lists), never gated;
  - `pipx install <pkg>` and `uv tool install <pkg>`, allowed after `sigil pip <pkg> &&`;
  - `deno run|x|install|serve` of an `npm:`, `jsr:` or `http(s)://` module (`npm:` allowed after `sigil npm <pkg> &&`);
  - `npm exec` / `npm x`, `bun x` and `uv tool run` of a registry package, in command position as the native hook matches runners, allowed after `sigil npm|pip <pkg> &&` (`bun x <bin>` of the project's own `node_modules/.bin` is allowed, as natively).
- Like the native hook, the fallback judges these per pipeline stage, and it follows `cd`. It matches command words after quote removal (`cu''rl`, `w\get` and `"curl"` are curl) and treats a runner word as a runner only in command position, so a URL ending in `/npx` or an argument named `bunx` does not exempt a stage from these checks. It no longer denies a download piped into an interpreter that reads it as data (`| python3 -m json.tool`, `| bash -c '…'`, `| sh ./script.sh`).
- The per-stage checks need `awk`. Without it they are skipped, and the pipe check and the older rules still apply.
- Without `jq`, a JSON-escaped newline in the command now separates commands, as it does with `jq`, instead of becoming a space. Deny reasons that quote the command are JSON-escaped.
- The gate (native hook and shell fallback alike) now closes command shapes that got past both:
  - a download piped to an interpreter after `2>&1` or `|&`, with `;`, `&`, `#` or an output redirect after the interpreter, a quoted interpreter name (`| "bash"`, `| ba''sh`), `env -i`, `command`, `doas`, `busybox`, `timeout` or `$SHELL` in front of it, a whole pipeline in backticks, `bash < <(curl …)` and `bash <<< "$(curl …)"`;
  - a downloaded file run through `bash -e`, `sudo -u <user>` / `sudo -E`, `exec`, `command`, `nohup`, `time`, `xargs`, `. ./i.sh`, `( … )` or `{ …; }`, `bash < i.sh` or `cat i.sh | sh`, saved by `curl -oFILE`, `1> FILE`, `&> FILE` or `| tee FILE`, or run with an option that takes a value (`python3 -X dev`, `bash -O extglob`, `bash -euo pipefail`);
  - the scan gate: a scan that ran before the download, or before a second download to the same path, no longer vets it; only the bare `sigil` on PATH vets (not `./sigil`, not `PATH=… sigil`, and nothing when the command defines a `sigil` function or alias or changes PATH);
  - downloads into agent tooling behind `sudo -E`, `env`, `command`, a `( … )` subshell, `bash -c '…'`, or through `| tee <tooling path>`;
  - quoted command words (`"npm" exec`, `de''no run`, `pip''x install`) and runners behind a wrapper (`sudo -u root npm exec x`).
- Paths apply `..` (`curl -o i.sh …; cd sub; bash ../i.sh` is denied), and `wget -P dir -O f` is read as saving to `f`, as wget does.
- A scan gate across a line continuation (`… && sigil scan i.sh && \` then `bash i.sh`) is no longer denied: a backslash-newline continues the command.
- A download piped to an interpreter whose stdin is a here-document or a file (`curl … | python3 - <<'EOF'`, `curl … | bash < local.sh`) is no longer denied: the download is not what runs.
- The fallback reads each stage the way the native hook does (`cmdline::command_words`: grouping, redirections, assignments and wrapper commands set aside; interpreter options read per interpreter), in its awk lexer, and gives the same reasons for these denies. Measured on synthetic commands written for these shapes, it agrees with the native hook on 12,444 of 12,444 generated download-to-interpreter commands (decision and reason) and on the decision for 22,242 of 22,246 generated per-stage commands; the 4 others are its older early allow of a command in which a segment starts with `sigil` (below).
- Known difference, unchanged: when any segment of a command starts with `sigil`, the fallback allows the whole command before its package-manager rules run (`sigil --version; npm install evil`), where the native hook judges each segment.
- The bundled MCP server is now the `sigil` binary's built-in server (`sigil mcp`) instead of `npx -y @nomark/sigil-mcp-server`. The npm package was never published, so the previous registration failed to start on every install; the built-in server needs nothing beyond the `sigil` binary the hooks already require.

## [1.1.0] - 2026-08-06

### Added
- PreToolUse enforcement gate (`hooks/sigil-guard.sh`): blocks `git clone`, `npm install <pkg>`, `pip install <pkg>`, `cargo`/`gem`/`go` installs, and curl-pipe-to-shell in Claude Code sessions, redirecting to Sigil's quarantine-first equivalents. Lockfile restores and one-shot runners (`npx`, `dlx`, `pipx run`) prompt for confirmation instead
- Escape hatches for the gate: `SIGIL_BYPASS=1` (single command) and `SIGIL_GUARD_MODE=enforce|advise|off`
- SessionStart hook (`hooks/session-setup.sh`) that checks the `sigil` binary is available and surfaces install instructions when it is missing
- Automatic MCP server registration: installing the plugin now registers `@nomark/sigil-mcp-server` via `mcpServers` in the plugin manifest

### Changed
- Skills now invoke `sigil` from PATH instead of the repo-relative `./bin/sigil`, so they work in any project directory
- `scan-file` skill gained `name` and `allowed-tools` frontmatter matching the other skills
- `security-auditor` agent and plugin documentation updated to cover all 8 scan phases, adding Prompt Injection (Critical 10x) and Skill Security (High 5x)

## [1.0.0] - 2026-02-22

### Added
- Initial release of Sigil Security plugin for Claude Code
- Four security scanning skills:
  - `scan-repo` - Scan repositories for malicious patterns
  - `scan-package` - Audit npm and pip packages before installation
  - `scan-file` - Analyze specific files for security vulnerabilities
  - `review-quarantine` - Review and manage quarantined findings
- Two specialized security agents:
  - `security-auditor` - Expert threat analysis and remediation guidance
  - `quarantine-manager` - Quarantine workflow coordination
- Automated hooks for security recommendations:
  - Auto-suggest Sigil when user mentions cloning, installing, or security
  - Advisory prompts suggesting quarantine alternatives when `git clone`, `pip install`, or `npm install` appear in a prompt (advisory only — commands were not blocked; enforcement arrived in 1.1.0)
- Comprehensive documentation and usage examples
- Support for all 6 Sigil scan phases:
  - Install Hooks (Critical 10x)
  - Code Patterns (High 5x)
  - Network/Exfiltration (High 3x)
  - Credentials (Medium 2x)
  - Obfuscation (High 5x)
  - Provenance (Low 1-3x)

### Security
- Implements quarantine-first workflow for AI agent code
- Detects supply-chain attacks before code execution
- Risk-based scoring system (CLEAN, LOW, MEDIUM, HIGH, CRITICAL)
- Threat intelligence integration via Sigil CLI

## [Unreleased]

### Planned
- Custom scan rule configuration
- Integration with Sigil Pro dashboard
- Team policy enforcement
- CI/CD integration helpers
- Enhanced false positive detection
