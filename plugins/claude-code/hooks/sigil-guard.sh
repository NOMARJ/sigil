#!/bin/sh
# sigil-guard.sh — PreToolUse gate for Bash tool calls.
#
# Enforces Sigil's quarantine-first workflow: acquisition commands (git clone,
# package installs, curl|sh) are denied with a redirect to the sigil equivalent.
# Pure pattern gate — never invokes the sigil binary, never touches the network.
#
# Policy summary:
#   DENY  — commands that pull unscanned third-party code into the environment
#           (git clone, npm/pip/cargo/gem/go installs with explicit packages,
#           curl|sh pipelines). Redirected to sigil clone / sigil npm / sigil pip.
#   ASK   — commands that are lower risk but still execute third-party code
#           (bare lockfile restores, npx/dlx-style arbitrary-exec runners).
#   ALLOW — everything else.
#
# Escape hatches:
#   SIGIL_BYPASS=1        — allow this one command (also honoured as a prefix
#                           inside the command string itself).
#   SIGIL_GUARD_MODE      — "enforce" (default), "advise" (deny -> ask), "off".
#
# Always exits 0 with valid PreToolUse JSON on stdout.

MODE="${SIGIL_GUARD_MODE:-enforce}"

emit() {
  # $1 = permissionDecision, $2 = reason (must not contain " or \)
  printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"%s","permissionDecisionReason":"%s"}}\n' "$1" "$2"
  exit 0
}

deny() {
  # In advise mode every deny is downgraded to ask.
  if [ "$MODE" = "advise" ]; then
    emit ask "$1"
  else
    emit deny "$1"
  fi
}

# ── Mode / bypass short-circuits ───────────────────────────────────────────

[ "$MODE" = "off" ] && emit allow "Sigil guard disabled (SIGIL_GUARD_MODE=off)"
[ "$SIGIL_BYPASS" = "1" ] && emit allow "Sigil guard bypassed (SIGIL_BYPASS=1)"

# ── Extract .tool_input.command from the hook JSON on stdin ────────────────

INPUT=$(cat)

# ── Delegate to the native implementation when available ───────────────────
# `sigil hook pretooluse` (CLI v1.3.0+) is the maintained home of this
# policy; the patterns below are the dependency-free fallback for missing or
# older binaries (which exit non-zero on the unknown subcommand and fall
# through here).
if command -v sigil >/dev/null 2>&1; then
  NATIVE=$(printf '%s' "$INPUT" | sigil hook pretooluse 2>/dev/null) || NATIVE=""
  case "$NATIVE" in
    *permissionDecision*) printf '%s\n' "$NATIVE"; exit 0 ;;
  esac
fi

if command -v jq >/dev/null 2>&1; then
  CMD=$(printf '%s' "$INPUT" | jq -r '.tool_input.command // empty' 2>/dev/null)
else
  # Conservative fallback: grab the text after "command":" and cut at the
  # first unescaped double quote, then flatten JSON-escaped \n and \t to
  # spaces so multiline commands still hit the word-boundary patterns.
  # Prefer installing jq for exact extraction.
  CMD=$(printf '%s' "$INPUT" | tr '\n' ' ' \
    | sed -n 's/.*"command"[ 	]*:[ 	]*"//p' \
    | sed 's/\([^\\]\)".*/\1/' \
    | sed 's/\\[nt]/ /g')
fi

# Fail-open on parse: if the command can't be extracted we allow rather than
# block. We gate acquisition patterns, not people — an unparseable payload is
# a hook-plumbing problem, not evidence of an acquisition attempt.
[ -z "$CMD" ] && emit allow "Sigil guard: no command extracted"

has() {
  printf '%s\n' "$CMD" | grep -Eq "$1"
}

# Left word boundary: start of string, a shell separator, or a quote (so
# `bash -c 'npm install evil'` is still seen).
WB='(^|[[:space:];&|("'\''])'
# Any run of flag tokens, then at least one non-flag token (a package arg).
FLAGS='([[:space:]]+-[^[:space:]]+)*'
PKG='[[:space:]]+[^-[:space:]]'
# Modifier tokens between a tool name and its subcommand: runs of -flag
# tokens, each optionally followed by one non-flag argument. Covers forms
# like `git -C /tmp clone`, `npm --prefix ./x install`, `go -C x install`.
MOD='([[:space:]]+-[^[:space:]]+([[:space:]]+[^-[:space:]][^[:space:]]*)?)*'

# ── Bypass: the command is already going through sigil ─────────────────────

# A sigil invocation at the start of the command or of any pipeline/list
# segment is the acquiring command — allow it.
has '(^[[:space:]]*|[;&|][[:space:]]*)sigil[[:space:]]' \
  && emit allow "Command uses sigil"

# SIGIL_BYPASS=1 given as an env prefix inside the command string.
has "${WB}SIGIL_BYPASS=1([[:space:]]|\$)" \
  && emit allow "Sigil guard bypassed (SIGIL_BYPASS=1)"

# ── DENY: piping downloads straight into a shell ───────────────────────────

has "${WB}(curl|wget)[^|]*\|[[:space:]]*(sudo[[:space:]]+)?([^[:space:]]*/)?(sh|bash|zsh)([[:space:]]|\$)" \
  && deny "Piping a download into a shell executes unscanned code. Download the script, run sigil scan on it, then execute. Bypass: SIGIL_BYPASS=1"

# ── DENY: cloning repositories ─────────────────────────────────────────────

has "${WB}git${MOD}[[:space:]]+clone([[:space:]]|\$)" \
  && deny "git clone pulls unscanned code. Use: sigil clone <url> (quarantine + scan first). Bypass: SIGIL_BYPASS=1"

has "${WB}gh${MOD}[[:space:]]+repo[[:space:]]+clone([[:space:]]|\$)" \
  && deny "gh repo clone pulls unscanned code. Use: sigil clone <url> (quarantine + scan first). Bypass: SIGIL_BYPASS=1"

# ── npm: explicit package -> deny; bare lockfile restore -> ask ────────────

if has "${WB}npm${MOD}[[:space:]]+(install|i|add)([[:space:]]|\$)"; then
  if has "${WB}npm${MOD}[[:space:]]+(install|i|add)${FLAGS}${PKG}"; then
    deny "npm install with a package installs unscanned code. Use: sigil npm <pkg> (quarantine + scan first). Bypass: SIGIL_BYPASS=1"
  else
    emit ask "Bare npm install restores the lockfile, which can still run install scripts from unreviewed dependencies. Confirm the lockfile is trusted."
  fi
fi

has "${WB}npm${MOD}[[:space:]]+ci([[:space:]]|\$)" \
  && emit ask "npm ci restores the lockfile, which can still run install scripts from unreviewed dependencies. Confirm the lockfile is trusted."

# ── yarn / pnpm / bun ──────────────────────────────────────────────────────

has "${WB}(yarn|pnpm|bun)${MOD}([[:space:]]+global)?[[:space:]]+add${FLAGS}${PKG}" \
  && deny "Adding a package installs unscanned code. Use: sigil npm <pkg> (quarantine + scan first). Bypass: SIGIL_BYPASS=1"

# Arbitrary-exec runners before bare installs: `pnpm dlx foo` must not fall
# through to the pnpm install branch.
has "${WB}(pnpm|yarn)${MOD}[[:space:]]+dlx[[:space:]]" \
  && emit ask "dlx downloads and executes a package in one step with no scan. Prefer sigil npm <pkg> to vet it first."

has "${WB}(yarn|pnpm)${MOD}[[:space:]]+install([[:space:]]|\$)" \
  && emit ask "Lockfile restore can still run install scripts from unreviewed dependencies. Confirm the lockfile is trusted."

# ── pip / uv: -r requirements -> ask; explicit package -> deny ─────────────

PIP_INSTALL="${WB}(pip[0-9.]*${MOD}[[:space:]]+install|python[0-9.]*[[:space:]]+-m[[:space:]]+pip[[:space:]]+install|uv[[:space:]]+pip[[:space:]]+install)"
if has "${PIP_INSTALL}([[:space:]]|\$)"; then
  if has "(^|[[:space:]])(-r|--requirement)([[:space:]]|\$)"; then
    emit ask "pip install -r installs every pinned dependency, any of which can run setup.py code. Confirm the requirements file is trusted."
  elif has "${PIP_INSTALL}${FLAGS}${PKG}"; then
    deny "pip install with a package installs unscanned code. Use: sigil pip <pkg> (quarantine + scan first). Bypass: SIGIL_BYPASS=1"
  else
    emit ask "Bare pip install can execute setup.py from the current directory. Run sigil scan . first."
  fi
fi

has "${WB}uv${MOD}[[:space:]]+add${FLAGS}${PKG}" \
  && deny "uv add installs unscanned code. Use: sigil pip <pkg> (quarantine + scan first). Bypass: SIGIL_BYPASS=1"

# ── Other package managers with explicit packages ──────────────────────────

has "${WB}cargo${MOD}[[:space:]]+(install|add)${FLAGS}${PKG}" \
  && deny "cargo install/add builds and installs unscanned code. Quarantine + scan the crate source with sigil clone first. Bypass: SIGIL_BYPASS=1"

has "${WB}gem${MOD}[[:space:]]+install${FLAGS}${PKG}" \
  && deny "gem install runs unscanned code (gems can execute extensions at install). Quarantine + scan the source with sigil clone first. Bypass: SIGIL_BYPASS=1"

has "${WB}go${MOD}[[:space:]]+(install|get)${FLAGS}${PKG}" \
  && deny "go install/get fetches and builds unscanned code. Quarantine + scan the module source with sigil clone first. Bypass: SIGIL_BYPASS=1"

# ── ASK: remaining lockfile restores and arbitrary-exec runners ────────────

has "${WB}bundle[[:space:]]+install([[:space:]]|\$)" \
  && emit ask "bundle install restores the Gemfile.lock, which can run native extension code from unreviewed gems. Confirm the lockfile is trusted."

has "${WB}(npx|bunx|uvx)[[:space:]]+" \
  && emit ask "This runner downloads and executes a package in one step with no scan. Prefer vetting the package with sigil first."

has "${WB}pipx[[:space:]]+run[[:space:]]" \
  && emit ask "pipx run downloads and executes a package in one step with no scan. Prefer sigil pip <pkg> to vet it first."

# ── Default ────────────────────────────────────────────────────────────────

emit allow "No acquisition pattern matched"
