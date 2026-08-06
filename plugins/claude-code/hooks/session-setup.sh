#!/bin/sh
# session-setup.sh — SessionStart check for the Sigil CLI.
#
# If sigil is on PATH: exit quietly (no context injected).
# If missing: inject SessionStart additionalContext telling the agent that
# enforcement is active but the CLI is absent, with install instructions.
#
# SIGIL_AUTO_INSTALL=1 opts in to installing the CLI from the latest GitHub
# release with SHA256SUMS verification (same approach as the sigil-scan skill
# installer). The default is to NEVER download anything.
#
# Always exits 0.

REPO="NOMARJ/sigil"
INSTALL_DIR="$HOME/.local/bin"

emit_context() {
  # $1 = additionalContext (must not contain " or \)
  printf '{"hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":"%s"}}\n' "$1"
}

find_sigil() {
  command -v sigil 2>/dev/null && return 0
  [ -x "$HOME/.local/bin/sigil" ] && { echo "$HOME/.local/bin/sigil"; return 0; }
  return 1
}

# ── Already installed: nothing to say ──────────────────────────────────────

if find_sigil >/dev/null 2>&1; then
  exit 0
fi

# ── Optional auto-install (opt-in only) ────────────────────────────────────

auto_install() {
  OS=$(uname -s); ARCH=$(uname -m)
  case "$OS" in
    Linux) PLATFORM=linux ;;
    Darwin) PLATFORM=macos ;;
    *) return 1 ;;
  esac
  case "$ARCH" in
    x86_64) ARCH_NORM=x86_64 ;;
    aarch64|arm64) ARCH_NORM=aarch64 ;;
    *) return 1 ;;
  esac

  command -v curl >/dev/null 2>&1 || return 1

  TAG=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null \
    | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
  [ -n "$TAG" ] || return 1

  ASSET="sigil-${PLATFORM}-${ARCH_NORM}"
  BASE="https://github.com/${REPO}/releases/download/${TAG}"
  TMP=$(mktemp) || return 1
  SUMS=$(mktemp) || { rm -f "$TMP"; return 1; }

  if ! curl -fsSL "${BASE}/${ASSET}" -o "$TMP" 2>/dev/null; then
    rm -f "$TMP" "$SUMS"; return 1
  fi

  # Checksum verification is mandatory for auto-install: no SHA256SUMS.txt or
  # no matching entry means we refuse to install.
  if ! curl -fsSL "${BASE}/SHA256SUMS.txt" -o "$SUMS" 2>/dev/null; then
    rm -f "$TMP" "$SUMS"; return 1
  fi
  EXPECTED=$(grep "$ASSET" "$SUMS" 2>/dev/null | awk '{print $1}')
  if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL=$(sha256sum "$TMP" | awk '{print $1}')
  elif command -v shasum >/dev/null 2>&1; then
    ACTUAL=$(shasum -a 256 "$TMP" | awk '{print $1}')
  else
    ACTUAL=""
  fi
  if [ -z "$EXPECTED" ] || [ -z "$ACTUAL" ] || [ "$EXPECTED" != "$ACTUAL" ]; then
    rm -f "$TMP" "$SUMS"; return 1
  fi
  rm -f "$SUMS"

  chmod +x "$TMP"
  if ! "$TMP" --version >/dev/null 2>&1; then
    rm -f "$TMP"; return 1
  fi

  mkdir -p "$INSTALL_DIR" && mv "$TMP" "${INSTALL_DIR}/sigil" || { rm -f "$TMP"; return 1; }
  return 0
}

if [ "$SIGIL_AUTO_INSTALL" = "1" ]; then
  if auto_install; then
    emit_context "Sigil CLI was auto-installed to ${INSTALL_DIR}/sigil (checksum verified). Use sigil clone / sigil pip / sigil npm to acquire third-party code."
    exit 0
  fi
  # Fall through to the missing-CLI notice if the install failed.
fi

# ── Missing: tell the agent, but download nothing by default ───────────────

emit_context "Sigil enforcement is active but the sigil CLI is not installed. Acquisition commands (git clone, npm/pip installs, curl|sh) are still gated by pattern and will be denied with sigil alternatives that need the CLI. Install it first: curl -fsSLO https://www.sigilsec.ai/install.sh && sh install.sh — then use sigil clone / sigil pip / sigil npm. Set SIGIL_AUTO_INSTALL=1 to let this hook install a checksum-verified release automatically."

exit 0
