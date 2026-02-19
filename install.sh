#!/usr/bin/env sh
# Sigil installer
# Usage: curl -sSL https://sigilsec.ai/install.sh | sh
#    or: curl -sSL https://raw.githubusercontent.com/NOMARJ/sigil/main/install.sh | sh

set -e

REPO="NOMARJ/sigil"
BINARY_NAME="sigil"
INSTALL_DIR="/usr/local/bin"
GITHUB_RAW="https://raw.githubusercontent.com/${REPO}/main"

# ── Helpers ──────────────────────────────────────────────────────────────────

info()  { printf '\033[1;34m[sigil]\033[0m %s\n' "$*"; }
ok()    { printf '\033[1;32m[sigil]\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33m[sigil]\033[0m %s\n' "$*"; }
die()   { printf '\033[1;31m[sigil]\033[0m %s\n' "$*" >&2; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

# ── Platform detection ────────────────────────────────────────────────────────

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Linux)  PLATFORM="linux" ;;
  Darwin) PLATFORM="macos" ;;
  *)      die "Unsupported OS: $OS. Install manually from https://github.com/${REPO}" ;;
esac

case "$ARCH" in
  x86_64)          ARCH_NORM="x86_64" ;;
  aarch64|arm64)   ARCH_NORM="aarch64" ;;
  *)               die "Unsupported architecture: $ARCH" ;;
esac

# ── Check install dir is writable ────────────────────────────────────────────

if [ ! -w "$INSTALL_DIR" ]; then
  if have sudo; then
    SUDO="sudo"
    warn "Installing to ${INSTALL_DIR} — sudo may prompt for your password"
  else
    die "${INSTALL_DIR} is not writable and sudo is not available. Run as root or set a writable INSTALL_DIR."
  fi
fi

# ── Check for pre-built release binary ───────────────────────────────────────

RELEASE_URL=""
if have curl || have wget; then
  # Check if a versioned release binary exists on GitHub Releases
  LATEST_TAG="$(curl -sfL "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null \
    | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')"

  if [ -n "$LATEST_TAG" ]; then
    ASSET_NAME="${BINARY_NAME}-${PLATFORM}-${ARCH_NORM}"
    RELEASE_URL="https://github.com/${REPO}/releases/download/${LATEST_TAG}/${ASSET_NAME}"
  fi
fi

install_from_release() {
  info "Downloading Sigil ${LATEST_TAG} for ${PLATFORM}/${ARCH_NORM}..."
  TMP="$(mktemp)"
  if have curl; then
    curl -fsSL "$RELEASE_URL" -o "$TMP" || return 1
  else
    wget -qO "$TMP" "$RELEASE_URL" || return 1
  fi
  chmod +x "$TMP"
  # Quick sanity check — should print a version string
  if ! "$TMP" --version >/dev/null 2>&1; then
    rm -f "$TMP"
    return 1
  fi
  ${SUDO:-} mv "$TMP" "${INSTALL_DIR}/${BINARY_NAME}"
  ok "Installed Rust binary → ${INSTALL_DIR}/${BINARY_NAME}"
  return 0
}

# ── Fallback: download bash script from GitHub ────────────────────────────────

install_from_script() {
  info "Downloading Sigil bash script from GitHub..."
  TMP="$(mktemp)"
  if have curl; then
    curl -fsSL "${GITHUB_RAW}/bin/sigil" -o "$TMP" || die "Download failed."
  elif have wget; then
    wget -qO "$TMP" "${GITHUB_RAW}/bin/sigil" || die "Download failed."
  else
    die "Neither curl nor wget found. Install one and try again."
  fi
  chmod +x "$TMP"
  ${SUDO:-} mv "$TMP" "${INSTALL_DIR}/${BINARY_NAME}"
  ok "Installed bash script → ${INSTALL_DIR}/${BINARY_NAME}"
}

# ── Try release binary first, fall back to bash script ───────────────────────

INSTALLED_MODE=""

if [ -n "$RELEASE_URL" ]; then
  if install_from_release 2>/dev/null; then
    INSTALLED_MODE="rust"
  else
    warn "Pre-built binary not available for ${PLATFORM}/${ARCH_NORM}, falling back to bash script"
    install_from_script
    INSTALLED_MODE="bash"
  fi
else
  warn "No release found — installing bash script from main branch"
  install_from_script
  INSTALLED_MODE="bash"
fi

# ── Verify ────────────────────────────────────────────────────────────────────

if ! have sigil; then
  warn "${INSTALL_DIR} may not be in your PATH. Add it:"
  warn "  export PATH=\"\$PATH:${INSTALL_DIR}\""
fi

VERSION="$(sigil --version 2>/dev/null || echo 'unknown')"
ok "Sigil installed: ${VERSION}"

if [ "$INSTALLED_MODE" = "bash" ]; then
  info "Tip: for a faster native binary, build from source:"
  info "  git clone https://github.com/${REPO} && cd sigil/cli && cargo build --release"
fi

# ── Run setup ─────────────────────────────────────────────────────────────────

info "Running sigil install to set up shell aliases..."
if sigil install 2>/dev/null; then
  ok "Shell aliases installed. Restart your terminal or run: source ~/.bashrc"
else
  warn "Alias setup skipped — run 'sigil install' manually when ready"
fi

echo ""
ok "Done! Try: sigil scan ."
