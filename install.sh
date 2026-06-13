#!/usr/bin/env sh
# Sigil installer
# Usage: curl -sSL https://sigilsec.ai/install.sh | sh
#    or: curl -sSL https://raw.githubusercontent.com/NOMARJ/sigil/main/install.sh | sh

set -e

REPO="NOMARJ/sigil"
BINARY_NAME="sigil"
INSTALL_DIR="/usr/local/bin"
GITHUB_RAW="https://raw.githubusercontent.com/${REPO}/main"
SKIP_VERIFY=false

# ── Argument parsing ────────────────────────────────────────────────────────

for arg in "$@"; do
  case "$arg" in
    --skip-verify) SKIP_VERIFY=true ;;
  esac
done

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
  x86_64)          ARCH_NORM="x64" ;;
  aarch64|arm64)   ARCH_NORM="arm64" ;;
  *)               die "Unsupported architecture: $ARCH" ;;
esac

case "${PLATFORM}/${ARCH_NORM}" in
  macos/arm64) ASSET_NAME="${BINARY_NAME}-macos-arm64.tar.gz" ;;
  macos/x64)   ASSET_NAME="${BINARY_NAME}-macos-x64.tar.gz" ;;
  linux/x64)   ASSET_NAME="${BINARY_NAME}-linux-x64.tar.gz" ;;
  linux/arm64) ASSET_NAME="${BINARY_NAME}-linux-arm64.tar.gz" ;;
  *)           die "Unsupported release target: ${PLATFORM}/${ARCH_NORM}" ;;
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
    RELEASE_URL="https://github.com/${REPO}/releases/download/${LATEST_TAG}/${ASSET_NAME}"
  fi
fi

install_from_release() {
  info "Downloading Sigil ${LATEST_TAG} for ${PLATFORM}/${ARCH_NORM}..."
  TMP_DIR="$(mktemp -d)"
  TMP="${TMP_DIR}/${ASSET_NAME}"
  if have curl; then
    curl -fsSL "$RELEASE_URL" -o "$TMP" || return 1
  else
    wget -qO "$TMP" "$RELEASE_URL" || return 1
  fi

  # ── Checksum verification ────────────────────────────────────────────────
  RELEASE_BASE="https://github.com/${REPO}/releases/download/${LATEST_TAG}"
  CHECKSUMS_URL="${RELEASE_BASE}/SHA256SUMS.txt"
  if [ "$SKIP_VERIFY" != "true" ]; then
    # Download checksum file
    CHECKSUMS_FILE="${TMP_DIR}/sigil-SHA256SUMS.txt"
    if have curl; then
      CHECKSUM_DL=$(curl -fsSL "$CHECKSUMS_URL" -o "$CHECKSUMS_FILE" 2>/dev/null && echo "ok" || echo "fail")
    else
      CHECKSUM_DL=$(wget -qO "$CHECKSUMS_FILE" "$CHECKSUMS_URL" 2>/dev/null && echo "ok" || echo "fail")
    fi

    if [ "$CHECKSUM_DL" != "ok" ]; then
      rm -rf "$TMP_DIR"
      die "Could not download checksums file"
    else
      EXPECTED_HASH=$(grep "$ASSET_NAME" "$CHECKSUMS_FILE" | awk '{print $1}')
      if [ -z "$EXPECTED_HASH" ]; then
        rm -f "$CHECKSUMS_FILE"
        rm -rf "$TMP_DIR"
        die "No checksum found for $ASSET_NAME"
      else
        ACTUAL_HASH=""
        if command -v sha256sum >/dev/null 2>&1; then
          ACTUAL_HASH=$(sha256sum "$TMP" | awk '{print $1}')
        elif command -v shasum >/dev/null 2>&1; then
          ACTUAL_HASH=$(shasum -a 256 "$TMP" | awk '{print $1}')
        else
          warn "Neither sha256sum nor shasum found — skipping verification"
        fi

        if [ -n "$ACTUAL_HASH" ] && [ "$ACTUAL_HASH" != "$EXPECTED_HASH" ]; then
          rm -f "$TMP" "$CHECKSUMS_FILE"
          die "Checksum verification FAILED!
  Expected: $EXPECTED_HASH
  Got:      $ACTUAL_HASH
  The downloaded binary may have been tampered with."
        elif [ -n "$ACTUAL_HASH" ]; then
          ok "Checksum verified"
        fi
      fi
      rm -f "$CHECKSUMS_FILE"
    fi
  else
    warn "Checksum verification skipped (--skip-verify)"
  fi

  tar -xzf "$TMP" -C "$TMP_DIR" sigil || {
    rm -rf "$TMP_DIR"
    return 1
  }
  chmod +x "${TMP_DIR}/sigil"
  # Quick sanity check — should print a version string
  if ! "${TMP_DIR}/sigil" --version >/dev/null 2>&1; then
    rm -rf "$TMP_DIR"
    return 1
  fi
  ${SUDO:-} mv "${TMP_DIR}/sigil" "${INSTALL_DIR}/${BINARY_NAME}"
  rm -rf "$TMP_DIR"
  ok "Installed Rust binary → ${INSTALL_DIR}/${BINARY_NAME}"
  return 0
}

# ── Install native release binary ────────────────────────────────────────────

INSTALLED_MODE=""

if [ -n "$RELEASE_URL" ]; then
  if install_from_release 2>/dev/null; then
    INSTALLED_MODE="rust"
  else
    die "Pre-built binary not available for ${PLATFORM}/${ARCH_NORM}. Install from source: cargo install sigil-cli"
  fi
else
  die "No GitHub release found. Install from source: cargo install sigil-cli"
fi

# ── Verify ────────────────────────────────────────────────────────────────────

if ! have sigil; then
  warn "${INSTALL_DIR} may not be in your PATH. Add it:"
  warn "  export PATH=\"\$PATH:${INSTALL_DIR}\""
fi

VERSION="$(sigil --version 2>/dev/null || echo 'unknown')"
ok "Sigil installed: ${VERSION}"

# ── Run setup ─────────────────────────────────────────────────────────────────

info "Running sigil install to set up shell aliases..."
if sigil install 2>/dev/null; then
  ok "Shell aliases installed. Restart your terminal or run: source ~/.bashrc"
else
  warn "Alias setup skipped — run 'sigil install' manually when ready"
fi

echo ""
ok "Done! Try: sigil scan ."
