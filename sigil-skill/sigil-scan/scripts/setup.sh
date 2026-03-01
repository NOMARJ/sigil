#!/usr/bin/env bash
# setup.sh — Install the Sigil CLI binary.
# Outputs JSON to stdout. Status messages to stderr.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=_lib.sh
source "$SCRIPT_DIR/_lib.sh"

REPO="NOMARJ/sigil"
BINARY_NAME="sigil"
INSTALL_DIR="$HOME/.local/bin"
export MIN_VERSION="1.0.5"

# ── Check if already installed ─────────────────────────────────────────────

check_existing() {
  local bin
  bin="$(find_sigil 2>/dev/null)" || true
  if [ -n "$bin" ]; then
    local version
    version="$("$bin" --version 2>/dev/null | head -1 || echo "unknown")"
    info "Sigil already installed: $version at $(command -v "$bin" 2>/dev/null || echo "$bin")"
    json_output "{\"installed\": true, \"version\": $(json_string "$version"), \"path\": $(json_string "$bin"), \"method\": \"existing\"}"
    exit 0
  fi
}

# ── Platform detection ─────────────────────────────────────────────────────

detect_platform() {
  OS="$(uname -s)"
  ARCH="$(uname -m)"

  case "$OS" in
    Linux)  PLATFORM="linux" ;;
    Darwin) PLATFORM="macos" ;;
    MINGW*|MSYS*|CYGWIN*) PLATFORM="windows" ;;
    *) die "Unsupported OS: $OS. Install manually from https://github.com/$REPO" ;;
  esac

  case "$ARCH" in
    x86_64)        ARCH_NORM="x86_64" ;;
    aarch64|arm64) ARCH_NORM="aarch64" ;;
    *) die "Unsupported architecture: $ARCH" ;;
  esac
}

# ── Download helpers ───────────────────────────────────────────────────────

download() {
  local url="$1" dest="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$dest" 2>/dev/null
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$dest" "$url" 2>/dev/null
  else
    die "Neither curl nor wget found. Install one and try again."
  fi
}

fetch_text() {
  local url="$1"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" 2>/dev/null
  elif command -v wget >/dev/null 2>&1; then
    wget -qO- "$url" 2>/dev/null
  else
    return 1
  fi
}

# ── Install from GitHub Release ────────────────────────────────────────────

install_from_release() {
  # Get latest release tag
  info "Checking for latest release..."
  local latest_tag
  latest_tag="$(fetch_text "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')" || true

  if [ -z "$latest_tag" ]; then
    warn "Could not determine latest release"
    return 1
  fi

  local asset_name="${BINARY_NAME}-${PLATFORM}-${ARCH_NORM}"
  local release_url="https://github.com/${REPO}/releases/download/${latest_tag}/${asset_name}"

  info "Downloading Sigil ${latest_tag} for ${PLATFORM}/${ARCH_NORM}..."
  local tmp
  tmp="$(mktemp)"

  if ! download "$release_url" "$tmp"; then
    rm -f "$tmp"
    warn "Download failed for ${asset_name}"
    return 1
  fi

  # Checksum verification
  local checksums_url="https://github.com/${REPO}/releases/download/${latest_tag}/SHA256SUMS.txt"
  local checksums_file
  checksums_file="$(mktemp)"

  if download "$checksums_url" "$checksums_file" 2>/dev/null; then
    local expected_hash actual_hash
    expected_hash="$(grep "$asset_name" "$checksums_file" 2>/dev/null | awk '{print $1}')"

    if [ -n "$expected_hash" ]; then
      if command -v sha256sum >/dev/null 2>&1; then
        actual_hash="$(sha256sum "$tmp" | awk '{print $1}')"
      elif command -v shasum >/dev/null 2>&1; then
        actual_hash="$(shasum -a 256 "$tmp" | awk '{print $1}')"
      fi

      if [ -n "$actual_hash" ] && [ "$actual_hash" != "$expected_hash" ]; then
        rm -f "$tmp" "$checksums_file"
        die "Checksum verification FAILED. The downloaded binary may have been tampered with."
      elif [ -n "$actual_hash" ]; then
        info "Checksum verified"
      fi
    fi
  fi
  rm -f "$checksums_file"

  # Make executable and sanity check
  chmod +x "$tmp"
  if ! "$tmp" --version >/dev/null 2>&1; then
    rm -f "$tmp"
    warn "Downloaded binary failed sanity check"
    return 1
  fi

  # Install
  mkdir -p "$INSTALL_DIR"
  mv "$tmp" "${INSTALL_DIR}/${BINARY_NAME}"

  local version
  version="$("${INSTALL_DIR}/${BINARY_NAME}" --version 2>/dev/null | head -1 || echo "$latest_tag")"
  info "Installed: ${INSTALL_DIR}/${BINARY_NAME} (${version})"

  echo "$version"
}

# ── Alternative install methods ────────────────────────────────────────────

install_via_homebrew() {
  if command -v brew >/dev/null 2>&1; then
    info "Attempting install via Homebrew..."
    if brew install nomarj/tap/sigil 2>/dev/null; then
      local version
      version="$(sigil --version 2>/dev/null | head -1 || echo "unknown")"
      echo "$version"
      return 0
    fi
  fi
  return 1
}

install_via_npm() {
  if command -v npm >/dev/null 2>&1; then
    info "Attempting install via npm..."
    if npm install -g @nomark/sigil 2>/dev/null; then
      local version
      version="$(sigil --version 2>/dev/null | head -1 || echo "unknown")"
      echo "$version"
      return 0
    fi
  fi
  return 1
}

install_via_cargo() {
  if command -v cargo >/dev/null 2>&1; then
    info "Attempting install via cargo..."
    if cargo install sigil-cli 2>/dev/null; then
      local version
      version="$(sigil --version 2>/dev/null | head -1 || echo "unknown")"
      echo "$version"
      return 0
    fi
  fi
  return 1
}

# ── Main ───────────────────────────────────────────────────────────────────

main() {
  check_existing

  detect_platform

  local version="" method=""

  # Try GitHub release first (fastest)
  if version="$(install_from_release 2>/dev/null)"; then
    method="github_release"
  elif version="$(install_via_homebrew 2>/dev/null)"; then
    method="homebrew"
  elif version="$(install_via_npm 2>/dev/null)"; then
    method="npm"
  elif version="$(install_via_cargo 2>/dev/null)"; then
    method="cargo"
  else
    die "Could not install Sigil. Install manually: brew install nomarj/tap/sigil, npm install -g @nomark/sigil, or cargo install sigil-cli"
  fi

  # Check PATH
  local bin_path
  bin_path="$(find_sigil 2>/dev/null)" || true
  if [ -z "$bin_path" ]; then
    warn "${INSTALL_DIR} may not be in your PATH. Add it:"
    warn "  export PATH=\"\$PATH:${INSTALL_DIR}\""
    bin_path="${INSTALL_DIR}/${BINARY_NAME}"
  fi

  json_output "{\"installed\": true, \"version\": $(json_string "$version"), \"path\": $(json_string "$bin_path"), \"method\": $(json_string "$method")}"
}

main "$@"
