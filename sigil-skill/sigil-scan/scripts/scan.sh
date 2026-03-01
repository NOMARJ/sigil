#!/usr/bin/env bash
# scan.sh — Core scan wrapper for the sigil-scan skill.
# Accepts a path, URL, package name, or GitHub shorthand (owner/repo).
# Outputs unified JSON to stdout. Status messages to stderr.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=_lib.sh
source "$SCRIPT_DIR/_lib.sh"

TARGET="${1:?$(die "Usage: scan.sh <path|url|package|owner/repo>")}"

SIGIL="$(require_sigil)"

# ── Scan functions ─────────────────────────────────────────────────────────

scan_path() {
  local path="$1"
  info "Scanning path: $path"

  local raw_output exit_code=0
  raw_output="$("$SIGIL" --format json scan "$path" 2>/dev/null)" || exit_code=$?

  if [ -z "$raw_output" ]; then
    die "Scan produced no output for: $path"
  fi

  merge_scan_json "$raw_output" "$path"
  return "$exit_code"
}

scan_git_url() {
  local url="$1"
  info "Cloning and scanning: $url"

  local raw_output exit_code=0
  raw_output="$("$SIGIL" --format json clone "$url" 2>/dev/null)" || exit_code=$?

  if [ -z "$raw_output" ]; then
    die "Clone/scan produced no output for: $url"
  fi

  merge_scan_json "$raw_output" "$url"
  return "$exit_code"
}

scan_npm_package() {
  local pkg="$1"
  info "Scanning npm package: $pkg"

  local raw_output exit_code=0
  raw_output="$("$SIGIL" --format json npm "$pkg" 2>/dev/null)" || exit_code=$?

  if [ -z "$raw_output" ]; then
    die "npm scan produced no output for: $pkg"
  fi

  merge_scan_json "$raw_output" "$pkg"
  return "$exit_code"
}

scan_pip_package() {
  local pkg="$1"
  info "Scanning pip package: $pkg"

  local raw_output exit_code=0
  raw_output="$("$SIGIL" --format json pip "$pkg" 2>/dev/null)" || exit_code=$?

  if [ -z "$raw_output" ]; then
    die "pip scan produced no output for: $pkg"
  fi

  merge_scan_json "$raw_output" "$pkg"
  return "$exit_code"
}

scan_url() {
  local url="$1"
  info "Fetching and scanning URL: $url"

  local raw_output exit_code=0
  raw_output="$("$SIGIL" --format json fetch "$url" 2>/dev/null)" || exit_code=$?

  if [ -z "$raw_output" ]; then
    die "URL scan produced no output for: $url"
  fi

  merge_scan_json "$raw_output" "$url"
  return "$exit_code"
}

# ── Input type detection ──────────────────────────────────────────────────

detect_and_scan() {
  local target="$1"

  # Local path
  if [ -e "$target" ]; then
    scan_path "$target"
    return $?
  fi

  # Full URL
  if echo "$target" | grep -qE '^https?://'; then
    if echo "$target" | grep -qE '(github\.com|gitlab\.com|bitbucket\.org|codeberg\.org)'; then
      scan_git_url "$target"
    else
      scan_url "$target"
    fi
    return $?
  fi

  # GitHub shorthand: owner/repo (no slashes beyond the one)
  if echo "$target" | grep -qE '^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$'; then
    scan_git_url "https://github.com/${target}.git"
    return $?
  fi

  # npm scoped package: @scope/name
  if echo "$target" | grep -qE '^@[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+'; then
    scan_npm_package "$target"
    return $?
  fi

  # Explicit package manager prefix
  if echo "$target" | grep -qE '^npm:'; then
    scan_npm_package "${target#npm:}"
    return $?
  fi
  if echo "$target" | grep -qE '^pip:'; then
    scan_pip_package "${target#pip:}"
    return $?
  fi

  # Heuristic: try pip first (more common in AI agent ecosystem), fallback to npm
  info "Attempting to resolve package: $target"
  if scan_pip_package "$target" 2>/dev/null; then
    return $?
  fi

  info "pip scan failed, trying npm..."
  scan_npm_package "$target"
  return $?
}

# ── Main ───────────────────────────────────────────────────────────────────

detect_and_scan "$TARGET"
