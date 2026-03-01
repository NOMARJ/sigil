#!/usr/bin/env bash
# audit-env.sh — Scan local environment for exposed credentials.
# CLI-independent: uses shell utilities, not the sigil binary.
# Outputs JSON to stdout. Status messages to stderr.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/_lib.sh"

FINDINGS=()
FILES_CHECKED=0

# ── Helpers ────────────────────────────────────────────────────────────────

add_finding() {
  local type="$1" file="$2" severity="$3" description="$4" line="${5:-}" key="${6:-}" perms="${7:-}" expected="${8:-}"

  local json="{\"type\": $(json_string "$type"), \"file\": $(json_string "$file"), \"severity\": $(json_string "$severity"), \"description\": $(json_string "$description")"

  [ -n "$line" ]     && json="$json, \"line\": $line"
  [ -n "$key" ]      && json="$json, \"key\": $(json_string "$key")"
  [ -n "$perms" ]    && json="$json, \"permissions\": $(json_string "$perms")"
  [ -n "$expected" ] && json="$json, \"expected\": $(json_string "$expected")"

  json="$json}"
  FINDINGS+=("$json")
}

get_perms() {
  if stat -f '%Lp' "$1" 2>/dev/null; then
    return
  fi
  stat -c '%a' "$1" 2>/dev/null || echo "unknown"
}

# ── Scan .env files in CWD ────────────────────────────────────────────────

scan_env_files() {
  local env_patterns=(".env" ".env.local" ".env.production" ".env.staging" ".env.development")
  local sensitive_patterns=(
    "AWS_ACCESS_KEY_ID"
    "AWS_SECRET_ACCESS_KEY"
    "SECRET_KEY"
    "API_KEY"
    "API_SECRET"
    "PRIVATE_KEY"
    "DATABASE_URL"
    "DB_PASSWORD"
    "OPENAI_API_KEY"
    "ANTHROPIC_API_KEY"
    "STRIPE_SECRET"
    "GITHUB_TOKEN"
    "GH_TOKEN"
    "SLACK_TOKEN"
    "DISCORD_TOKEN"
    "SENDGRID_API_KEY"
    "TWILIO_AUTH_TOKEN"
    "PASSWORD"
    "PASSWD"
    "_SECRET"
    "_TOKEN"
    "AUTH_TOKEN"
    "BEARER_TOKEN"
  )

  for env_file in "${env_patterns[@]}"; do
    local path="${PWD}/${env_file}"
    [ -f "$path" ] || continue
    FILES_CHECKED=$((FILES_CHECKED + 1))

    for pattern in "${sensitive_patterns[@]}"; do
      local line_num
      line_num=$(grep -n "^${pattern}=" "$path" 2>/dev/null | head -1 | cut -d: -f1) || true
      if [ -n "$line_num" ]; then
        # Check if the value is non-empty and not a placeholder
        local value
        value=$(grep "^${pattern}=" "$path" 2>/dev/null | head -1 | cut -d= -f2-) || true
        if [ -n "$value" ] && ! echo "$value" | grep -qiE '^(your_|changeme|xxx|placeholder|TODO)'; then
          add_finding "exposed_credential" "$path" "critical" \
            ".env file contains ${pattern}" "$line_num" "$pattern"
        fi
      fi
    done
  done
}

# ── Check credential file permissions ─────────────────────────────────────

check_credential_files() {
  local cred_files=(
    "$HOME/.aws/credentials:600:critical:AWS credentials file"
    "$HOME/.aws/config:600:low:AWS config file"
    "$HOME/.ssh/id_rsa:600:critical:SSH RSA private key"
    "$HOME/.ssh/id_ed25519:600:critical:SSH Ed25519 private key"
    "$HOME/.ssh/id_ecdsa:600:critical:SSH ECDSA private key"
    "$HOME/.netrc:600:high:Netrc authentication file"
    "$HOME/.npmrc:600:medium:npm config (may contain auth tokens)"
    "$HOME/.pypirc:600:medium:PyPI config (may contain passwords)"
    "$HOME/.kube/config:600:high:Kubernetes config"
    "$HOME/.docker/config.json:600:medium:Docker config (may contain auth)"
  )

  for entry in "${cred_files[@]}"; do
    IFS=: read -r filepath expected_perms severity desc <<< "$entry"
    [ -f "$filepath" ] || continue
    FILES_CHECKED=$((FILES_CHECKED + 1))

    local actual_perms
    actual_perms="$(get_perms "$filepath")"

    if [ "$actual_perms" != "unknown" ] && [ "$actual_perms" != "$expected_perms" ]; then
      # Check if it's world-readable (last digit > 0)
      local world_bits="${actual_perms: -1}"
      if [ "$world_bits" != "0" ]; then
        add_finding "insecure_permissions" "$filepath" "$severity" \
          "$desc is world-readable" "" "" "$actual_perms" "$expected_perms"
      fi
    fi
  done

  # Check for auth tokens in npmrc
  if [ -f "$HOME/.npmrc" ]; then
    if grep -q "_authToken" "$HOME/.npmrc" 2>/dev/null; then
      local line_num
      line_num=$(grep -n "_authToken" "$HOME/.npmrc" 2>/dev/null | head -1 | cut -d: -f1) || true
      add_finding "exposed_credential" "$HOME/.npmrc" "high" \
        "npm config contains authentication token" "$line_num" "_authToken"
    fi
  fi

  # Check for password in pypirc
  if [ -f "$HOME/.pypirc" ]; then
    if grep -q "password" "$HOME/.pypirc" 2>/dev/null; then
      local line_num
      line_num=$(grep -n "password" "$HOME/.pypirc" 2>/dev/null | head -1 | cut -d: -f1) || true
      add_finding "exposed_credential" "$HOME/.pypirc" "high" \
        "PyPI config contains password" "$line_num" "password"
    fi
  fi
}

# ── Check shell history for leaked secrets ────────────────────────────────

check_shell_history() {
  local history_files=(
    "$HOME/.bash_history"
    "$HOME/.zsh_history"
    "$HOME/.local/share/fish/fish_history"
  )

  local secret_patterns=(
    'AKIA[0-9A-Z]\{16\}:AWS access key ID in shell history'
    'ghp_[A-Za-z0-9]\{36\}:GitHub personal access token in shell history'
    'gho_[A-Za-z0-9]\{36\}:GitHub OAuth token in shell history'
    'sk-[A-Za-z0-9]\{20,\}:API secret key in shell history'
    'xoxb-[0-9]\{10,\}:Slack bot token in shell history'
    'xoxp-[0-9]\{10,\}:Slack user token in shell history'
  )

  for hist_file in "${history_files[@]}"; do
    [ -f "$hist_file" ] || continue
    FILES_CHECKED=$((FILES_CHECKED + 1))

    for pattern_entry in "${secret_patterns[@]}"; do
      local pattern="${pattern_entry%%:*}"
      local desc="${pattern_entry#*:}"

      local match_count
      match_count=$(grep -cE "$pattern" "$hist_file" 2>/dev/null) || true
      if [ "${match_count:-0}" -gt 0 ]; then
        add_finding "history_leak" "$hist_file" "high" \
          "$desc ($match_count occurrence(s))"
      fi
    done
  done
}

# ── Check agent-accessible directories ────────────────────────────────────

check_agent_accessible() {
  # Check if sensitive files are in directories agents can access
  local agent_dirs=(
    "$HOME/.agents"
    "$HOME/.claude"
    "$HOME/.cursor"
    "$HOME/.codex"
  )

  for dir in "${agent_dirs[@]}"; do
    [ -d "$dir" ] || continue

    # Check for .env files in agent directories
    while IFS= read -r -d '' env_file; do
      FILES_CHECKED=$((FILES_CHECKED + 1))
      if grep -qE '(API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE_KEY)=' "$env_file" 2>/dev/null; then
        add_finding "agent_accessible_secret" "$env_file" "high" \
          "Credential file found in agent-accessible directory"
      fi
    done < <(find "$dir" -name ".env*" -type f -print0 2>/dev/null)
  done
}

# ── Main ───────────────────────────────────────────────────────────────────

main() {
  info "Auditing local environment for exposed credentials..."

  scan_env_files
  check_credential_files
  check_shell_history
  check_agent_accessible

  # Count by severity
  local critical=0 high=0 medium=0 low=0
  for f in "${FINDINGS[@]}"; do
    case "$f" in
      *'"critical"'*) critical=$((critical + 1)) ;;
      *'"high"'*)     high=$((high + 1)) ;;
      *'"medium"'*)   medium=$((medium + 1)) ;;
      *'"low"'*)      low=$((low + 1)) ;;
    esac
  done

  # Build findings JSON array
  local findings_json="["
  local first=true
  for f in "${FINDINGS[@]}"; do
    if [ "$first" = true ]; then
      first=false
    else
      findings_json="$findings_json, "
    fi
    findings_json="$findings_json$f"
  done
  findings_json="$findings_json]"

  json_output "{
  \"target\": \"environment\",
  \"findings\": $findings_json,
  \"summary\": {
    \"files_checked\": $FILES_CHECKED,
    \"findings_count\": ${#FINDINGS[@]},
    \"critical\": $critical,
    \"high\": $high,
    \"medium\": $medium,
    \"low\": $low
  }
}"

  info "Environment audit complete: ${#FINDINGS[@]} finding(s) across $FILES_CHECKED file(s)"
}

main "$@"
