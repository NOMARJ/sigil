#!/usr/bin/env bash
# audit-skills.sh — Scan all installed skills across agent directories.
# Requires the sigil CLI binary.
# Outputs JSON to stdout. Status messages to stderr.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/_lib.sh"

SIGIL="$(require_sigil)"
TIMEOUT_SECONDS=30

# ── Agent skill directories ───────────────────────────────────────────────

GLOBAL_SKILL_DIRS=(
  "$HOME/.agents/skills"              # Universal: Amp, Cline, Codex, Cursor, Gemini CLI, GitHub Copilot
  "$HOME/.claude/skills"              # Claude Code
  "$HOME/.cursor/skills"              # Cursor global
  "$HOME/.roo/skills"                 # Roo Code
  "$HOME/.config/opencode/skills"     # OpenCode
  "$HOME/.copilot/skills"             # GitHub Copilot
  "$HOME/.cline/skills"               # Cline
  "$HOME/.codex/skills"               # OpenAI Codex
  "$HOME/.continue/skills"            # Continue
  "$HOME/.windsurf/skills"            # Windsurf
  "$HOME/.aider/skills"               # Aider
)

LOCAL_SKILL_DIRS=(
  "./.claude/skills"
  "./.cursor/skills"
  "./.agents/skills"
  "./.skills"
)

# Map directory patterns to agent names
agent_for_dir() {
  local dir="$1"
  case "$dir" in
    */.agents/skills*)        echo "universal" ;;
    */.claude/skills*)        echo "claude-code" ;;
    */.cursor/skills*)        echo "cursor" ;;
    */.roo/skills*)           echo "roo-code" ;;
    */.config/opencode/*)     echo "opencode" ;;
    */.copilot/skills*)       echo "github-copilot" ;;
    */.cline/skills*)         echo "cline" ;;
    */.codex/skills*)         echo "codex" ;;
    */.continue/skills*)      echo "continue" ;;
    */.windsurf/skills*)      echo "windsurf" ;;
    */.aider/skills*)         echo "aider" ;;
    *)                        echo "unknown" ;;
  esac
}

# ── Scan a single skill ──────────────────────────────────────────────────

scan_skill() {
  local skill_dir="$1"
  local skill_name
  skill_name="$(basename "$skill_dir")"
  local agent
  agent="$(agent_for_dir "$skill_dir")"

  info "Scanning skill: $skill_name ($agent)"

  local raw_output exit_code=0
  if command -v timeout >/dev/null 2>&1; then
    raw_output="$(timeout "$TIMEOUT_SECONDS" "$SIGIL" --format json scan "$skill_dir" 2>/dev/null)" || exit_code=$?
  elif command -v gtimeout >/dev/null 2>&1; then
    raw_output="$(gtimeout "$TIMEOUT_SECONDS" "$SIGIL" --format json scan "$skill_dir" 2>/dev/null)" || exit_code=$?
  else
    raw_output="$("$SIGIL" --format json scan "$skill_dir" 2>/dev/null)" || exit_code=$?
  fi

  # Handle timeout (exit code 124)
  if [ "$exit_code" -eq 124 ]; then
    echo "{\"skill\": $(json_string "$skill_name"), \"path\": $(json_string "$skill_dir"), \"agent\": $(json_string "$agent"), \"error\": \"Scan timed out after ${TIMEOUT_SECONDS}s\"}"
    return
  fi

  if [ -z "$raw_output" ]; then
    echo "{\"skill\": $(json_string "$skill_name"), \"path\": $(json_string "$skill_dir"), \"agent\": $(json_string "$agent"), \"error\": \"Scan produced no output\"}"
    return
  fi

  # Parse the merged JSON to extract key fields
  local merged
  merged="$(merge_scan_json "$raw_output" "$skill_dir")"

  if command -v jq >/dev/null 2>&1; then
    echo "$merged" | jq --arg name "$skill_name" --arg agent "$agent" '{
      skill: $name,
      path: .target,
      agent: $agent,
      verdict: .verdict,
      score: .score,
      findings_count: (.findings | length),
      critical_findings: ([.findings[] | select(.severity == "Critical")] | length),
      top_findings: [.findings | sort_by(
        if .severity == "Critical" then 0
        elif .severity == "High" then 1
        elif .severity == "Medium" then 2
        else 3 end
      ) | limit(3; .[])]
    }' 2>/dev/null
  elif command -v python3 >/dev/null 2>&1; then
    echo "$merged" | python3 -c "
import json, sys
data = json.load(sys.stdin)
findings = data.get('findings', [])
severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.get('severity', 'Low'), 3))
result = {
    'skill': '$skill_name',
    'path': data.get('target', '$skill_dir'),
    'agent': '$agent',
    'verdict': data.get('verdict', 'UNKNOWN'),
    'score': data.get('score', 0),
    'findings_count': len(findings),
    'critical_findings': sum(1 for f in findings if f.get('severity') == 'Critical'),
    'top_findings': sorted_findings[:3]
}
print(json.dumps(result))
" 2>/dev/null
  else
    echo "{\"skill\": $(json_string "$skill_name"), \"path\": $(json_string "$skill_dir"), \"agent\": $(json_string "$agent"), \"verdict\": \"UNKNOWN\", \"score\": 0, \"error\": \"No jq or python3 available for JSON parsing\"}"
  fi
}

# ── Main ───────────────────────────────────────────────────────────────────

main() {
  info "Auditing installed skills across all agent directories..."

  local results=()
  local dirs_scanned=0
  local skills_scanned=0
  local low=0 medium=0 high=0 critical=0

  # Combine global and local directories
  local all_dirs=("${GLOBAL_SKILL_DIRS[@]}" "${LOCAL_SKILL_DIRS[@]}")

  for skill_parent in "${all_dirs[@]}"; do
    [ -d "$skill_parent" ] || continue
    dirs_scanned=$((dirs_scanned + 1))

    # Each subdirectory is a skill
    for skill_dir in "$skill_parent"/*/; do
      [ -d "$skill_dir" ] || continue
      skills_scanned=$((skills_scanned + 1))

      local result
      result="$(scan_skill "${skill_dir%/}")"
      results+=("$result")

      # Count verdicts
      case "$result" in
        *'"LOW RISK"'*|*'"LOW_RISK"'*)       low=$((low + 1)) ;;
        *'"MEDIUM RISK"'*|*'"MEDIUM_RISK"'*) medium=$((medium + 1)) ;;
        *'"HIGH RISK"'*|*'"HIGH_RISK"'*)     high=$((high + 1)) ;;
        *'"CRITICAL RISK"'*|*'"CRITICAL"'*)  critical=$((critical + 1)) ;;
      esac
    done
  done

  # Build results JSON array
  local results_json="["
  local first=true
  for r in "${results[@]}"; do
    if [ "$first" = true ]; then
      first=false
    else
      results_json="$results_json, "
    fi
    results_json="$results_json$r"
  done
  results_json="$results_json]"

  json_output "{
  \"target\": \"installed_skills\",
  \"agent_dirs_scanned\": $dirs_scanned,
  \"skills_scanned\": $skills_scanned,
  \"results\": $results_json,
  \"summary\": {
    \"low_risk\": $low,
    \"medium_risk\": $medium,
    \"high_risk\": $high,
    \"critical_risk\": $critical
  }
}"

  info "Skills audit complete: $skills_scanned skill(s) across $dirs_scanned director(ies)"
}

main "$@"
