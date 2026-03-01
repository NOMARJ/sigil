#!/usr/bin/env bash
# _lib.sh — Shared helper functions for sigil-scan skill scripts.
# Source this file: source "$(dirname "$0")/_lib.sh"

set -euo pipefail

# ── Output helpers ─────────────────────────────────────────────────────────
# All data goes to stdout (JSON). All status/progress goes to stderr.

json_output() { printf '%s\n' "$1"; }
json_error()  { printf '{"error": true, "message": %s}\n' "$(json_string "$1")"; }
info()        { printf '[sigil-scan] %s\n' "$*" >&2; }
warn()        { printf '[sigil-scan] WARNING: %s\n' "$*" >&2; }

die() {
  json_error "$1"
  exit 1
}

# ── JSON helpers ───────────────────────────────────────────────────────────

# Escape a string for safe JSON embedding.
json_string() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\t'/\\t}"
  printf '"%s"' "$s"
}

# ── Binary detection ──────────────────────────────────────────────────────

# Locate the sigil binary. Returns the path or empty string.
find_sigil() {
  local bin=""
  if command -v sigil >/dev/null 2>&1; then
    bin="sigil"
  elif [ -x "$HOME/.local/bin/sigil" ]; then
    bin="$HOME/.local/bin/sigil"
  elif [ -x "/usr/local/bin/sigil" ]; then
    bin="/usr/local/bin/sigil"
  fi

  # Verify it's the Rust binary (supports --format json), not the bash wrapper
  if [ -n "$bin" ]; then
    if "$bin" --format json scan --help >/dev/null 2>&1 || "$bin" --version 2>&1 | grep -q "sigil-cli\|sigil [0-9]"; then
      echo "$bin"
      return 0
    fi
  fi

  echo ""
  return 1
}

# Require the sigil binary or die with a helpful JSON error.
require_sigil() {
  local bin
  bin="$(find_sigil 2>/dev/null)" || true
  if [ -z "$bin" ]; then
    die "Sigil CLI not found. Run: bash $(cd "$(dirname "$0")" && pwd)/setup.sh"
  fi
  echo "$bin"
}

# ── JSON merging ──────────────────────────────────────────────────────────
# The Rust CLI outputs 3 separate JSON objects when using --format json:
#   1. Summary: {files_scanned, findings_count, score, verdict, duration_ms}
#   2. Findings array: [{phase, rule, severity, file, line, snippet, weight}]
#   3. Verdict: {verdict: "..."}
# This function merges them into a single envelope and adds a target field.

merge_scan_json() {
  local raw_output="$1"
  local target="$2"

  if command -v jq >/dev/null 2>&1; then
    echo "$raw_output" | jq -s --arg target "$target" '
      (.[0] // {}) + {
        findings: (.[1] // []),
        target: $target,
        phases: (
          (.[1] // []) | group_by(.phase) | map({
            key: .[0].phase,
            value: {
              findings: length,
              severity: (map(.severity) | sort_by(
                if . == "Critical" then 0
                elif . == "High" then 1
                elif . == "Medium" then 2
                else 3 end
              ) | first // "clean")
            }
          }) | from_entries
        )
      }
    ' 2>/dev/null
  elif command -v python3 >/dev/null 2>&1; then
    echo "$raw_output" | python3 -c "
import json, sys

data = sys.stdin.read().strip()
parts = []
decoder = json.JSONDecoder()
idx = 0
while idx < len(data):
    while idx < len(data) and data[idx] in ' \n\r\t':
        idx += 1
    if idx >= len(data):
        break
    obj, end = decoder.raw_decode(data, idx)
    parts.append(obj)
    idx = end

result = parts[0] if parts else {}
findings = parts[1] if len(parts) > 1 and isinstance(parts[1], list) else []
result['findings'] = findings
result['target'] = '$target'

severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
phases = {}
for f in findings:
    p = f.get('phase', 'Unknown')
    if p not in phases:
        phases[p] = {'findings': 0, 'severity': 'clean'}
    phases[p]['findings'] += 1
    f_sev = f.get('severity', 'Low')
    cur_sev = phases[p]['severity']
    if cur_sev == 'clean' or severity_order.get(f_sev, 3) < severity_order.get(cur_sev, 3):
        phases[p]['severity'] = f_sev.lower()
result['phases'] = phases

print(json.dumps(result, indent=2))
" 2>/dev/null
  else
    # No jq or python3 — pass raw output through
    echo "$raw_output"
  fi
}
