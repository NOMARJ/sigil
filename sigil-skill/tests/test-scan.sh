#!/usr/bin/env bash
# test-scan.sh — Integration tests for scan.sh
# Requires the sigil CLI binary to be installed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCAN_SCRIPT="$SCRIPT_DIR/../sigil-scan/scripts/scan.sh"
FIXTURES_DIR="$SCRIPT_DIR/fixtures"

PASS=0
FAIL=0

# ── Test helpers ──────────────────────────────────────────────────────────

pass() { PASS=$((PASS + 1)); printf '\033[32m  PASS\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '\033[31m  FAIL\033[0m %s: %s\n' "$1" "$2"; }

assert_json_field() {
  local json="$1" field="$2" expected="$3" test_name="$4"
  local actual

  if command -v jq >/dev/null 2>&1; then
    actual="$(echo "$json" | jq -r "$field" 2>/dev/null)" || true
  elif command -v python3 >/dev/null 2>&1; then
    actual="$(echo "$json" | python3 -c "
import json, sys
data = json.load(sys.stdin)
keys = '$field'.strip('.').split('.')
val = data
for k in keys:
    if isinstance(val, dict):
        val = val.get(k)
    else:
        val = None
        break
print(val if val is not None else 'null')
" 2>/dev/null)" || true
  else
    fail "$test_name" "No jq or python3 available"
    return
  fi

  if [ "$actual" = "$expected" ]; then
    pass "$test_name"
  else
    fail "$test_name" "expected $field=$expected, got $actual"
  fi
}

assert_json_valid() {
  local json="$1" test_name="$2"

  if command -v jq >/dev/null 2>&1; then
    if echo "$json" | jq . >/dev/null 2>&1; then
      pass "$test_name"
    else
      fail "$test_name" "Invalid JSON output"
    fi
  elif command -v python3 >/dev/null 2>&1; then
    if echo "$json" | python3 -c "import json, sys; json.load(sys.stdin)" 2>/dev/null; then
      pass "$test_name"
    else
      fail "$test_name" "Invalid JSON output"
    fi
  else
    fail "$test_name" "No jq or python3 available"
  fi
}

assert_exit_code() {
  local actual="$1" expected="$2" test_name="$3"
  if [ "$actual" -eq "$expected" ]; then
    pass "$test_name"
  else
    fail "$test_name" "expected exit code $expected, got $actual"
  fi
}

# ── Check prerequisites ──────────────────────────────────────────────────

echo "=== Sigil Scan Integration Tests ==="
echo ""

if ! command -v sigil >/dev/null 2>&1 && \
   ! [ -x "$HOME/.local/bin/sigil" ] && \
   ! [ -x "/usr/local/bin/sigil" ]; then
  echo "SKIP: sigil binary not found. Install it first: bash ../sigil-scan/scripts/setup.sh"
  exit 0
fi

if ! command -v jq >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
  echo "SKIP: jq or python3 required for JSON validation"
  exit 0
fi

# ── Test: Clean project scan ─────────────────────────────────────────────

echo "--- Clean project ---"
OUTPUT=""
EXIT_CODE=0
OUTPUT="$(bash "$SCAN_SCRIPT" "$FIXTURES_DIR/clean-project" 2>/dev/null)" || EXIT_CODE=$?

assert_json_valid "$OUTPUT" "clean-project: produces valid JSON"
assert_json_field "$OUTPUT" ".verdict" "CLEAN" "clean-project: verdict is CLEAN"
assert_exit_code "$EXIT_CODE" 0 "clean-project: exit code 0"

# ── Test: Malicious project scan ─────────────────────────────────────────

echo "--- Malicious project ---"
OUTPUT=""
EXIT_CODE=0
OUTPUT="$(bash "$SCAN_SCRIPT" "$FIXTURES_DIR/malicious-project" 2>/dev/null)" || EXIT_CODE=$?

assert_json_valid "$OUTPUT" "malicious-project: produces valid JSON"

# Should be HIGH or CRITICAL risk
VERDICT=""
if command -v jq >/dev/null 2>&1; then
  VERDICT="$(echo "$OUTPUT" | jq -r '.verdict' 2>/dev/null)"
else
  VERDICT="$(echo "$OUTPUT" | python3 -c "import json,sys; print(json.load(sys.stdin).get('verdict',''))" 2>/dev/null)"
fi

if [ "$VERDICT" = "HIGH RISK" ] || [ "$VERDICT" = "CRITICAL" ]; then
  pass "malicious-project: verdict is HIGH RISK or CRITICAL ($VERDICT)"
else
  fail "malicious-project: verdict is HIGH RISK or CRITICAL" "got $VERDICT"
fi

# Should have findings
FINDINGS_COUNT=""
if command -v jq >/dev/null 2>&1; then
  FINDINGS_COUNT="$(echo "$OUTPUT" | jq '.findings | length' 2>/dev/null)"
else
  FINDINGS_COUNT="$(echo "$OUTPUT" | python3 -c "import json,sys; print(len(json.load(sys.stdin).get('findings',[])))" 2>/dev/null)"
fi

if [ "${FINDINGS_COUNT:-0}" -gt 0 ]; then
  pass "malicious-project: has findings ($FINDINGS_COUNT)"
else
  fail "malicious-project: has findings" "got 0"
fi

# Exit code should be non-zero
if [ "$EXIT_CODE" -ne 0 ]; then
  pass "malicious-project: exit code non-zero ($EXIT_CODE)"
else
  fail "malicious-project: exit code non-zero" "got 0"
fi

# ── Test: Medium risk project scan ───────────────────────────────────────

echo "--- Medium risk project ---"
OUTPUT=""
EXIT_CODE=0
OUTPUT="$(bash "$SCAN_SCRIPT" "$FIXTURES_DIR/medium-risk-project" 2>/dev/null)" || EXIT_CODE=$?

assert_json_valid "$OUTPUT" "medium-risk-project: produces valid JSON"

# Should have some findings
FINDINGS_COUNT=""
if command -v jq >/dev/null 2>&1; then
  FINDINGS_COUNT="$(echo "$OUTPUT" | jq '.findings | length' 2>/dev/null)"
else
  FINDINGS_COUNT="$(echo "$OUTPUT" | python3 -c "import json,sys; print(len(json.load(sys.stdin).get('findings',[])))" 2>/dev/null)"
fi

if [ "${FINDINGS_COUNT:-0}" -gt 0 ]; then
  pass "medium-risk-project: has findings ($FINDINGS_COUNT)"
else
  fail "medium-risk-project: has findings" "got 0"
fi

# ── Test: JSON structure ─────────────────────────────────────────────────

echo "--- JSON structure validation ---"
OUTPUT="$(bash "$SCAN_SCRIPT" "$FIXTURES_DIR/clean-project" 2>/dev/null)" || true

# Check required fields exist
for field in verdict score target files_scanned findings; do
  HAS_FIELD=""
  if command -v jq >/dev/null 2>&1; then
    HAS_FIELD="$(echo "$OUTPUT" | jq "has(\"$field\")" 2>/dev/null)"
  else
    HAS_FIELD="$(echo "$OUTPUT" | python3 -c "import json,sys; print('true' if '$field' in json.load(sys.stdin) else 'false')" 2>/dev/null)"
  fi

  if [ "$HAS_FIELD" = "true" ]; then
    pass "json-structure: has '$field' field"
  else
    fail "json-structure: has '$field' field" "missing"
  fi
done

# ── Test: Non-existent path ──────────────────────────────────────────────

echo "--- Error handling ---"
OUTPUT=""
EXIT_CODE=0
OUTPUT="$(bash "$SCAN_SCRIPT" "/nonexistent/path/xyz" 2>/dev/null)" || EXIT_CODE=$?

if [ "$EXIT_CODE" -ne 0 ]; then
  pass "error-handling: non-existent path returns non-zero"
else
  fail "error-handling: non-existent path returns non-zero" "got 0"
fi

# ── Summary ──────────────────────────────────────────────────────────────

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
