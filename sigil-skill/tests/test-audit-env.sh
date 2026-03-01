#!/usr/bin/env bash
# test-audit-env.sh — Integration tests for audit-env.sh
# Creates temporary credential files and validates detection.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AUDIT_SCRIPT="$SCRIPT_DIR/../sigil-scan/scripts/audit-env.sh"

PASS=0
FAIL=0
TMPDIR=""

# ── Test helpers ──────────────────────────────────────────────────────────

pass() { PASS=$((PASS + 1)); printf '\033[32m  PASS\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '\033[31m  FAIL\033[0m %s: %s\n' "$1" "$2"; }

cleanup() {
  if [ -n "$TMPDIR" ] && [ -d "$TMPDIR" ]; then
    rm -rf "$TMPDIR"
  fi
}
trap cleanup EXIT

# ── Setup temp environment ───────────────────────────────────────────────

setup_test_env() {
  TMPDIR="$(mktemp -d)"

  # Create a .env file with sensitive values
  cat > "$TMPDIR/.env" <<'ENVFILE'
APP_NAME=test-app
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
API_KEY=sk-1234567890abcdef
DATABASE_URL=postgres://user:password@host:5432/db
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
PUBLIC_VAR=not-a-secret
ENVFILE
}

# ── Tests ────────────────────────────────────────────────────────────────

echo "=== Audit Environment Integration Tests ==="
echo ""

if ! command -v jq >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
  echo "SKIP: jq or python3 required for JSON validation"
  exit 0
fi

# Test: Basic execution
echo "--- Basic execution ---"
setup_test_env

OUTPUT=""
OUTPUT="$(cd "$TMPDIR" && bash "$AUDIT_SCRIPT" 2>/dev/null)" || true

# Should produce valid JSON
if command -v jq >/dev/null 2>&1; then
  if echo "$OUTPUT" | jq . >/dev/null 2>&1; then
    pass "produces valid JSON"
  else
    fail "produces valid JSON" "invalid JSON output"
  fi
elif command -v python3 >/dev/null 2>&1; then
  if echo "$OUTPUT" | python3 -c "import json, sys; json.load(sys.stdin)" 2>/dev/null; then
    pass "produces valid JSON"
  else
    fail "produces valid JSON" "invalid JSON output"
  fi
fi

# Should detect .env credentials
FINDINGS_COUNT=""
if command -v jq >/dev/null 2>&1; then
  FINDINGS_COUNT="$(echo "$OUTPUT" | jq '.findings | length' 2>/dev/null)"
else
  FINDINGS_COUNT="$(echo "$OUTPUT" | python3 -c "import json,sys; print(len(json.load(sys.stdin).get('findings',[])))" 2>/dev/null)"
fi

if [ "${FINDINGS_COUNT:-0}" -gt 0 ]; then
  pass "detects .env credentials ($FINDINGS_COUNT findings)"
else
  fail "detects .env credentials" "got 0 findings"
fi

# Should have summary
HAS_SUMMARY=""
if command -v jq >/dev/null 2>&1; then
  HAS_SUMMARY="$(echo "$OUTPUT" | jq 'has("summary")' 2>/dev/null)"
else
  HAS_SUMMARY="$(echo "$OUTPUT" | python3 -c "import json,sys; print('true' if 'summary' in json.load(sys.stdin) else 'false')" 2>/dev/null)"
fi

if [ "$HAS_SUMMARY" = "true" ]; then
  pass "has summary field"
else
  fail "has summary field" "missing"
fi

# Should have target=environment
TARGET=""
if command -v jq >/dev/null 2>&1; then
  TARGET="$(echo "$OUTPUT" | jq -r '.target' 2>/dev/null)"
else
  TARGET="$(echo "$OUTPUT" | python3 -c "import json,sys; print(json.load(sys.stdin).get('target',''))" 2>/dev/null)"
fi

if [ "$TARGET" = "environment" ]; then
  pass "target is 'environment'"
else
  fail "target is 'environment'" "got '$TARGET'"
fi

# Test: Should NOT leak actual secret values
echo "--- Secret value protection ---"
if echo "$OUTPUT" | grep -q "wJalrXUtnFEMI"; then
  fail "does not leak AWS secret value" "found actual key in output"
else
  pass "does not leak AWS secret value"
fi

# Test: Empty directory (no .env files)
echo "--- Empty directory ---"
EMPTY_DIR="$(mktemp -d)"
OUTPUT="$(cd "$EMPTY_DIR" && bash "$AUDIT_SCRIPT" 2>/dev/null)" || true
rmdir "$EMPTY_DIR" 2>/dev/null || true

FINDINGS_COUNT=""
if command -v jq >/dev/null 2>&1; then
  FINDINGS_COUNT="$(echo "$OUTPUT" | jq '.summary.findings_count' 2>/dev/null)"
else
  FINDINGS_COUNT="$(echo "$OUTPUT" | python3 -c "import json,sys; print(json.load(sys.stdin).get('summary',{}).get('findings_count',0))" 2>/dev/null)"
fi

# May or may not have findings depending on home dir state — just check valid JSON
if command -v jq >/dev/null 2>&1; then
  if echo "$OUTPUT" | jq . >/dev/null 2>&1; then
    pass "empty directory: produces valid JSON"
  else
    fail "empty directory: produces valid JSON" "invalid"
  fi
fi

# ── Summary ──────────────────────────────────────────────────────────────

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
