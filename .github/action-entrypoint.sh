#!/usr/bin/env bash
# ============================================================================
# SIGIL — GitHub Action Entrypoint
# by NOMARK
#
# Runs a Sigil security scan inside a GitHub Actions workflow, parses the
# results, writes a job summary, and sets output variables.
# ============================================================================
set -euo pipefail

# ── Colour helpers (GitHub Actions supports ANSI) ────────────────────────────
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log()  { echo -e "${BLUE}[sigil-action]${NC} $1"; }
warn() { echo -e "${YELLOW}[sigil-action]${NC} $1"; }
fail() { echo -e "${RED}[sigil-action]${NC} $1"; }
pass() { echo -e "${GREEN}[sigil-action]${NC} $1"; }

# ── Read inputs from environment ─────────────────────────────────────────────
SCAN_PATH="${INPUT_PATH:-.}"
THRESHOLD="${INPUT_THRESHOLD:-medium}"
API_KEY="${INPUT_API_KEY:-}"
FAIL_ON_FINDINGS="${INPUT_FAIL_ON_FINDINGS:-true}"
PHASES="${INPUT_PHASES:-all}"
UPLOAD_SARIF="${INPUT_UPLOAD_SARIF:-false}"
SARIF_FILE="${INPUT_SARIF_FILE:-sigil-results.sarif}"
ACTION_PATH="${SIGIL_ACTION_PATH:-$(dirname "$(dirname "$0")")}"

# ── Validate inputs ──────────────────────────────────────────────────────────
THRESHOLD=$(echo "$THRESHOLD" | tr '[:upper:]' '[:lower:]')
case "$THRESHOLD" in
    low|medium|high|critical) ;;
    *)
        fail "Invalid threshold: $THRESHOLD (must be low/medium/high/critical)"
        exit 1
        ;;
esac

if [ ! -e "$SCAN_PATH" ]; then
    fail "Scan path does not exist: $SCAN_PATH"
    exit 1
fi

log "Sigil Security Scan"
log "  Path:      $SCAN_PATH"
log "  Threshold: $THRESHOLD"
log "  Phases:    $PHASES"
log "  Fail:      $FAIL_ON_FINDINGS"
log "  SARIF:     $UPLOAD_SARIF"
[ -n "$API_KEY" ] && log "  API key:   (provided)"

# ── SARIF pass (opt-in, best effort) ─────────────────────────────────────────
# When upload-sarif is enabled, run a second scan in SARIF format so the
# github/codeql-action/upload-sarif step in action.yml can publish it. This
# pass never fails the job: a scanner exit code here is informational only,
# and if no valid SARIF document is produced we write an empty one so the
# upload step still has a well-formed file to consume.
write_empty_sarif() {
    cat > "$1" <<'EOF'
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": { "driver": { "name": "Sigil", "informationUri": "https://github.com/NOMARJ/sigil" } },
      "results": []
    }
  ]
}
EOF
}

run_sarif_pass() {
    [ "$UPLOAD_SARIF" = "true" ] || return 0

    local sarif_cmd=(sigil scan "$SCAN_PATH" --format sarif)
    if [ -n "${PHASES:-}" ] && [ "$PHASES" != "all" ]; then
        sarif_cmd+=(--phases "$PHASES")
    fi

    local sarif_dir
    sarif_dir=$(dirname "$SARIF_FILE")
    mkdir -p "$sarif_dir" 2>/dev/null || true

    log "Running SARIF pass -> '$SARIF_FILE'..."
    local sarif_exit=0
    set +e
    "${sarif_cmd[@]}" > "$SARIF_FILE"
    sarif_exit=$?
    set -e

    if ! jq -e '.runs' "$SARIF_FILE" >/dev/null 2>&1; then
        warn "SARIF pass did not produce a valid SARIF document (exit $sarif_exit); writing an empty report."
        write_empty_sarif "$SARIF_FILE"
    elif [ "$sarif_exit" -ne 0 ]; then
        # Non-zero exit is the scanner's verdict signalling (see docs/cicd.md);
        # the threshold check on the JSON pass decides whether the job fails.
        log "SARIF pass finished with scanner exit code $sarif_exit (not fatal)."
    fi

    echo "sarif-file=$SARIF_FILE" >> "$GITHUB_OUTPUT"
}

# ── Set up temporary report directory ────────────────────────────────────────
SIGIL_REPORT_DIR=$(mktemp -d)
export SIGIL_QUARANTINE_DIR=$(mktemp -d)
export SIGIL_APPROVED_DIR=$(mktemp -d)
export SIGIL_LOG_DIR=$(mktemp -d)
export SIGIL_REPORT_DIR

# ── Run the scan ─────────────────────────────────────────────────────────────
SCAN_OUTPUT=$(mktemp)
SCAN_EXIT=0

log "Running sigil scan on '$SCAN_PATH'..."
echo ""

SCAN_CMD=(sigil scan "$SCAN_PATH" --format json)

# Add phases filter if specified
if [ -n "${PHASES:-}" ] && [ "$PHASES" != "all" ]; then
    SCAN_CMD+=(--phases "$PHASES")
fi


# Add API key for cloud features
if [ -n "${API_KEY:-}" ]; then
    export SIGIL_API_KEY="$API_KEY"
    SCAN_CMD+=(--submit)
fi

# The CLI emits a single JSON document on stdout (--format json), shaped
# {"summary": {...}, "findings": [...]}, with its log lines on stderr.
# Capture stdout for parsing and let the logs stream through to the console.
set +e
"${SCAN_CMD[@]}" > "$SCAN_OUTPUT"
SCAN_EXIT=$?
set -e

echo ""

# ── Parse results from the JSON output ───────────────────────────────────────
RISK_SCORE=0
VERDICT="clean"
FINDINGS_COUNT=0
GRADE=""
RECOMMENDATION=""
BADGE=""
JSON_OK=false

if jq -e '.summary' "$SCAN_OUTPUT" >/dev/null 2>&1; then
    JSON_OK=true
    RISK_SCORE=$(jq -r '(.summary.score // 0) | (tonumber? // 0) | floor' "$SCAN_OUTPUT")
    FINDINGS_COUNT=$(jq -r '.summary.findings_count // ((.findings // []) | length)' "$SCAN_OUTPUT")
    # Grade (A-F) and recommendation are emitted by sigil >= 1.3.6; older
    # binaries simply leave them empty and the badge is skipped.
    GRADE=$(jq -r '.summary.grade // empty' "$SCAN_OUTPUT" | tr '[:lower:]' '[:upper:]' | tr -cd 'A-F' | cut -c1)
    RECOMMENDATION=$(jq -r '.summary.recommendation // empty' "$SCAN_OUTPUT" | tr -d '\r' | head -n1)
    VERDICT=$(jq -r '.summary.verdict // empty' "$SCAN_OUTPUT" | tr '[:upper:]' '[:lower:]' | tr ' ' '-')
    case "$VERDICT" in
        low-risk) VERDICT="low" ;;
        medium-risk) VERDICT="medium" ;;
        high-risk) VERDICT="high" ;;
        critical-risk) VERDICT="critical" ;;
    esac

    # Fall back to deriving the verdict from the score if the JSON lacks one
    if [ -z "$VERDICT" ]; then
        if [ "$RISK_SCORE" -lt 10 ]; then
            VERDICT="low"
        elif [ "$RISK_SCORE" -lt 25 ]; then
            VERDICT="medium"
        elif [ "$RISK_SCORE" -lt 50 ]; then
            VERDICT="high"
        else
            VERDICT="critical"
        fi
    fi
else
    warn "No parseable JSON scan output found"
fi

if [ "$JSON_OK" != "true" ]; then
    if [ "$VERDICT" = "clean" ] && [ "$FINDINGS_COUNT" -eq 0 ] && [ "$RISK_SCORE" -eq 0 ]; then
        SCAN_EXIT=${SCAN_EXIT:-1}
        [ "$SCAN_EXIT" -eq 0 ] && SCAN_EXIT=1
    fi
fi

if [ "$SCAN_EXIT" -ne 0 ] && [ "$JSON_OK" != "true" ] && [ "$VERDICT" = "clean" ]; then
    VERDICT="error"
    fail "Sigil scan failed with exit code $SCAN_EXIT and did not produce parseable JSON output."

    echo "verdict=$VERDICT" >> "$GITHUB_OUTPUT"
    echo "risk-score=$RISK_SCORE" >> "$GITHUB_OUTPUT"
    echo "findings-count=$FINDINGS_COUNT" >> "$GITHUB_OUTPUT"
    echo "grade=" >> "$GITHUB_OUTPUT"
    echo "badge=" >> "$GITHUB_OUTPUT"

    # Still hand the upload step a well-formed (possibly empty) SARIF file so
    # a guarded `always()` upload does not fail on a missing path.
    run_sarif_pass

    {
        echo "## Sigil Security Scan Failed"
        echo ""
        echo "Sigil exited with code \`$SCAN_EXIT\` before producing parseable JSON output."
        echo ""
        echo '```'
        sed 's/\x1b\[[0-9;]*m//g' "$SCAN_OUTPUT"
        echo '```'
    } >> "$GITHUB_STEP_SUMMARY"

    exit "$SCAN_EXIT"
fi

log "Scan complete."
log "  Verdict:  $VERDICT"
log "  Score:    $RISK_SCORE"
log "  Findings: $FINDINGS_COUNT"
[ -n "$GRADE" ] && log "  Grade:    $GRADE"

# ── Grade badge (shields.io) ─────────────────────────────────────────────────
# Grade is derived from the verdict by the CLI: A = no findings, B = low-
# severity observations only, C = MEDIUM RISK, D = HIGH RISK, F = CRITICAL RISK.
grade_to_colour() {
    case "$1" in
        A) echo "brightgreen" ;;
        B) echo "green" ;;
        C) echo "yellow" ;;
        D) echo "orange" ;;
        F) echo "red" ;;
        *) echo "lightgrey" ;;
    esac
}

if [ -n "$GRADE" ]; then
    BADGE_COLOUR=$(grade_to_colour "$GRADE")
    BADGE="[![Sigil grade $GRADE](https://img.shields.io/badge/Sigil-Grade%20$GRADE-$BADGE_COLOUR?style=flat-square)](https://github.com/NOMARJ/sigil)"
fi

# ── Set GitHub Actions outputs ───────────────────────────────────────────────
echo "verdict=$VERDICT" >> "$GITHUB_OUTPUT"
echo "risk-score=$RISK_SCORE" >> "$GITHUB_OUTPUT"
echo "findings-count=$FINDINGS_COUNT" >> "$GITHUB_OUTPUT"
echo "grade=$GRADE" >> "$GITHUB_OUTPUT"
echo "badge=$BADGE" >> "$GITHUB_OUTPUT"

# ── Optional SARIF pass for GitHub Code Scanning ────────────────────────────
run_sarif_pass

# ── Write job summary ────────────────────────────────────────────────────────
VERDICT_EMOJI=""
case "$VERDICT" in
    clean)    VERDICT_EMOJI="CLEAN" ;;
    low)      VERDICT_EMOJI="LOW RISK" ;;
    medium)   VERDICT_EMOJI="MEDIUM RISK" ;;
    high)     VERDICT_EMOJI="HIGH RISK" ;;
    critical) VERDICT_EMOJI="CRITICAL RISK" ;;
    *)        VERDICT_EMOJI=$(echo "$VERDICT" | tr '[:lower:]' '[:upper:]') ;;
esac

{
    echo "## Sigil Security Scan Results"
    echo ""
    if [ -n "$BADGE" ]; then
        echo "$BADGE"
        echo ""
    fi
    echo "| Property | Value |"
    echo "|----------|-------|"
    echo "| **Verdict** | \`$VERDICT_EMOJI\` |"
    if [ -n "$GRADE" ]; then
        echo "| **Grade** | \`$GRADE\` |"
    fi
    echo "| **Risk Score** | \`$RISK_SCORE\` |"
    echo "| **Findings** | \`$FINDINGS_COUNT\` |"
    echo "| **Threshold** | \`$THRESHOLD\` |"
    echo "| **Scan Path** | \`$SCAN_PATH\` |"
    if [ "$UPLOAD_SARIF" = "true" ]; then
        echo "| **SARIF** | \`$SARIF_FILE\` |"
    fi
    echo ""
    if [ -n "$RECOMMENDATION" ]; then
        echo "**Recommendation:** $RECOMMENDATION"
        echo ""
    fi
    if [ -n "$BADGE" ]; then
        echo "<details>"
        echo "<summary>Badge markdown</summary>"
        echo ""
        echo '```markdown'
        echo "$BADGE"
        echo '```'
        echo ""
        echo "</details>"
        echo ""
    fi

    if [ "$FINDINGS_COUNT" -gt 0 ] && [ "$JSON_OK" = "true" ]; then
        echo "### Findings"
        echo ""
        echo "<details>"
        echo "<summary>Show detailed findings ($FINDINGS_COUNT total)</summary>"
        echo ""
        echo '```'

        # One line per finding, straight from the JSON
        jq -r '(.findings // [])[]
            | "[\(.severity // "info" | ascii_upcase)] \(.phase // "unknown"): \(.title // .message // .description // .rule // "finding")"
              + (if .file then " (\(.file)" + (if .line then ":\(.line)" else "" end) + ")" else "" end)' \
            "$SCAN_OUTPUT"

        echo '```'
        echo ""
        echo "</details>"
        echo ""
    fi

    if [ "$FINDINGS_COUNT" -gt 0 ] && [ "$JSON_OK" = "true" ]; then
        echo "### Phase Breakdown"
        echo ""
        echo "| Phase | Findings |"
        echo "|-------|----------|"

        # Derive the phase list from the findings themselves rather than a
        # hardcoded list — the scanner has eight phases plus inference security.
        jq -r '[(.findings // [])[] | (.phase // "unknown")]
            | group_by(.)
            | map("| \(.[0]) | `\(length) finding(s)` |")
            | .[]' \
            "$SCAN_OUTPUT"
        echo ""
    fi

    echo "---"
    echo "*Scanned by [Sigil](https://github.com/NOMARJ/sigil) — automated security auditing for AI agent code.*"
    echo ""
    echo "*Automated static analysis result. Not a security certification. Provided as-is without warranty. See [sigilsec.ai/terms](https://sigilsec.ai/terms) for full terms.*"
} >> "$GITHUB_STEP_SUMMARY"

# ── Determine threshold-based exit ───────────────────────────────────────────
threshold_to_score() {
    case "$1" in
        low)      echo 1 ;;
        medium)   echo 10 ;;
        high)     echo 25 ;;
        critical) echo 50 ;;
        *)        echo 10 ;;
    esac
}

THRESHOLD_SCORE=$(threshold_to_score "$THRESHOLD")

if [ "$FAIL_ON_FINDINGS" = "true" ] && [ "$RISK_SCORE" -ge "$THRESHOLD_SCORE" ]; then
    fail "Risk score ($RISK_SCORE) meets or exceeds threshold ($THRESHOLD = score $THRESHOLD_SCORE)"
    fail "Set 'fail-on-findings: false' to continue on findings."
    exit 1
fi

# ── Clean up ─────────────────────────────────────────────────────────────────
rm -rf "$SIGIL_QUARANTINE_DIR" "$SIGIL_APPROVED_DIR" "$SIGIL_LOG_DIR" "$SIGIL_REPORT_DIR" "$SCAN_OUTPUT" 2>/dev/null || true

pass "Scan passed. Risk score $RISK_SCORE is below threshold ($THRESHOLD = score $THRESHOLD_SCORE)."
exit 0
