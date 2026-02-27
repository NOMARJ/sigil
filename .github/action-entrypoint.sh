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
EXCLUDE="${INPUT_EXCLUDE:-}"
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
[ -n "$EXCLUDE" ] && log "  Exclude:   $EXCLUDE"
[ -n "$API_KEY" ] && log "  API key:   (provided)"

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

SCAN_CMD="sigil scan \"$SCAN_PATH\""

# Add phases filter if specified
if [ -n "${PHASES:-}" ] && [ "$PHASES" != "all" ]; then
    SCAN_CMD="$SCAN_CMD --phases $PHASES"
fi

# Add exclusions if specified
if [ -n "${EXCLUDE:-}" ]; then
    SCAN_CMD="$SCAN_CMD --exclude $EXCLUDE"
fi

# Add API key for cloud features
if [ -n "${API_KEY:-}" ]; then
    export SIGIL_API_KEY="$API_KEY"
    SCAN_CMD="$SCAN_CMD --submit"
fi

eval $SCAN_CMD 2>&1 | tee "$SCAN_OUTPUT" || SCAN_EXIT=$?

echo ""

# ── Parse results from the report file ───────────────────────────────────────
REPORT_FILE=$(find "$SIGIL_REPORT_DIR" -name "*_report.txt" -type f | head -1)

RISK_SCORE=0
VERDICT="clean"
FINDINGS_COUNT=0

if [ -n "$REPORT_FILE" ] && [ -f "$REPORT_FILE" ]; then
    # Extract risk score from the verdict line
    SCORE_LINE=$(grep -o 'Risk Score: [0-9]*' "$REPORT_FILE" | tail -1 || true)
    if [ -n "$SCORE_LINE" ]; then
        RISK_SCORE=$(echo "$SCORE_LINE" | grep -o '[0-9]*')
    fi

    # Count findings (lines with [FAIL] or [warn])
    FAIL_COUNT=$(grep -c '\[FAIL\]' "$REPORT_FILE" 2>/dev/null || echo "0")
    WARN_COUNT=$(grep -c '\[warn\]' "$REPORT_FILE" 2>/dev/null || echo "0")
    FINDINGS_COUNT=$((FAIL_COUNT + WARN_COUNT))

    # Determine verdict from score
    if [ "$RISK_SCORE" -eq 0 ]; then
        VERDICT="clean"
    elif [ "$RISK_SCORE" -lt 10 ]; then
        VERDICT="low"
    elif [ "$RISK_SCORE" -lt 25 ]; then
        VERDICT="medium"
    elif [ "$RISK_SCORE" -lt 50 ]; then
        VERDICT="high"
    else
        VERDICT="critical"
    fi
else
    warn "No report file found — scan may have failed"
fi

log "Scan complete."
log "  Verdict:  $VERDICT"
log "  Score:    $RISK_SCORE"
log "  Findings: $FINDINGS_COUNT"

# ── Set GitHub Actions outputs ───────────────────────────────────────────────
echo "verdict=$VERDICT" >> "$GITHUB_OUTPUT"
echo "risk-score=$RISK_SCORE" >> "$GITHUB_OUTPUT"
echo "findings-count=$FINDINGS_COUNT" >> "$GITHUB_OUTPUT"

# ── Write job summary ────────────────────────────────────────────────────────
VERDICT_EMOJI=""
case "$VERDICT" in
    low)      VERDICT_EMOJI="LOW RISK" ;;
    medium)   VERDICT_EMOJI="MEDIUM RISK" ;;
    high)     VERDICT_EMOJI="HIGH RISK" ;;
    critical) VERDICT_EMOJI="CRITICAL RISK" ;;
esac

{
    echo "## Sigil Security Scan Results"
    echo ""
    echo "| Property | Value |"
    echo "|----------|-------|"
    echo "| **Verdict** | \`$VERDICT_EMOJI\` |"
    echo "| **Risk Score** | \`$RISK_SCORE\` |"
    echo "| **Findings** | \`$FINDINGS_COUNT\` |"
    echo "| **Threshold** | \`$THRESHOLD\` |"
    echo "| **Scan Path** | \`$SCAN_PATH\` |"
    echo ""

    if [ "$FINDINGS_COUNT" -gt 0 ] && [ -n "$REPORT_FILE" ] && [ -f "$REPORT_FILE" ]; then
        echo "### Findings"
        echo ""
        echo "<details>"
        echo "<summary>Show detailed findings ($FINDINGS_COUNT total)</summary>"
        echo ""
        echo '```'

        # Extract finding lines from the report
        grep -E '\[FAIL\]|\[warn\]' "$REPORT_FILE" | while IFS= read -r line; do
            # Strip ANSI colour codes for the summary
            echo "$line" | sed 's/\x1b\[[0-9;]*m//g'
        done

        echo '```'
        echo ""
        echo "</details>"
        echo ""
    fi

    if [ "$FINDINGS_COUNT" -gt 0 ]; then
        echo "### Phase Breakdown"
        echo ""
        echo "| Phase | Status |"
        echo "|-------|--------|"

        for phase in "Phase 1: Install Hook" "Phase 2: Code Pattern" "Phase 3: Network" "Phase 4: Credential" "Phase 5: Obfuscation" "Phase 6: Provenance"; do
            if [ -n "$REPORT_FILE" ] && [ -f "$REPORT_FILE" ]; then
                phase_short=$(echo "$phase" | sed 's/Phase [0-9]: //')
                if grep -q "$phase" "$REPORT_FILE" 2>/dev/null; then
                    phase_findings=$(sed -n "/$phase/,/Phase\|===\|VERDICT/p" "$REPORT_FILE" | grep -c '\[FAIL\]\|\[warn\]' 2>/dev/null || echo "0")
                    if [ "$phase_findings" -gt 0 ]; then
                        echo "| $phase_short | \`$phase_findings finding(s)\` |"
                    else
                        echo "| $phase_short | \`clean\` |"
                    fi
                fi
            fi
        done
        echo ""
    fi

    echo "---"
    echo "*Scanned by [Sigil](https://github.com/nomark/sigil) — automated security auditing for AI agent code.*"
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
