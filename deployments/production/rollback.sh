#!/bin/bash
#
# Scanner v2 Rollback Script
# Quickly revert to Scanner v1 in case of issues
#

set -e

echo "======================================"
echo "Scanner v2 Rollback Procedure"
echo "======================================"
echo ""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Step 1: Immediate scanner version rollback
log_warn "Step 1: Rolling back scanner version to v1..."

# Set environment to use v1 scanner
export SCANNER_VERSION="1.0.0"
export SCANNER_V1_ENABLED="true"
export SCANNER_V2_FEATURES=""

# Update configuration in database (if using config table)
psql "$DATABASE_URL" -c "
    UPDATE config 
    SET value = '1.0.0' 
    WHERE key = 'scanner_version'
"

log_info "Scanner version rolled back to 1.0.0"

# Step 2: Stop rescan worker
log_warn "Step 2: Stopping rescan worker..."

# Kill rescan worker process
pkill -f "rescan_worker" || true

# Mark any in-progress rescans as cancelled
psql "$DATABASE_URL" -c "
    UPDATE scans 
    SET scanner_version = '1.0.0'
    WHERE scanner_version = '2.0.0' 
    AND rescanned_at > NOW() - INTERVAL '1 hour'
    RETURNING COUNT(*)
"

log_info "Rescan worker stopped"

# Step 3: Revert API to v1 behavior
log_warn "Step 3: Reverting API to v1 scanner..."

if [ "$DEPLOYMENT_ENV" = "production" ]; then
    # Redeploy API with v1 settings
    docker-compose -f docker-compose.prod.yml run --rm api \
        sh -c "export SCANNER_VERSION=1.0.0 && echo 'Scanner reverted to v1'"
    
    # Restart API containers
    docker-compose -f docker-compose.prod.yml restart api
    
    # Wait for API to be healthy
    sleep 10
    
    # Verify rollback
    if curl -s "${API_URL}/v1/scanner/status" | grep -q "1.0.0"; then
        log_info "API successfully rolled back to v1"
    else
        log_error "API rollback verification failed"
    fi
else
    log_info "Skipping API rollback in non-production environment"
fi

# Step 4: Revert bot worker
log_warn "Step 4: Reverting bot worker to v1 scanner..."

if [ "$DEPLOYMENT_ENV" = "production" ]; then
    # Update bot configuration
    docker-compose -f docker-compose.prod.yml run --rm bot \
        sh -c "export SCANNER_VERSION=1.0.0 && echo 'Bot reverted to v1'"
    
    # Restart bot
    docker-compose -f docker-compose.prod.yml restart bot
    
    log_info "Bot worker rolled back"
else
    log_info "Skipping bot rollback in non-production environment"
fi

# Step 5: Preserve v2 scan data
log_info "Step 5: Preserving v2 scan data for analysis..."

# Create backup of v2 scans
psql "$DATABASE_URL" -c "
    CREATE TABLE IF NOT EXISTS scans_v2_backup AS
    SELECT * FROM scans 
    WHERE scanner_version = '2.0.0'
"

V2_SCAN_COUNT=$(psql "$DATABASE_URL" -t -c "
    SELECT COUNT(*) FROM scans_v2_backup
")

log_info "Preserved $V2_SCAN_COUNT v2 scans in backup table"

# Step 6: Update monitoring
log_warn "Step 6: Updating monitoring for rollback state..."

# Record rollback event
psql "$DATABASE_URL" -c "
    INSERT INTO deployment_events (
        event_type, 
        event_data, 
        created_at
    ) VALUES (
        'scanner_rollback',
        jsonb_build_object(
            'from_version', '2.0.0',
            'to_version', '1.0.0',
            'reason', 'Manual rollback triggered',
            'v2_scans_affected', $V2_SCAN_COUNT
        ),
        NOW()
    )
"

log_info "Monitoring updated"

# Step 7: Clear v2 caches
log_info "Step 7: Clearing v2 caches..."

# Clear any v2-specific caches
if command -v redis-cli &> /dev/null; then
    redis-cli --scan --pattern "scanner:v2:*" | xargs -r redis-cli del
    log_info "Redis caches cleared"
fi

# Step 8: Notify team
log_warn "Step 8: Sending rollback notifications..."

# Send rollback notification
if [ -n "$SLACK_WEBHOOK_URL" ]; then
    curl -X POST "$SLACK_WEBHOOK_URL" \
        -H 'Content-Type: application/json' \
        -d "{
            \"text\": \"⚠️ Scanner v2 has been rolled back to v1\",
            \"attachments\": [{
                \"color\": \"warning\",
                \"fields\": [
                    {\"title\": \"Environment\", \"value\": \"$DEPLOYMENT_ENV\", \"short\": true},
                    {\"title\": \"Affected Scans\", \"value\": \"$V2_SCAN_COUNT\", \"short\": true},
                    {\"title\": \"Action Required\", \"value\": \"Review logs and investigate issues\", \"short\": false}
                ]
            }]
        }"
fi

# Step 9: Verification
log_info "Step 9: Verifying rollback..."

VERIFICATION_PASSED=true

# Check API is using v1
if ! curl -s "${API_URL}/v1/scanner/status" | grep -q "1.0.0"; then
    log_error "API still reporting v2"
    VERIFICATION_PASSED=false
fi

# Check no new v2 scans are being created
sleep 5
NEW_V2_SCANS=$(psql "$DATABASE_URL" -t -c "
    SELECT COUNT(*) 
    FROM scans 
    WHERE scanner_version = '2.0.0' 
    AND created_at > NOW() - INTERVAL '1 minute'
")

if [ "$NEW_V2_SCANS" -gt 0 ]; then
    log_error "New v2 scans still being created"
    VERIFICATION_PASSED=false
fi

# Check services are healthy
if ! curl -f -s "${API_URL}/health" > /dev/null; then
    log_error "API health check failed after rollback"
    VERIFICATION_PASSED=false
fi

if [ "$VERIFICATION_PASSED" = false ]; then
    log_error "Rollback verification failed - manual intervention required"
    exit 1
fi

echo ""
echo "======================================"
echo -e "${YELLOW}Rollback Complete${NC}"
echo "======================================"
echo "Scanner Version: 1.0.0 (reverted from 2.0.0)"
echo "Affected v2 Scans: $V2_SCAN_COUNT (preserved in backup)"
echo ""
echo "Next Steps:"
echo "1. Review logs to identify root cause of issues"
echo "2. Analyze preserved v2 scans in scans_v2_backup table"
echo "3. Fix identified issues in v2 scanner"
echo "4. Plan re-deployment after fixes"
echo ""
echo -e "${YELLOW}Note: v2 scan data has been preserved and can be restored${NC}"
echo ""

exit 0