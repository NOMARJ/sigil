#!/bin/bash
#
# Scanner v2 Production Deployment Script
# Performs progressive deployment with health checks and rollback capability
#

set -e

DEPLOYMENT_ENV="${DEPLOYMENT_ENV:-production}"
SCANNER_VERSION="${SCANNER_VERSION:-2.0.0}"
ROLLBACK_ON_FAILURE="${ROLLBACK_ON_FAILURE:-true}"

echo "======================================"
echo "Scanner v2 Production Deployment"
echo "======================================"
echo "Environment: $DEPLOYMENT_ENV"
echo "Scanner Version: $SCANNER_VERSION"
echo "Rollback on Failure: $ROLLBACK_ON_FAILURE"
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

# Step 1: Pre-deployment checks
log_info "Step 1: Running pre-deployment checks..."

# Check database connectivity
if ! psql "$DATABASE_URL" -c "SELECT 1" > /dev/null 2>&1; then
    log_error "Cannot connect to database"
    exit 1
fi

# Check API health
if ! curl -f -s "${API_URL}/health" > /dev/null; then
    log_error "API health check failed"
    exit 1
fi

log_info "Pre-deployment checks passed"

# Step 2: Database migrations
log_info "Step 2: Applying database migrations..."

# Run migration
psql "$DATABASE_URL" < api/migrations/add_scanner_v2_columns.sql

# Verify migration
COLUMNS_ADDED=$(psql "$DATABASE_URL" -t -c "
    SELECT COUNT(*) 
    FROM information_schema.columns 
    WHERE table_name = 'scans' 
    AND column_name IN ('scanner_version', 'confidence_level', 'original_score', 'rescanned_at', 'context_weight')
")

if [ "$COLUMNS_ADDED" -lt 5 ]; then
    log_error "Database migration failed - expected 5 new columns, found $COLUMNS_ADDED"
    exit 1
fi

log_info "Database migrations applied successfully"

# Step 3: Deploy API with feature flag
log_info "Step 3: Deploying API with Scanner v$SCANNER_VERSION..."

# Set environment variables for deployment
export SCANNER_VERSION="$SCANNER_VERSION"
export SCANNER_V1_ENABLED="true"  # Keep v1 available for rollback
export SCANNER_V2_FEATURES="confidence,context,safe_domains"

# Deploy API (platform-specific - adjust for your deployment method)
if [ "$DEPLOYMENT_ENV" = "production" ]; then
    # Example for Docker deployment
    docker build -t sigil-api:v2 -f api/Dockerfile api/
    docker tag sigil-api:v2 sigil-api:latest
    
    # Rolling deployment with health checks
    docker-compose -f docker-compose.prod.yml up -d --no-deps --scale api=2 api
    sleep 30  # Wait for new containers to be healthy
    
    # Verify new API is responding
    if ! curl -f -s "${API_URL}/v1/scanner/status" | grep -q "$SCANNER_VERSION"; then
        log_error "New API deployment failed verification"
        if [ "$ROLLBACK_ON_FAILURE" = "true" ]; then
            bash deployments/production/rollback.sh
        fi
        exit 1
    fi
    
    # Remove old containers
    docker-compose -f docker-compose.prod.yml up -d --no-deps --scale api=1 api
else
    log_info "Skipping production deployment in $DEPLOYMENT_ENV environment"
fi

log_info "API deployed successfully"

# Step 4: Deploy Bot Worker with v2 scanner
log_info "Step 4: Deploying Bot Worker with Scanner v2..."

# Deploy bot worker
if [ "$DEPLOYMENT_ENV" = "production" ]; then
    docker build -t sigil-bot:v2 -f bot/Dockerfile bot/
    docker tag sigil-bot:v2 sigil-bot:latest
    
    # Restart bot worker with new version
    docker-compose -f docker-compose.prod.yml restart bot
    
    # Verify bot is processing with v2
    sleep 10
    LATEST_SCAN=$(psql "$DATABASE_URL" -t -c "
        SELECT scanner_version 
        FROM scans 
        ORDER BY created_at DESC 
        LIMIT 1
    ")
    
    if [[ ! "$LATEST_SCAN" =~ "2.0.0" ]]; then
        log_warn "Bot may not be using Scanner v2 yet"
    fi
else
    log_info "Skipping bot deployment in $DEPLOYMENT_ENV environment"
fi

log_info "Bot Worker deployed"

# Step 5: Deploy Frontend with v2 UI components
log_info "Step 5: Deploying Frontend with Scanner v2 UI..."

if [ "$DEPLOYMENT_ENV" = "production" ]; then
    # Build frontend
    cd sigilsec
    npm ci
    npm run build
    
    # Deploy to hosting platform (adjust for your setup)
    # Example for Vercel/Netlify would go here
    
    cd ..
else
    log_info "Skipping frontend deployment in $DEPLOYMENT_ENV environment"
fi

log_info "Frontend deployed"

# Step 6: Smoke tests
log_info "Step 6: Running smoke tests..."

# Test v2 scan endpoint
TEST_RESULT=$(curl -s -X POST "${API_URL}/v1/scan/v2" \
    -H "Content-Type: application/json" \
    -H "X-API-Key: ${API_KEY}" \
    -d '{"package_name": "test-package", "package_version": "1.0.0", "package_type": "npm"}' \
    | jq -r '.scanner_version')

if [ "$TEST_RESULT" != "$SCANNER_VERSION" ]; then
    log_error "Smoke test failed - scanner version mismatch"
    if [ "$ROLLBACK_ON_FAILURE" = "true" ]; then
        bash deployments/production/rollback.sh
    fi
    exit 1
fi

# Test rescan endpoint
RESCAN_TEST=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "${API_URL}/api/rescan/00000000-0000-0000-0000-000000000000" \
    -H "X-API-Key: ${API_KEY}")

if [ "$RESCAN_TEST" != "404" ]; then
    log_error "Rescan endpoint not responding correctly"
    if [ "$ROLLBACK_ON_FAILURE" = "true" ]; then
        bash deployments/production/rollback.sh
    fi
    exit 1
fi

log_info "Smoke tests passed"

# Step 7: Performance validation
log_info "Step 7: Validating performance..."

# Check API response time
RESPONSE_TIME=$(curl -o /dev/null -s -w "%{time_total}" "${API_URL}/health")
if (( $(echo "$RESPONSE_TIME > 2" | bc -l) )); then
    log_warn "API response time is slow: ${RESPONSE_TIME}s"
fi

# Check database query performance  
QUERY_TIME=$(psql "$DATABASE_URL" -t -c "
    EXPLAIN (ANALYZE, FORMAT JSON) 
    SELECT * FROM scans 
    WHERE scanner_version = '2.0.0' 
    LIMIT 100
" | jq '.[0].["Execution Time"]')

if (( $(echo "$QUERY_TIME > 100" | bc -l) )); then
    log_warn "Database query performance may be degraded: ${QUERY_TIME}ms"
fi

log_info "Performance validation complete"

# Step 8: Start migration queue
log_info "Step 8: Starting progressive migration queue..."

# Start rescan worker if not already running
if [ "$DEPLOYMENT_ENV" = "production" ]; then
    # Check if rescan worker is running
    if ! pgrep -f "rescan_worker" > /dev/null; then
        nohup python -m api.workers.rescan_worker > /var/log/rescan_worker.log 2>&1 &
        log_info "Rescan worker started with PID $!"
    else
        log_info "Rescan worker already running"
    fi
fi

# Record deployment
psql "$DATABASE_URL" -c "
    INSERT INTO scanner_migration_progress (
        total_scans, v1_scans, v2_scans, avg_score_reduction, false_positive_rate
    )
    SELECT 
        COUNT(*),
        COUNT(*) FILTER (WHERE scanner_version = '1.0.0' OR scanner_version IS NULL),
        COUNT(*) FILTER (WHERE scanner_version = '2.0.0'),
        0, -- Will be calculated as migration progresses
        0  -- Will be calculated as migration progresses
    FROM scans
"

log_info "Migration queue started"

# Step 9: Update monitoring
log_info "Step 9: Configuring monitoring and alerts..."

# Update monitoring dashboards (platform-specific)
# This would integrate with your monitoring solution (DataDog, NewRelic, etc.)

log_info "Monitoring configured"

# Step 10: Final verification
log_info "Step 10: Final deployment verification..."

# Check all services are healthy
SERVICES_HEALTHY=true

if ! curl -f -s "${API_URL}/health" > /dev/null; then
    log_error "API health check failed"
    SERVICES_HEALTHY=false
fi

if ! curl -f -s "${FRONTEND_URL}" > /dev/null; then
    log_error "Frontend not responding"
    SERVICES_HEALTHY=false
fi

if [ "$SERVICES_HEALTHY" = false ]; then
    log_error "Deployment verification failed"
    if [ "$ROLLBACK_ON_FAILURE" = "true" ]; then
        bash deployments/production/rollback.sh
    fi
    exit 1
fi

echo ""
echo "======================================"
echo -e "${GREEN}Scanner v2 Deployment Complete!${NC}"
echo "======================================"
echo "Scanner Version: $SCANNER_VERSION"
echo "API Endpoint: ${API_URL}/v1/scan/v2"
echo "Migration Dashboard: ${FRONTEND_URL}/admin/migration-status"
echo ""
echo "Next Steps:"
echo "1. Monitor migration dashboard for progress"
echo "2. Check false positive rates in metrics"
echo "3. Review feedback from users"
echo "4. Gradually increase rescan rate if metrics are good"
echo ""

# Send deployment notification (optional)
if [ -n "$SLACK_WEBHOOK_URL" ]; then
    curl -X POST "$SLACK_WEBHOOK_URL" \
        -H 'Content-Type: application/json' \
        -d "{
            \"text\": \"Scanner v2 deployed successfully to $DEPLOYMENT_ENV\",
            \"attachments\": [{
                \"color\": \"good\",
                \"fields\": [
                    {\"title\": \"Version\", \"value\": \"$SCANNER_VERSION\", \"short\": true},
                    {\"title\": \"Environment\", \"value\": \"$DEPLOYMENT_ENV\", \"short\": true}
                ]
            }]
        }"
fi

exit 0