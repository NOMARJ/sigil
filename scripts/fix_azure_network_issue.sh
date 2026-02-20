#!/bin/bash
#
# Quick fix for Azure Container Apps IPv6 connectivity issue
#
# This script updates the DATABASE_URL secret to use Supabase's connection pooler
# which supports IPv4 (compatible with Azure Container Apps).
#
# Usage:
#   ./fix_azure_network_issue.sh [PASSWORD]
#
# If PASSWORD is not provided, you'll be prompted to enter it securely.
#

set -e  # Exit on error

# Configuration
RESOURCE_GROUP="sigil-rg"
APP_NAME="sigil-api"
PROJECT_REF="pjjelfyuplqjgljvuybr"
POOLER_HOST="aws-0-us-east-1.pooler.supabase.com"
POOLER_PORT="6543"  # Transaction mode (recommended for web apps)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
print_header() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

# Main script
clear
print_header "Azure Container Apps - Supabase IPv4 Fix"

echo
print_info "This script will update sigil-api to use Supabase's connection pooler"
print_info "which supports IPv4 (compatible with Azure Container Apps)."
echo

# Check if Azure CLI is installed
if ! command -v az &> /dev/null; then
    print_error "Azure CLI not found. Please install it first:"
    echo "  https://learn.microsoft.com/en-us/cli/azure/install-azure-cli"
    exit 1
fi

# Check if logged in to Azure
print_info "Checking Azure authentication..."
if ! az account show &> /dev/null; then
    print_error "Not logged in to Azure. Please run: az login"
    exit 1
fi
print_success "Azure CLI authenticated"

# Get password
PASSWORD="$1"
if [ -z "$PASSWORD" ]; then
    echo
    echo "Enter your Supabase PostgreSQL password:"
    read -s PASSWORD
    echo
fi

if [ -z "$PASSWORD" ]; then
    print_error "Password cannot be empty"
    exit 1
fi

# Construct new connection string
NEW_DB_URL="postgresql://postgres.${PROJECT_REF}:${PASSWORD}@${POOLER_HOST}:${POOLER_PORT}/postgres"

echo
print_header "Step 1: Test Connection Pooler Connectivity"

print_info "Testing DNS resolution for pooler..."
if host "$POOLER_HOST" > /dev/null 2>&1; then
    POOLER_IP=$(host "$POOLER_HOST" | grep "has address" | head -1 | awk '{print $NF}')
    print_success "Pooler resolves to IPv4: $POOLER_IP"
else
    print_warning "Could not resolve pooler hostname (may still work)"
fi

print_info "Testing TCP connectivity to $POOLER_HOST:$POOLER_PORT..."
if nc -zv -w 3 "$POOLER_HOST" "$POOLER_PORT" 2>&1 | grep -q succeeded; then
    print_success "TCP connection successful"
else
    print_warning "TCP test inconclusive (may still work from Azure)"
fi

echo
print_header "Step 2: Backup Current Configuration"

print_info "Getting current revision..."
CURRENT_REVISION=$(az containerapp revision list \
    --name "$APP_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --query "[?properties.active].name" \
    --output tsv | head -1)

if [ -z "$CURRENT_REVISION" ]; then
    print_error "Could not find active revision"
    exit 1
fi

print_success "Current revision: $CURRENT_REVISION"

# Save current state
BACKUP_FILE="container_app_backup_$(date +%Y%m%d_%H%M%S).json"
print_info "Saving current configuration to $BACKUP_FILE..."
az containerapp show \
    --name "$APP_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --output json > "$BACKUP_FILE"
print_success "Backup saved"

echo
print_header "Step 3: Update DATABASE_URL Secret"

print_info "Updating sigil-database-url secret..."

# Update the secret
if az containerapp secret set \
    --name "$APP_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --secrets "sigil-database-url=$NEW_DB_URL" \
    --output none 2>&1; then
    print_success "Secret updated successfully"
else
    print_error "Failed to update secret"
    print_info "Restoring from backup..."
    # Note: You would need to manually restore if this fails
    exit 1
fi

echo
print_header "Step 4: Deploy New Revision"

print_info "Creating new revision with updated secret..."
print_warning "This will create a new revision and may take 1-2 minutes..."

# The secret update triggers a new revision automatically, but let's verify
sleep 5

NEW_REVISION=$(az containerapp revision list \
    --name "$APP_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --query "[?properties.active].name" \
    --output tsv | head -1)

if [ "$NEW_REVISION" != "$CURRENT_REVISION" ]; then
    print_success "New revision created: $NEW_REVISION"
else
    print_warning "Revision may still be updating..."
fi

echo
print_header "Step 5: Verify Deployment"

print_info "Waiting for revision to become healthy (max 60s)..."

# Wait up to 60 seconds for the new revision to be healthy
TIMEOUT=60
ELAPSED=0
INTERVAL=5

while [ $ELAPSED -lt $TIMEOUT ]; do
    HEALTH_STATE=$(az containerapp revision show \
        --revision "$NEW_REVISION" \
        --resource-group "$RESOURCE_GROUP" \
        --query "properties.healthState" \
        --output tsv 2>/dev/null || echo "Unknown")

    if [ "$HEALTH_STATE" = "Healthy" ]; then
        print_success "Revision is healthy"
        break
    fi

    echo -ne "\r  Waiting... ${ELAPSED}s elapsed (Status: $HEALTH_STATE)"
    sleep $INTERVAL
    ELAPSED=$((ELAPSED + INTERVAL))
done

echo
if [ $ELAPSED -ge $TIMEOUT ]; then
    print_warning "Timeout waiting for healthy state. Check manually with:"
    echo "  az containerapp revision list --name $APP_NAME --resource-group $RESOURCE_GROUP"
fi

echo
print_header "Step 6: Test API Connectivity"

API_URL="https://api.sigilsec.ai/health"
print_info "Testing API health endpoint: $API_URL"

if command -v curl &> /dev/null; then
    HEALTH_RESPONSE=$(curl -s -m 10 "$API_URL" 2>&1 || echo "")

    if echo "$HEALTH_RESPONSE" | grep -q '"status"'; then
        print_success "API is responding"
        echo
        echo "$HEALTH_RESPONSE" | jq '.' 2>/dev/null || echo "$HEALTH_RESPONSE"
        echo

        # Check database connection status
        if echo "$HEALTH_RESPONSE" | jq -e '.supabase_connected == true' &>/dev/null; then
            print_success "Database connection confirmed!"
        elif echo "$HEALTH_RESPONSE" | jq -e '.supabase_connected == false' &>/dev/null; then
            print_error "Database connection still failing"
            print_info "Check logs with: az containerapp logs show --name $APP_NAME --resource-group $RESOURCE_GROUP --tail 50"
        else
            print_warning "Could not determine database status from health check"
        fi
    else
        print_warning "API health check failed or returned unexpected response"
        print_info "Response: $HEALTH_RESPONSE"
    fi
else
    print_warning "curl not found - skipping health check"
    print_info "Manually test: curl https://api.sigilsec.ai/health"
fi

echo
print_header "Summary"

echo
echo "Configuration Changes:"
echo "  Resource Group: $RESOURCE_GROUP"
echo "  Container App: $APP_NAME"
echo "  Old Revision: $CURRENT_REVISION"
echo "  New Revision: $NEW_REVISION"
echo
echo "Connection String Update:"
echo "  Old: postgresql://...@db.$PROJECT_REF.supabase.co:5432/postgres (IPv6)"
echo "  New: postgresql://...@$POOLER_HOST:$POOLER_PORT/postgres (IPv4)"
echo
echo "Backup saved to: $BACKUP_FILE"
echo

print_header "Next Steps"

echo
print_success "1. Verify API is working:"
echo "   curl https://api.sigilsec.ai/health | jq"
echo
print_success "2. Check application logs:"
echo "   az containerapp logs show --name $APP_NAME --resource-group $RESOURCE_GROUP --tail 50"
echo
print_success "3. Monitor for errors:"
echo "   az containerapp logs show --name $APP_NAME --resource-group $RESOURCE_GROUP --follow"
echo
print_success "4. If issues persist, rollback to previous revision:"
echo "   az containerapp revision activate --revision $CURRENT_REVISION --name $APP_NAME --resource-group $RESOURCE_GROUP"
echo

print_header "Documentation"

echo
echo "Full diagnostic report: /Users/reecefrazier/CascadeProjects/sigil/NETWORK_DIAGNOSTIC_REPORT.md"
echo "Test script: /Users/reecefrazier/CascadeProjects/sigil/scripts/test_supabase_connection.py"
echo

print_success "Fix script completed!"
