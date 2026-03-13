#!/bin/bash
# Retrieve Auth0 configuration from Azure Container Apps
# Usage: ./scripts/get_azure_auth0_config.sh

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
RESOURCE_GROUP="sigil-rg"
DASHBOARD_APP_NAME="sigil-dashboard"

echo "🔍 Retrieving Auth0 configuration from Azure"
echo ""

# Check if Azure CLI is installed
if ! command -v az &> /dev/null; then
    echo "❌ Azure CLI not found"
    echo "Install from: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli"
    exit 1
fi

# Check if logged into Azure
if ! az account show &> /dev/null; then
    echo "❌ Not logged into Azure"
    echo "Run: az login"
    exit 1
fi

echo -e "${GREEN}✅ Azure CLI configured${NC}"
echo ""

# Check if container app exists
if ! az containerapp show --name "$DASHBOARD_APP_NAME" --resource-group "$RESOURCE_GROUP" &> /dev/null; then
    echo "❌ Container app '$DASHBOARD_APP_NAME' not found in resource group '$RESOURCE_GROUP'"
    echo ""
    echo "Available container apps:"
    az containerapp list --resource-group "$RESOURCE_GROUP" --query "[].name" -o tsv
    exit 1
fi

echo -e "${GREEN}✅ Found container app: $DASHBOARD_APP_NAME${NC}"
echo ""

# Get environment variables
echo -e "${CYAN}Environment Variables:${NC}"
echo ""

ENV_VARS=$(az containerapp show \
    --name "$DASHBOARD_APP_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --query "properties.template.containers[0].env" -o json)

# Extract Auth0 configuration
AUTH0_BASE_URL=$(echo "$ENV_VARS" | jq -r '.[] | select(.name=="AUTH0_BASE_URL") | .value // "NOT SET"')
AUTH0_ISSUER_BASE_URL=$(echo "$ENV_VARS" | jq -r '.[] | select(.name=="AUTH0_ISSUER_BASE_URL") | .value // "NOT SET"')
AUTH0_CLIENT_ID=$(echo "$ENV_VARS" | jq -r '.[] | select(.name=="AUTH0_CLIENT_ID") | .value // "NOT SET"')
AUTH0_AUDIENCE=$(echo "$ENV_VARS" | jq -r '.[] | select(.name=="AUTH0_AUDIENCE") | .value // "NOT SET"')
NEXT_PUBLIC_API_URL=$(echo "$ENV_VARS" | jq -r '.[] | select(.name=="NEXT_PUBLIC_API_URL") | .value // "NOT SET"')

# Check for secret references
AUTH0_SECRET_REF=$(echo "$ENV_VARS" | jq -r '.[] | select(.name=="AUTH0_SECRET") | .secretRef // "NOT SET"')
AUTH0_CLIENT_SECRET_REF=$(echo "$ENV_VARS" | jq -r '.[] | select(.name=="AUTH0_CLIENT_SECRET") | .secretRef // "NOT SET"')

echo "AUTH0_BASE_URL: $AUTH0_BASE_URL"
echo "AUTH0_ISSUER_BASE_URL: $AUTH0_ISSUER_BASE_URL"
echo "AUTH0_CLIENT_ID: $AUTH0_CLIENT_ID"
echo "AUTH0_AUDIENCE: $AUTH0_AUDIENCE"
echo "NEXT_PUBLIC_API_URL: $NEXT_PUBLIC_API_URL"
echo ""

echo -e "${CYAN}Secrets (stored securely):${NC}"
echo ""
if [ "$AUTH0_SECRET_REF" != "NOT SET" ]; then
    echo -e "${GREEN}✅ AUTH0_SECRET: configured (secret: $AUTH0_SECRET_REF)${NC}"
else
    echo -e "${YELLOW}⚠️  AUTH0_SECRET: NOT CONFIGURED${NC}"
fi

if [ "$AUTH0_CLIENT_SECRET_REF" != "NOT SET" ]; then
    echo -e "${GREEN}✅ AUTH0_CLIENT_SECRET: configured (secret: $AUTH0_CLIENT_SECRET_REF)${NC}"
else
    echo -e "${YELLOW}⚠️  AUTH0_CLIENT_SECRET: NOT CONFIGURED${NC}"
fi

echo ""
echo -e "${CYAN}Container App Status:${NC}"
echo ""

STATUS=$(az containerapp show \
    --name "$DASHBOARD_APP_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --query "properties.runningStatus" -o tsv)

REPLICAS=$(az containerapp show \
    --name "$DASHBOARD_APP_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --query "properties.template.scale.minReplicas" -o tsv)

FQDN=$(az containerapp show \
    --name "$DASHBOARD_APP_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --query "properties.configuration.ingress.fqdn" -o tsv)

echo "Status: $STATUS"
echo "Min Replicas: $REPLICAS"
echo "URL: https://$FQDN"

echo ""
echo -e "${CYAN}Configuration Summary:${NC}"
echo ""

# Check if Auth0 is properly configured
MISSING_CONFIG=0

if [ "$AUTH0_BASE_URL" == "NOT SET" ]; then
    echo -e "${YELLOW}⚠️  AUTH0_BASE_URL not set${NC}"
    MISSING_CONFIG=1
fi

if [ "$AUTH0_ISSUER_BASE_URL" == "NOT SET" ]; then
    echo -e "${YELLOW}⚠️  AUTH0_ISSUER_BASE_URL not set${NC}"
    MISSING_CONFIG=1
fi

if [ "$AUTH0_CLIENT_ID" == "NOT SET" ]; then
    echo -e "${YELLOW}⚠️  AUTH0_CLIENT_ID not set${NC}"
    MISSING_CONFIG=1
fi

if [ "$AUTH0_SECRET_REF" == "NOT SET" ]; then
    echo -e "${YELLOW}⚠️  AUTH0_SECRET not set${NC}"
    MISSING_CONFIG=1
fi

if [ "$AUTH0_CLIENT_SECRET_REF" == "NOT SET" ]; then
    echo -e "${YELLOW}⚠️  AUTH0_CLIENT_SECRET not set${NC}"
    MISSING_CONFIG=1
fi

if [ $MISSING_CONFIG -eq 0 ]; then
    echo -e "${GREEN}✅ All Auth0 configuration is set${NC}"
    echo ""
    echo "Login should work at: https://app.sigilsec.ai/login"
else
    echo ""
    echo -e "${YELLOW}⚠️  Some Auth0 configuration is missing${NC}"
    echo ""
    echo "To set Auth0 secrets, run:"
    echo "  ./scripts/set_azure_auth0_secrets.sh"
fi

echo ""
echo "To view logs:"
echo "  az containerapp logs show --name $DASHBOARD_APP_NAME --resource-group $RESOURCE_GROUP --follow"
