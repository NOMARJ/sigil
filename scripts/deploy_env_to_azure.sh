#!/bin/bash
# Deploy .env.production secrets to Azure Container Apps
# Usage: ./scripts/deploy_env_to_azure.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
RESOURCE_GROUP="sigil-rg"
DASHBOARD_APP_NAME="sigil-dashboard"
ENV_FILE="dashboard/.env.production"

echo -e "${CYAN}🚀 Deploying .env.production to Azure Container Apps${NC}"
echo ""

# Check if .env.production exists
if [ ! -f "$ENV_FILE" ]; then
    echo -e "${RED}❌ File not found: $ENV_FILE${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Found $ENV_FILE${NC}"
echo ""

# Check if Azure CLI is installed
if ! command -v az &> /dev/null; then
    echo -e "${RED}❌ Azure CLI not found${NC}"
    echo "Install from: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli"
    exit 1
fi

# Check if logged into Azure
if ! az account show &> /dev/null; then
    echo -e "${RED}❌ Not logged into Azure${NC}"
    echo "Run: az login"
    exit 1
fi

echo -e "${GREEN}✅ Azure CLI configured${NC}"
echo ""

# Check if container app exists
if ! az containerapp show --name "$DASHBOARD_APP_NAME" --resource-group "$RESOURCE_GROUP" &> /dev/null; then
    echo -e "${RED}❌ Container app '$DASHBOARD_APP_NAME' not found in resource group '$RESOURCE_GROUP'${NC}"
    echo ""
    echo "Available container apps:"
    az containerapp list --resource-group "$RESOURCE_GROUP" --query "[].name" -o tsv
    exit 1
fi

echo -e "${GREEN}✅ Found container app: $DASHBOARD_APP_NAME${NC}"
echo ""

# Load environment variables from .env.production
echo -e "${CYAN}📋 Loading environment variables from $ENV_FILE${NC}"
echo ""

# Source the file to load variables
set -a
source "$ENV_FILE"
set +a

# Display what will be deployed (without showing secrets)
echo "Configuration to deploy:"
echo "  NEXT_PUBLIC_API_URL: $NEXT_PUBLIC_API_URL"
echo "  AUTH0_BASE_URL: $AUTH0_BASE_URL"
echo "  AUTH0_ISSUER_BASE_URL: $AUTH0_ISSUER_BASE_URL"
echo "  AUTH0_CLIENT_ID: $AUTH0_CLIENT_ID"
echo "  AUTH0_AUDIENCE: $AUTH0_AUDIENCE"
echo "  AUTH0_DOMAIN: $AUTH0_DOMAIN"
echo "  AUTH0_SECRET: ******* (secret)"
echo "  AUTH0_CLIENT_SECRET: ******* (secret)"
echo "  GITHUB_CLIENT_ID: $GITHUB_CLIENT_ID"
echo "  GITHUB_CLIENT_SECRET: ******* (secret)"
echo "  NEXT_TELEMETRY_DISABLED: $NEXT_TELEMETRY_DISABLED"
echo ""

# Validate required variables
MISSING_VARS=0

if [ -z "$AUTH0_SECRET" ]; then
    echo -e "${RED}❌ AUTH0_SECRET not set in $ENV_FILE${NC}"
    MISSING_VARS=1
fi

if [ -z "$AUTH0_CLIENT_SECRET" ]; then
    echo -e "${RED}❌ AUTH0_CLIENT_SECRET not set in $ENV_FILE${NC}"
    MISSING_VARS=1
fi

if [ -z "$AUTH0_CLIENT_ID" ]; then
    echo -e "${RED}❌ AUTH0_CLIENT_ID not set in $ENV_FILE${NC}"
    MISSING_VARS=1
fi

if [ $MISSING_VARS -eq 1 ]; then
    echo ""
    echo -e "${RED}❌ Missing required variables${NC}"
    exit 1
fi

echo -e "${GREEN}✅ All required variables present${NC}"
echo ""

read -p "Deploy these secrets to Azure? (y/n) " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 1
fi

echo ""
echo -e "${CYAN}🔄 Setting secrets in Azure Container App...${NC}"
echo ""

# Step 1: Set secrets first
az containerapp secret set \
    --name "$DASHBOARD_APP_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --secrets \
        "auth0-secret=$AUTH0_SECRET" \
        "auth0-client-secret=$AUTH0_CLIENT_SECRET" \
        "github-client-secret=$GITHUB_CLIENT_SECRET" \
    --output none

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Failed to set secrets${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Secrets set successfully${NC}"
echo ""
echo -e "${CYAN}🔄 Updating environment variables...${NC}"
echo ""

# Step 2: Update environment variables to reference secrets
az containerapp update \
    --name "$DASHBOARD_APP_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --set-env-vars \
        "AUTH0_SECRET=secretref:auth0-secret" \
        "AUTH0_BASE_URL=$AUTH0_BASE_URL" \
        "AUTH0_ISSUER_BASE_URL=$AUTH0_ISSUER_BASE_URL" \
        "AUTH0_CLIENT_ID=$AUTH0_CLIENT_ID" \
        "AUTH0_CLIENT_SECRET=secretref:auth0-client-secret" \
        "AUTH0_AUDIENCE=$AUTH0_AUDIENCE" \
        "AUTH0_DOMAIN=$AUTH0_DOMAIN" \
        "NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL" \
        "NEXT_TELEMETRY_DISABLED=$NEXT_TELEMETRY_DISABLED" \
        "GITHUB_CLIENT_ID=$GITHUB_CLIENT_ID" \
        "GITHUB_CLIENT_SECRET=secretref:github-client-secret" \
    --output none

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Environment variables updated successfully${NC}"
else
    echo -e "${RED}❌ Failed to update environment variables${NC}"
    exit 1
fi

echo ""
echo -e "${CYAN}⏳ Waiting for deployment to complete...${NC}"
sleep 15

# Check deployment status
STATUS=$(az containerapp show \
    --name "$DASHBOARD_APP_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --query "properties.runningStatus" -o tsv)

REVISION=$(az containerapp revision list \
    --name "$DASHBOARD_APP_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --query "[0].name" -o tsv)

echo ""
echo "Deployment Status:"
echo "  Status: $STATUS"
echo "  Latest Revision: $REVISION"
echo ""

if [ "$STATUS" == "Running" ]; then
    echo -e "${GREEN}✅ Dashboard is running${NC}"
else
    echo -e "${YELLOW}⚠️  Dashboard status: $STATUS${NC}"
    echo ""
    echo "Check logs with:"
    echo "  az containerapp logs show --name $DASHBOARD_APP_NAME --resource-group $RESOURCE_GROUP --follow"
fi

echo ""
echo -e "${GREEN}🎉 Deployment complete!${NC}"
echo ""
echo "Next steps:"
echo "1. Test login at: https://app.sigilsec.ai/login"
echo ""
echo "2. Verify Auth0 Application Settings in Auth0 Dashboard:"
echo "   - Allowed Callback URLs: https://app.sigilsec.ai/api/auth/callback"
echo "   - Allowed Logout URLs: https://app.sigilsec.ai"
echo "   - Allowed Web Origins: https://app.sigilsec.ai"
echo ""
echo "3. Monitor logs:"
echo "   az containerapp logs show --name $DASHBOARD_APP_NAME --resource-group $RESOURCE_GROUP --follow"
echo ""
echo "4. Verify configuration:"
echo "   ./scripts/get_azure_auth0_config.sh"
