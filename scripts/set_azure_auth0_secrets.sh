#!/bin/bash
# Set Auth0 secrets in Azure Container Apps for Sigil Dashboard
# Usage: ./scripts/set_azure_auth0_secrets.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
RESOURCE_GROUP="sigil-rg"
DASHBOARD_APP_NAME="sigil-dashboard"

echo "🔐 Setting Auth0 secrets for Sigil Dashboard in Azure"
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

# Prompt for Auth0 secrets
echo "Enter Auth0 configuration values:"
echo ""

# AUTH0_SECRET
echo -e "${YELLOW}AUTH0_SECRET${NC} (generate with: openssl rand -hex 32)"
read -p "Enter AUTH0_SECRET: " AUTH0_SECRET
if [ -z "$AUTH0_SECRET" ]; then
    echo -e "${RED}❌ AUTH0_SECRET is required${NC}"
    exit 1
fi

# AUTH0_CLIENT_SECRET
echo ""
echo -e "${YELLOW}AUTH0_CLIENT_SECRET${NC} (from Auth0 Dashboard → Applications → Sigil Dashboard → Settings)"
read -p "Enter AUTH0_CLIENT_SECRET: " AUTH0_CLIENT_SECRET
if [ -z "$AUTH0_CLIENT_SECRET" ]; then
    echo -e "${RED}❌ AUTH0_CLIENT_SECRET is required${NC}"
    exit 1
fi

echo ""
echo "Using the following configuration:"
echo "  AUTH0_BASE_URL: https://app.sigilsec.ai"
echo "  AUTH0_ISSUER_BASE_URL: https://auth.sigilsec.ai"
echo "  AUTH0_CLIENT_ID: WzNmPGqml7IKSAcSCwz8lhwyv383CKfq"
echo "  AUTH0_AUDIENCE: https://api.sigilsec.ai"
echo "  NEXT_PUBLIC_API_URL: https://api.sigilsec.ai"
echo ""

read -p "Continue with these values? (y/n) " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 1
fi

echo ""
echo "🔄 Updating container app secrets..."

# Update container app with Auth0 configuration
az containerapp update \
    --name "$DASHBOARD_APP_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --set-env-vars \
        "AUTH0_SECRET=secretref:auth0-secret" \
        "AUTH0_BASE_URL=https://app.sigilsec.ai" \
        "AUTH0_ISSUER_BASE_URL=https://auth.sigilsec.ai" \
        "AUTH0_CLIENT_ID=WzNmPGqml7IKSAcSCwz8lhwyv383CKfq" \
        "AUTH0_CLIENT_SECRET=secretref:auth0-client-secret" \
        "AUTH0_AUDIENCE=https://api.sigilsec.ai" \
        "NEXT_PUBLIC_API_URL=https://api.sigilsec.ai" \
        "NEXT_TELEMETRY_DISABLED=1" \
    --secrets \
        "auth0-secret=$AUTH0_SECRET" \
        "auth0-client-secret=$AUTH0_CLIENT_SECRET" \
    --output none

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Secrets updated successfully${NC}"
else
    echo -e "${RED}❌ Failed to update secrets${NC}"
    exit 1
fi

echo ""
echo "⏳ Waiting for deployment to complete..."
sleep 10

# Check deployment status
STATUS=$(az containerapp show \
    --name "$DASHBOARD_APP_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --query "properties.runningStatus" -o tsv)

echo "Current status: $STATUS"

if [ "$STATUS" == "Running" ]; then
    echo -e "${GREEN}✅ Dashboard is running${NC}"
else
    echo -e "${YELLOW}⚠️  Dashboard status: $STATUS${NC}"
    echo "Check logs with:"
    echo "  az containerapp logs show --name $DASHBOARD_APP_NAME --resource-group $RESOURCE_GROUP --follow"
fi

echo ""
echo "🎉 Auth0 configuration complete!"
echo ""
echo "Next steps:"
echo "1. Verify Auth0 Application Settings in Auth0 Dashboard:"
echo "   - Allowed Callback URLs: https://app.sigilsec.ai/api/auth/callback"
echo "   - Allowed Logout URLs: https://app.sigilsec.ai"
echo "   - Allowed Web Origins: https://app.sigilsec.ai"
echo ""
echo "2. Test login at: https://app.sigilsec.ai/login"
echo ""
echo "3. Monitor logs:"
echo "   az containerapp logs show --name $DASHBOARD_APP_NAME --resource-group $RESOURCE_GROUP --follow"
echo ""
echo "4. Check deployment:"
echo "   az containerapp show --name $DASHBOARD_APP_NAME --resource-group $RESOURCE_GROUP"
