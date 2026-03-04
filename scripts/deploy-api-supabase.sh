#!/bin/bash
# Deploy Sigil API with Supabase Auth support to Azure Container Apps

set -e

# Configuration
RESOURCE_GROUP="sigil-rg"
ACR_NAME="sigilacrhoqms2"
CONTAINER_APP="sigil-api"
IMAGE_TAG="supabase-auth-$(git rev-parse --short HEAD)"

echo "🚀 Deploying Sigil API with Supabase Auth Support"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Image tag: $IMAGE_TAG"
echo ""

# Prompt for JWT secret if not set
if [ -z "$SUPABASE_JWT_SECRET" ]; then
  echo "⚠️  SUPABASE_JWT_SECRET not set in environment"
  echo "Please get it from: https://supabase.com/dashboard/project/pjjelfyuplqjgljvuybr/settings/api"
  echo ""
  read -p "Enter Supabase JWT Secret (or press Enter to skip): " jwt_secret
  if [ -n "$jwt_secret" ]; then
    SUPABASE_JWT_SECRET="$jwt_secret"
  fi
fi

# Step 1: Build and push Docker image
echo "📦 Building Docker image..."
cd api
az acr build \
  --registry "$ACR_NAME" \
  --image "sigil-api:$IMAGE_TAG" \
  --file Dockerfile \
  .

echo ""
echo "✅ Image built and pushed to ACR"

# Step 2: Update secrets (if JWT secret provided)
if [ -n "$SUPABASE_JWT_SECRET" ]; then
  echo ""
  echo "🔐 Updating Supabase Auth secrets..."
  az containerapp secret set \
    --name "$CONTAINER_APP" \
    --resource-group "$RESOURCE_GROUP" \
    --secrets \
      "sigil-supabase-url=https://pjjelfyuplqjgljvuybr.supabase.co" \
      "sigil-supabase-jwt-secret=$SUPABASE_JWT_SECRET"

  echo ""
  echo "🔧 Updating environment variables..."
  az containerapp update \
    --name "$CONTAINER_APP" \
    --resource-group "$RESOURCE_GROUP" \
    --set-env-vars \
      "SIGIL_SUPABASE_URL=secretref:sigil-supabase-url" \
      "SIGIL_SUPABASE_JWT_SECRET=secretref:sigil-supabase-jwt-secret"
fi

# Step 3: Update Container App image
echo ""
echo "🔄 Updating Container App image..."
az containerapp update \
  --name "$CONTAINER_APP" \
  --resource-group "$RESOURCE_GROUP" \
  --image "$ACR_NAME.azurecr.io/sigil-api:$IMAGE_TAG"

echo ""
echo "✅ Deployment complete!"
echo ""
echo "🌐 API URL: https://api.sigilsec.ai"
echo ""
echo "📊 Test the API:"
echo "  curl https://api.sigilsec.ai/health"
echo ""
echo "To rollback, run:"
echo "  az containerapp update --name $CONTAINER_APP --resource-group $RESOURCE_GROUP --image $ACR_NAME.azurecr.io/sigil-api:a675c5c"
