#!/bin/bash
# Deploy Sigil Dashboard with Supabase Auth to Azure Container Apps

set -e

# Configuration
RESOURCE_GROUP="sigil-rg"
ACR_NAME="sigilacrhoqms2"
CONTAINER_APP="sigil-dashboard-v2"
IMAGE_TAG="supabase-auth-$(git rev-parse --short HEAD)"

# Supabase configuration
SUPABASE_URL="https://pjjelfyuplqjgljvuybr.supabase.co"
SUPABASE_ANON_KEY="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InBqamVsZnl1cGxxamdsanZ1eWJyIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzE0NDYyMzUsImV4cCI6MjA4NzAyMjIzNX0.BNjx-iRbvRnHZWaNTNe9F_RqBmtNbSntFGA0Wpb7d3o"

echo "🚀 Deploying Sigil Dashboard with Supabase Auth"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Image tag: $IMAGE_TAG"
echo ""

# Step 1: Build and push Docker image
echo "📦 Building Docker image..."
cd dashboard
az acr build \
  --registry "$ACR_NAME" \
  --image "sigil-dashboard:$IMAGE_TAG" \
  --file Dockerfile \
  --build-arg NEXT_PUBLIC_API_URL=https://api.sigilsec.ai \
  --build-arg NEXT_PUBLIC_SUPABASE_URL="$SUPABASE_URL" \
  --build-arg NEXT_PUBLIC_SUPABASE_ANON_KEY="$SUPABASE_ANON_KEY" \
  .

echo ""
echo "✅ Image built and pushed to ACR"

# Step 2: Update Container App
echo ""
echo "🔄 Updating Container App..."
az containerapp update \
  --name "$CONTAINER_APP" \
  --resource-group "$RESOURCE_GROUP" \
  --image "$ACR_NAME.azurecr.io/sigil-dashboard:$IMAGE_TAG"

echo ""
echo "✅ Deployment complete!"
echo ""
echo "🌐 Dashboard URL: https://app.sigilsec.ai"
echo ""
echo "To rollback, run:"
echo "  az containerapp update --name $CONTAINER_APP --resource-group $RESOURCE_GROUP --image $ACR_NAME.azurecr.io/sigil-dashboard:prod"
