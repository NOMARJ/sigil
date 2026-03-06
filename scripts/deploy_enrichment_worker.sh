#!/bin/bash
set -e

# Deploy Sigil Forge Enrichment Worker to Azure Container Apps
# Usage: ./scripts/deploy_enrichment_worker.sh [environment]

ENVIRONMENT=${1:-production}
RESOURCE_GROUP="sigil-rg"
CONTAINER_APP_ENV="sigil-env-46iy6y"
ACR_NAME="sigilacr46iy6y"
APP_NAME="sigil-forge-enrichment"

echo "🚀 Deploying Forge Enrichment Worker to Azure Container Apps"
echo "Environment: $ENVIRONMENT"
echo "Resource Group: $RESOURCE_GROUP"
echo "Container App Environment: $CONTAINER_APP_ENV"

# Get the latest bot image tag
echo "📦 Getting latest bot image tag..."
LATEST_TAG=$(az acr repository show-tags --name $ACR_NAME --repository sigil-bot --orderby time_desc --top 1 --query "[0]" -o tsv)
IMAGE_URI="$ACR_NAME.azurecr.io/sigil-bot:$LATEST_TAG"

echo "Using image: $IMAGE_URI"

# Get existing secrets from the bot-workers container app
echo "🔐 Retrieving database and Redis configuration..."
DATABASE_URL=$(az containerapp secret show --name sigil-bot-workers --resource-group $RESOURCE_GROUP --secret-name "bot-database-url" --query "value" -o tsv 2>/dev/null || echo "")
REDIS_URL=$(az containerapp secret show --name sigil-bot-workers --resource-group $RESOURCE_GROUP --secret-name "bot-redis-url" --query "value" -o tsv 2>/dev/null || echo "")

if [ -z "$DATABASE_URL" ] || [ -z "$REDIS_URL" ]; then
    echo "❌ Error: Could not retrieve database or Redis URLs from existing container apps"
    echo "Please ensure the sigil-bot-workers container app is deployed with secrets"
    exit 1
fi

echo "✅ Retrieved configuration secrets"

# Check if container app already exists
APP_EXISTS=$(az containerapp show --name $APP_NAME --resource-group $RESOURCE_GROUP --query "name" -o tsv 2>/dev/null || echo "")

if [ -n "$APP_EXISTS" ]; then
    echo "📝 Updating existing container app: $APP_NAME"
    
    # Update the container app
    az containerapp update \
        --name $APP_NAME \
        --resource-group $RESOURCE_GROUP \
        --image $IMAGE_URI \
        --set-env-vars \
            "SIGIL_BOT_FORGE_ENRICHMENT_ENABLED=true" \
            "SIGIL_BOT_FORGE_ENRICHMENT_BATCH_SIZE=25" \
            "SIGIL_BOT_FORGE_ENRICHMENT_DELAY=2.0" \
            "SIGIL_BOT_FORGE_ENRICHMENT_MAX_RECORDS=5000" \
            "SIGIL_BOT_FORGE_ENRICHMENT_POLL_INTERVAL=300" \
            "PYTHONPATH=/app" \
        --output none

else
    echo "🆕 Creating new container app: $APP_NAME"
    
    # Get ACR admin password from existing container app
    ACR_PASSWORD=$(az containerapp secret show --name sigil-bot-workers --resource-group $RESOURCE_GROUP --secret-name acr-password --query value -o tsv)
    
    # Create the container app
    az containerapp create \
        --name $APP_NAME \
        --resource-group $RESOURCE_GROUP \
        --environment $CONTAINER_APP_ENV \
        --image $IMAGE_URI \
        --target-port 8080 \
        --ingress external \
        --command "python" "/app/scripts/enrichment_worker_service.py" \
        --cpu 0.75 \
        --memory 1.5Gi \
        --min-replicas 1 \
        --max-replicas 2 \
        --registry-server $ACR_NAME.azurecr.io \
        --registry-username $ACR_NAME \
        --registry-password $ACR_PASSWORD \
        --secrets \
            "database-url=$DATABASE_URL" \
            "redis-url=$REDIS_URL" \
        --env-vars \
            "SIGIL_BOT_DATABASE_URL=secretref:database-url" \
            "SIGIL_DATABASE_URL=secretref:database-url" \
            "SIGIL_BOT_REDIS_URL=secretref:redis-url" \
            "SIGIL_BOT_FORGE_ENRICHMENT_ENABLED=true" \
            "SIGIL_BOT_FORGE_ENRICHMENT_BATCH_SIZE=25" \
            "SIGIL_BOT_FORGE_ENRICHMENT_DELAY=2.0" \
            "SIGIL_BOT_FORGE_ENRICHMENT_MAX_RECORDS=5000" \
            "SIGIL_BOT_FORGE_ENRICHMENT_POLL_INTERVAL=300" \
            "PYTHONPATH=/app" \
        --output none
fi

echo "⏳ Waiting for deployment to complete..."
sleep 10

# Check deployment status
STATUS=$(az containerapp show --name $APP_NAME --resource-group $RESOURCE_GROUP --query "properties.runningStatus" -o tsv)
LATEST_REVISION=$(az containerapp revision list --name $APP_NAME --resource-group $RESOURCE_GROUP --query "[0].name" -o tsv)

echo "✅ Deployment completed!"
echo "Status: $STATUS"
echo "Latest Revision: $LATEST_REVISION"

# Get the container app URL
APP_URL=$(az containerapp show --name $APP_NAME --resource-group $RESOURCE_GROUP --query "properties.configuration.ingress.fqdn" -o tsv)
if [ -n "$APP_URL" ]; then
    echo "🌐 Container App URL: https://$APP_URL"
fi

echo ""
echo "📊 Container App Details:"
az containerapp show --name $APP_NAME --resource-group $RESOURCE_GROUP --query "{
    name: name,
    status: properties.runningStatus,
    image: properties.template.containers[0].image,
    replicas: properties.template.scale.minReplicas,
    cpu: properties.template.containers[0].resources.cpu,
    memory: properties.template.containers[0].resources.memory
}" -o table

echo ""
echo "🎉 Forge Enrichment Worker deployed successfully!"
echo ""
echo "Next steps:"
echo "1. Monitor logs: az containerapp logs show --name $APP_NAME --resource-group $RESOURCE_GROUP --follow"
echo "2. Check status: az containerapp show --name $APP_NAME --resource-group $RESOURCE_GROUP --query 'properties.runningStatus'"
echo "3. Monitor progress: Use the monitoring script in the deployed container"
echo ""
echo "To monitor enrichment progress:"
echo "az containerapp exec --name $APP_NAME --resource-group $RESOURCE_GROUP --command 'python scripts/monitor_forge_enrichment.py'"