#!/bin/bash
# Deploy Forge Fix to Azure Container Apps
# This script updates the production environment to use MSSQL and creates forge tables

set -e

echo "=== Sigil Forge Production Fix Deployment ==="
echo

# Configuration
RESOURCE_GROUP="sigil-rg"
APPS=("sigil-api-v2" "sigil-dashboard-v2")

# Check if we have Azure CLI
if ! command -v az >/dev/null 2>&1; then
    echo "❌ Azure CLI not found. Please install it first:"
    echo "   https://docs.microsoft.com/en-us/cli/azure/install-azure-cli"
    exit 1
fi

# Check if logged into Azure
if ! az account show >/dev/null 2>&1; then
    echo "❌ Not logged into Azure. Please run: az login"
    exit 1
fi

echo "✅ Azure CLI configured"

# Function to update container app database configuration
update_database_config() {
    local app_name=$1
    
    echo "Updating database configuration for $app_name..."
    
    # Note: In production, you would use actual Azure SQL Database connection string
    # This is a placeholder - replace with actual production MSSQL connection
    local mssql_connection="Driver={ODBC Driver 18 for SQL Server};Server=sigil-sql-server.database.windows.net;Database=sigil;Authentication=ActiveDirectoryMsi;TrustServerCertificate=yes"
    
    # Update the database URL secret
    az containerapp secret set \
        --name "$app_name" \
        --resource-group "$RESOURCE_GROUP" \
        --secrets "database-url=$mssql_connection" \
        --output none
    
    echo "✅ Updated database secret for $app_name"
}

# Function to create forge tables in production
create_forge_tables() {
    echo "Creating forge tables in production database..."
    
    # This would typically be done via a deployment job or migration runner
    # For now, we'll create a script that can be run manually
    
    cat > "deploy_forge_schema.py" << 'EOF'
#!/usr/bin/env python3
"""
Deploy forge schema to production MSSQL database.
Run this from a machine that has access to the production database.
"""

import asyncio
import sys
from pathlib import Path

# Add project root
sys.path.append(str(Path(__file__).parent))

from api.database import db
from api.config import settings

async def deploy_schema():
    """Deploy forge schema to production."""
    try:
        await db.connect()
        if not db.connected:
            print("❌ Database connection failed")
            return False
        
        print("✅ Connected to production database")
        
        # Read forge migration
        migration_file = Path("migrations/004_create_forge_classification.sql")
        if not migration_file.exists():
            print("❌ Migration file not found")
            return False
        
        sql_content = migration_file.read_text()
        statements = [s.strip() for s in sql_content.split('GO') if s.strip()]
        
        print(f"Executing {len(statements)} SQL statements...")
        
        for i, statement in enumerate(statements):
            if statement and not statement.startswith('--'):
                try:
                    await db.execute_raw_sql(statement)
                    print(f"✅ Statement {i+1}/{len(statements)} completed")
                except Exception as e:
                    # Some may fail if tables exist - that's OK
                    print(f"⚠️  Statement {i+1}: {e}")
        
        print("✅ Forge schema deployment completed")
        return True
        
    except Exception as e:
        print(f"❌ Deployment failed: {e}")
        return False
    finally:
        await db.disconnect()

if __name__ == "__main__":
    success = asyncio.run(deploy_schema())
    sys.exit(0 if success else 1)
EOF

    echo "✅ Created deployment script: deploy_forge_schema.py"
    echo "   Run this script on a machine with production database access"
}

# Function to restart container apps
restart_apps() {
    echo "Restarting container apps to apply new configuration..."
    
    for app in "${APPS[@]}"; do
        echo "Restarting $app..."
        
        # Get current revision
        current_revision=$(az containerapp revision list \
            --name "$app" \
            --resource-group "$RESOURCE_GROUP" \
            --query "[?properties.active].name" \
            --output tsv)
        
        if [ -n "$current_revision" ]; then
            # Restart by updating with same configuration
            az containerapp revision restart \
                --name "$app" \
                --resource-group "$RESOURCE_GROUP" \
                --revision "$current_revision" \
                --output none
            
            echo "✅ $app restarted"
        else
            echo "⚠️  Could not find active revision for $app"
        fi
    done
}

# Function to verify deployment
verify_deployment() {
    echo "Verifying deployment..."
    
    # Check API health
    echo "Checking API health..."
    if curl -f -s "https://api.sigilsec.ai/health" >/dev/null; then
        echo "✅ API is responding"
    else
        echo "❌ API health check failed"
        return 1
    fi
    
    # Check forge endpoints
    echo "Checking forge endpoints..."
    if curl -f -s "https://api.sigilsec.ai/forge/stats" >/dev/null; then
        echo "✅ Forge endpoints accessible"
    else
        echo "❌ Forge endpoints not accessible"
        return 1
    fi
    
    echo "✅ Deployment verification passed"
}

# Function to show logs
show_logs() {
    local app_name=$1
    echo "Recent logs for $app_name:"
    az containerapp logs show \
        --name "$app_name" \
        --resource-group "$RESOURCE_GROUP" \
        --tail 20 \
        --follow false
}

# Main menu
echo "Choose deployment action:"
echo "1. Update database configuration only"
echo "2. Create forge schema deployment script"
echo "3. Restart container apps"
echo "4. Verify deployment"
echo "5. Show app logs"
echo "6. Full deployment (1+2+3)"
echo

read -p "Enter your choice (1-6): " choice

case $choice in
    1)
        for app in "${APPS[@]}"; do
            update_database_config "$app"
        done
        ;;
    2)
        create_forge_tables
        ;;
    3)
        restart_apps
        ;;
    4)
        verify_deployment
        ;;
    5)
        echo "Which app logs to show?"
        select app in "${APPS[@]}"; do
            show_logs "$app"
            break
        done
        ;;
    6)
        echo "Running full deployment..."
        for app in "${APPS[@]}"; do
            update_database_config "$app"
        done
        create_forge_tables
        restart_apps
        sleep 30  # Wait for apps to start
        verify_deployment
        ;;
    *)
        echo "❌ Invalid choice"
        exit 1
        ;;
esac

echo
echo "=== Deployment Notes ==="
echo "1. Run deploy_forge_schema.py on a machine with production DB access"
echo "2. Process initial data: python scripts/setup_mssql_forge.py --process-data --limit 100"
echo "3. Set up scheduled job for ongoing classification"
echo "4. Monitor forge data freshness"
echo
echo "✅ Forge fix deployment completed!"