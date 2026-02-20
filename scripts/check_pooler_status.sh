#!/bin/bash
#
# Check Supabase Connection Pooler Status
# Run this periodically to monitor when the pooler auth starts working
#

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== Supabase Pooler Status Check ===${NC}"
echo ""

# Check API v2 (VNet) health
echo -e "${YELLOW}Checking API v2 (VNet) health...${NC}"
HEALTH=$(curl -s https://sigil-api-v2.yellowdesert-3086f866.eastus.azurecontainerapps.io/health)
echo "$HEALTH"

# Parse the response
SUPABASE_CONNECTED=$(echo "$HEALTH" | grep -o '"supabase_connected":[^,}]*' | cut -d':' -f2)
REDIS_CONNECTED=$(echo "$HEALTH" | grep -o '"redis_connected":[^,}]*' | cut -d':' -f2)

echo ""
echo -e "${YELLOW}Connection Status:${NC}"
if [ "$SUPABASE_CONNECTED" = "true" ]; then
  echo -e "  Database: ${GREEN}✓ CONNECTED${NC}"
  echo ""
  echo -e "${GREEN}🎉 SUCCESS! Supabase pooler is now working!${NC}"
  echo ""
  echo "Next steps:"
  echo "1. Migrate custom domains to VNet apps (see MIGRATION_SUMMARY.md)"
  echo "2. Verify all functionality with database persistence"
  echo "3. Decommission old apps after 24-48 hours of stable operation"
else
  echo -e "  Database: ${RED}✗ NOT CONNECTED (in-memory storage)${NC}"
  echo ""
  echo "This is expected. Supabase pooler auth is still propagating."
  echo "Your project is only 2 days old - typically resolves within a few days."
fi

if [ "$REDIS_CONNECTED" = "true" ]; then
  echo -e "  Redis:    ${GREEN}✓ CONNECTED${NC}"
else
  echo -e "  Redis:    ${RED}✗ NOT CONNECTED${NC}"
fi

echo ""
echo -e "${YELLOW}Recent API logs:${NC}"
az containerapp logs show \
  --name sigil-api-v2 \
  --resource-group sigil-rg \
  --type console \
  --follow false \
  --tail 10 2>&1 | grep -E "(AsyncpgClient|connection|ERROR)" | tail -5 || echo "No database connection errors in recent logs"

echo ""
echo -e "${YELLOW}Alternative: Enable IPv4 Add-on${NC}"
echo "If you need database persistence immediately:"
echo "1. Go to: https://supabase.com/dashboard/project/pjjelfyuplqjgljvuybr/settings/addons"
echo "2. Enable 'Dedicated IPv4 Address' (\$4/month)"
echo "3. Update DATABASE_URL to use direct connection"
echo ""
echo "Run this script periodically: ./scripts/check_pooler_status.sh"
