# VNet Migration Guide

## Overview

Migrating from basic Azure Container Apps to VNet-integrated infrastructure for better network isolation, static egress IP, and reliable outbound connectivity.

## Current Status

✅ **VNet infrastructure deployed** by cloud-architect team
✅ **New container apps running**:
  - `sigil-api-v2` at https://sigil-api-v2.yellowdesert-3086f866.eastus.azurecontainerapps.io
  - `sigil-dashboard-v2` at https://sigil-dashboard-v2.yellowdesert-3086f866.eastus.azurecontainerapps.io
✅ **DATABASE_URL configured** with Supabase pooler (waiting for auth propagation)
✅ **Health checks passing**: Both apps healthy with Redis connected

## DNS Update Required

### Current DNS Configuration
```
api.sigilsec.ai  →  20.242.129.244  (old environment)
app.sigilsec.ai  →  20.242.129.244  (old environment)
```

### New DNS Configuration
```
api.sigilsec.ai  →  20.120.67.7  (VNet environment)
app.sigilsec.ai  →  20.120.67.7  (VNet environment)
```

**Action Required**: Update your DNS A records to point to `20.120.67.7`

## Migration Steps

### Step 1: Update DNS (DO THIS FIRST)

Update the following A records in your DNS provider:

| Record Type | Hostname | Current IP | New IP |
|-------------|----------|------------|---------|
| A | api.sigilsec.ai | 20.242.129.244 | **20.120.67.7** |
| A | app.sigilsec.ai | 20.242.129.244 | **20.120.67.7** |

**DNS Propagation**: 5-60 minutes (usually ~15 minutes)

### Step 2: Wait for DNS Propagation

Monitor DNS propagation:
```bash
# Check DNS from your location
nslookup api.sigilsec.ai
nslookup app.sigilsec.ai

# Should show: 20.120.67.7
```

### Step 3: Remove Custom Domains from Old Apps

**⚠️ Only do this AFTER DNS has propagated to avoid downtime**

```bash
# Remove API domain from old app
az containerapp hostname delete \
  --name sigil-api \
  --resource-group sigil-rg \
  --hostname api.sigilsec.ai \
  -y

# Remove Dashboard domain from old app
az containerapp hostname delete \
  --name sigil-dashboard \
  --resource-group sigil-rg \
  --hostname app.sigilsec.ai \
  -y
```

### Step 4: Add Custom Domains to VNet Apps

```bash
# Add API domain to VNet app
az containerapp hostname add \
  --name sigil-api-v2 \
  --resource-group sigil-rg \
  --hostname api.sigilsec.ai

# Add Dashboard domain to VNet app
az containerapp hostname add \
  --name sigil-dashboard-v2 \
  --resource-group sigil-rg \
  --hostname app.sigilsec.ai
```

### Step 5: Create Managed SSL Certificates

```bash
# Create API certificate
az containerapp env certificate create \
  -g sigil-rg \
  --name sigil-env-vnet \
  --hostname api.sigilsec.ai \
  --validation-method CNAME

# Create Dashboard certificate
az containerapp env certificate create \
  -g sigil-rg \
  --name sigil-env-vnet \
  --hostname app.sigilsec.ai \
  --validation-method CNAME
```

**Wait**: Certificate issuance takes 5-15 minutes

### Step 6: Bind SSL Certificates

```bash
# Get certificate IDs
API_CERT_ID=$(az containerapp env certificate list \
  -g sigil-rg \
  --name sigil-env-vnet \
  --query "[?properties.subjectName=='api.sigilsec.ai'].id" \
  -o tsv)

DASH_CERT_ID=$(az containerapp env certificate list \
  -g sigil-rg \
  --name sigil-env-vnet \
  --query "[?properties.subjectName=='app.sigilsec.ai'].id" \
  -o tsv)

# Bind certificates
az containerapp hostname bind \
  --name sigil-api-v2 \
  -g sigil-rg \
  --hostname api.sigilsec.ai \
  --certificate $API_CERT_ID

az containerapp hostname bind \
  --name sigil-dashboard-v2 \
  -g sigil-rg \
  --hostname app.sigilsec.ai \
  --certificate $DASH_CERT_ID
```

### Step 7: Verify Migration

```bash
# Test API health
curl https://api.sigilsec.ai/health

# Expected response:
# {"status":"ok","version":"0.1.0","supabase_connected":false,"redis_connected":true}

# Test Dashboard (should return 200)
curl -I https://app.sigilsec.ai
```

### Step 8: Monitor and Decommission Old Apps (Optional)

After 24-48 hours of stable operation:

```bash
# Scale down old apps to 0 (saves costs)
az containerapp update \
  --name sigil-api \
  --resource-group sigil-rg \
  --min-replicas 0 \
  --max-replicas 0

az containerapp update \
  --name sigil-dashboard \
  --resource-group sigil-rg \
  --min-replicas 0 \
  --max-replicas 0

# Or delete old apps entirely
# az containerapp delete --name sigil-api --resource-group sigil-rg -y
# az containerapp delete --name sigil-dashboard --resource-group sigil-rg -y
```

## VNet Infrastructure Benefits

### ✅ Network Isolation
- Apps run in dedicated virtual network (`sigil-vnet` - 10.0.0.0/16)
- Subnet dedicated to Container Apps (`10.0.0.0/23`)
- Delegated to `Microsoft.App/environments`

### ✅ Static Egress IP
- **NAT Gateway IP**: `20.120.67.7`
- Use for IP allowlisting with external services
- Consistent outbound IP for all apps

### ✅ Reliable Outbound Connectivity
- NAT Gateway provides reliable SNAT
- No shared infrastructure bottlenecks
- 10-minute idle timeout

### ✅ Better Security
- Network Security Groups (can be added)
- Private endpoints (can be configured)
- Traffic isolation

### ✅ Scalability
- Dedicated resources
- Better performance under load

## Database Connection Status

**Current**: Using Supabase connection pooler (IPv4 compatible with Azure)
**Status**: ⚠️ "Tenant or user not found" - waiting for Supabase auth propagation
**Impact**: API uses in-memory storage until pooler auth works

**When pooler authentication is fixed**:
- Full PostgreSQL persistence
- All data saved
- Production-ready

**Connection String**:
```
postgresql://postgres.pjjelfyuplqjgljvuybr:***@aws-0-us-east-1.pooler.supabase.com:6543/postgres
```

## Rollback Plan

If issues occur during migration:

1. **Revert DNS**:
   ```
   api.sigilsec.ai  →  20.242.129.244
   app.sigilsec.ai  →  20.242.129.244
   ```

2. **Keep old apps running**: Don't delete until VNet apps are verified

3. **Old apps remain functional**: They're still running and healthy

## Cost Impact

| Item | Monthly Cost |
|------|--------------|
| VNet | Free |
| Subnet | Free |
| NAT Gateway | ~$32/month |
| Static Public IP | ~$3.65/month |
| **Total Additional** | **~$36/month** |

**Note**: The network isolation and reliability benefits typically outweigh the cost for production workloads.

## Testing Before Migration

Test the VNet apps directly (without custom domains):

```bash
# API
curl https://sigil-api-v2.yellowdesert-3086f866.eastus.azurecontainerapps.io/health

# Dashboard
curl -I https://sigil-dashboard-v2.yellowdesert-3086f866.eastus.azurecontainerapps.io
```

Both should return healthy responses.

## Timeline

- **DNS Update**: ~15 minutes propagation
- **Certificate Creation**: 5-15 minutes
- **Total Migration Time**: ~30-45 minutes
- **Downtime**: None (DNS cutover is seamless)

## Support

If you encounter issues:

1. Check container app logs:
   ```bash
   az containerapp logs show --name sigil-api-v2 --resource-group sigil-rg --tail 50
   ```

2. Verify DNS propagation:
   ```bash
   nslookup api.sigilsec.ai
   ```

3. Check certificate status:
   ```bash
   az containerapp env certificate list -g sigil-rg --name sigil-env-vnet -o table
   ```

## Next Steps After Migration

Once database connectivity is restored (pooler auth fixed):

1. ✅ Full persistence enabled
2. ✅ Production-ready infrastructure
3. ✅ Static egress IP for partner integrations
4. ✅ Network isolation for compliance
5. ✅ Scalable foundation for growth

---

**Ready to migrate?** Start with Step 1: Update your DNS records to point to `20.120.67.7`
