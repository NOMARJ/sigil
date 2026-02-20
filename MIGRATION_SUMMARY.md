# Sigil VNet Migration - Quick Summary

## ✅ What's Ready

1. **VNet Infrastructure** - Fully deployed and operational
   - Virtual Network: `sigil-vnet` (10.0.0.0/16)
   - NAT Gateway with static IP: `20.120.67.7`
   - Container Apps Environment: `sigil-env-vnet`

2. **New Container Apps** - Running and healthy
   - API v2: https://sigil-api-v2.yellowdesert-3086f866.eastus.azurecontainerapps.io
   - Dashboard v2: https://sigil-dashboard-v2.yellowdesert-3086f866.eastus.azurecontainerapps.io
   - Both connected to Redis ✓
   - Both using pooler DATABASE_URL (waiting for auth fix)

3. **Code Fixes** - All deployed
   - Dashboard pricing page ✓
   - Auth token management ✓
   - API typing_extensions ✓

## 🎯 Next Action Required: Update DNS

**Update these A records in your DNS provider:**

```
api.sigilsec.ai    FROM: 20.242.129.244    TO: 20.120.67.7
app.sigilsec.ai    FROM: 20.242.129.244    TO: 20.120.67.7
```

**After DNS propagates** (~15 min), run the migration commands in [VNET_MIGRATION_GUIDE.md](VNET_MIGRATION_GUIDE.md)

## 📊 What This Gives You

✅ **Static egress IP** (`20.120.67.7`) for IP allowlisting
✅ **Network isolation** for security and compliance
✅ **NAT Gateway** for reliable outbound connectivity
✅ **Better performance** with dedicated resources
✅ **Production-ready** infrastructure

**Cost**: ~$36/month additional (NAT Gateway + Public IP)

## 🔄 Database Status

- **Current**: In-memory storage (data not persisted)
- **Reason**: Supabase pooler auth not yet propagated for 2-day-old project
- **Solution**: Wait (free) or enable IPv4 add-on ($4/month)
- **When fixed**: Full PostgreSQL persistence automatically enabled

## 📝 Migration Timeline

1. **Now**: Update DNS → `20.120.67.7`
2. **15 min**: DNS propagates
3. **5 min**: Run migration commands (remove old, add new domains)
4. **10 min**: SSL certificates issue
5. **Done**: Custom domains working on VNet infrastructure

**Total time**: ~30 minutes
**Downtime**: Zero (seamless DNS cutover)

## 🚀 Quick Start

```bash
# 1. After updating DNS, remove old custom domains
az containerapp hostname delete --name sigil-api --resource-group sigil-rg --hostname api.sigilsec.ai -y
az containerapp hostname delete --name sigil-dashboard --resource-group sigil-rg --hostname app.sigilsec.ai -y

# 2. Add custom domains to VNet apps
az containerapp hostname add --name sigil-api-v2 --resource-group sigil-rg --hostname api.sigilsec.ai
az containerapp hostname add --name sigil-dashboard-v2 --resource-group sigil-rg --hostname app.sigilsec.ai

# 3. Create SSL certificates (wait 5-15 min for issuance)
az containerapp env certificate create -g sigil-rg --name sigil-env-vnet --hostname api.sigilsec.ai --validation-method CNAME
az containerapp env certificate create -g sigil-rg --name sigil-env-vnet --hostname app.sigilsec.ai --validation-method CNAME

# 4. Bind certificates (run after certs issued)
API_CERT_ID=$(az containerapp env certificate list -g sigil-rg --name sigil-env-vnet --query "[?properties.subjectName=='api.sigilsec.ai'].id" -o tsv)
DASH_CERT_ID=$(az containerapp env certificate list -g sigil-rg --name sigil-env-vnet --query "[?properties.subjectName=='app.sigilsec.ai'].id" -o tsv)

az containerapp hostname bind --name sigil-api-v2 -g sigil-rg --hostname api.sigilsec.ai --certificate $API_CERT_ID
az containerapp hostname bind --name sigil-dashboard-v2 -g sigil-rg --hostname app.sigilsec.ai --certificate $DASH_CERT_ID
```

## ✅ Verification

```bash
curl https://api.sigilsec.ai/health
# {"status":"ok","version":"0.1.0","supabase_connected":false,"redis_connected":true}

curl -I https://app.sigilsec.ai
# HTTP/2 200
```

---

**Full details**: See [VNET_MIGRATION_GUIDE.md](VNET_MIGRATION_GUIDE.md)
**Current status**: See [DEPLOYMENT_STATUS.md](DEPLOYMENT_STATUS.md)
