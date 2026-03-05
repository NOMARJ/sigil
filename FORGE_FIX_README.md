# Sigil Forge Database Fix

## Quick Fix Summary

The Sigil Forge endpoints are returning empty data because the system is in an incomplete migration state from Supabase (PostgreSQL) to Azure SQL Database (MSSQL).

## Root Cause

1. **Environment Configuration**: Still pointing to Supabase instead of MSSQL
2. **Missing Tables**: Forge tables don't exist in the MSSQL database
3. **No Data Processing**: No workers running to classify data from `public_scans` into forge tables

## Quick Fix for Development

### Option 1: Local Development with Docker MSSQL

```bash
# 1. Set up local MSSQL environment
./scripts/configure_dev_mssql.sh

# 2. Copy development environment config
cp api/.env.dev api/.env

# 3. Create forge tables
python scripts/setup_mssql_forge.py --create-tables

# 4. Process sample data
python scripts/setup_mssql_forge.py --process-data --limit 50

# 5. Start API
cd api && python -m uvicorn main:app --reload
```

### Option 2: Quick Test with In-Memory Database

```bash
# Temporarily use in-memory database for testing
export SIGIL_DATABASE_URL=""  # Empty = in-memory mode
cd api && python -m uvicorn main:app --reload
```

## Production Fix

### Step 1: Update Azure Container Apps

```bash
# Update production database configuration
./scripts/deploy_forge_fix.sh
```

### Step 2: Create Production Tables

```bash
# Run on machine with production database access
python deploy_forge_schema.py
```

### Step 3: Process Initial Data

```bash
# Process existing scans into forge tables
python api/scripts/batch_classify_forge.py --limit 1000
```

## Verification

Test that forge endpoints now return data:

```bash
# Test forge endpoints
curl https://api.sigilsec.ai/forge/stats
curl https://api.sigilsec.ai/forge/search?q=database
curl https://api.sigilsec.ai/forge/categories
```

## Files Created

- `/scripts/setup_mssql_forge.py` - Complete MSSQL setup and data processing
- `/scripts/configure_dev_mssql.sh` - Local development environment setup  
- `/scripts/deploy_forge_fix.sh` - Production deployment helper
- `/FORGE_FIX_ANALYSIS.md` - Detailed technical analysis

## Next Steps

1. **Immediate**: Run the development setup to test locally
2. **Short-term**: Deploy production fix using deployment scripts
3. **Long-term**: Set up scheduled job for ongoing forge data processing

## Support

If you encounter issues:

1. Check database connection with `python scripts/setup_mssql_forge.py --verify-setup`
2. Review logs in the API application
3. Verify ODBC drivers are installed correctly
4. Confirm environment variables are set properly