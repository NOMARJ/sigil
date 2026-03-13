# Forge Component Archival - Complete Documentation

This document provides complete instructions for the Forge component archival performed on **March 13, 2026**.

## What Was Archived

### API Components Removed
- **Routers**: `api/routers/forge*.py` (4 files)
  - forge.py - Main Forge discovery and curation endpoints
  - forge_analytics.py - Forge analytics and metrics endpoints  
  - forge_premium.py - Forge premium features (authenticated)
  - forge_secure.py - Secure Forge endpoints

- **Services**: `api/services/forge*.py` (4 files)
  - forge_analytics.py - Analytics service implementation
  - forge_classifier.py - Tool classification service
  - forge_matcher.py - Tool matching and compatibility service
  - forge_user_tools.py - User tool tracking service

- **Security**: `api/security/forge_access.py`
  - Forge access control and authentication

### Database Components Archived
- **Tables** (11 tables total):
  - forge_classification - Main classification data
  - forge_categories - Category taxonomy
  - forge_capabilities - Package capabilities
  - forge_matches - Tool compatibility matches
  - forge_user_tools - User tool tracking
  - forge_stacks - Custom tool stacks
  - forge_alert_subscriptions - Alert subscriptions
  - forge_analytics_events - Analytics events
  - forge_analytics_summaries - Pre-computed metrics
  - forge_user_settings - User preferences
  - forge_tool_metrics - Tool metrics over time
  - forge_trending_cache - Trending calculations cache

- **Views**: 
  - forge_tool_metrics_latest - Latest metrics view

- **Procedures**:
  - sp_cleanup_trending_cache - Cache cleanup procedure

- **Triggers**:
  - tr_forge_tool_metrics_updated_at
  - tr_forge_trending_cache_updated_at

### API Configuration Changes
- Removed Forge router imports from main.py
- Removed Forge route registrations
- Removed Forge OpenAPI documentation
- Updated email router comment (removed "Forge Weekly" reference)

## Archive Location

All archived components are stored in:
```
archive/
├── migrations/           # Database migration files
├── routers/             # API router files
├── services/            # Service implementation files
├── security/            # Security modules
├── scripts/             # Database management scripts
└── documentation/       # This documentation
```

## Rollback Procedures

### Database Rollback Options

#### Option 1: Safe Archive (Preserves Data)
```bash
# Archive tables (rename with timestamp)
sqlcmd -S <server>.database.windows.net -d sigil -U <user> -i archive/scripts/archive_forge_database.sql
```

#### Option 2: Complete Removal (Destroys Data)
```bash
# WARNING: This permanently deletes all Forge data
sqlcmd -S <server>.database.windows.net -d sigil -U <user> -i archive/migrations/rollback_forge_tables.sql
```

#### Option 3: Restore from Archive
```bash
# Restore archived tables back to active names
sqlcmd -S <server>.database.windows.net -d sigil -U <user> -i archive/scripts/restore_forge_database.sql

# Then re-run original migrations for views/procedures
sqlcmd -S <server>.database.windows.net -d sigil -U <user> -i archive/migrations/009_forge_tool_metrics.sql
```

### Application Code Rollback

To restore Forge functionality:

1. **Restore API Files**:
```bash
cp archive/routers/* api/routers/
cp archive/services/* api/services/
cp archive/security/* api/security/
```

2. **Restore main.py Configuration**:
   - Add Forge router imports back to the import section
   - Add router registrations back to the app.include_router() calls
   - Restore OpenAPI tags and endpoint documentation
   - Restore "Forge Weekly" newsletter reference

3. **Database Restoration**:
   - Run restore_forge_database.sql if using safe archive
   - Re-run original migration files if starting fresh

4. **Verify Dependencies**:
   - Check that all Forge imports work correctly
   - Test Forge endpoints are accessible
   - Verify database connections work

## Migration Files Archived

Original migration files have been copied to archive/migrations/:
- 004_create_forge_classification.sql
- 008_forge_premium_features.sql  
- 009_forge_tool_metrics.sql
- add_forge_analytics.sql
- add_forge_security.sql

## Verification Commands

### Check Database State
```sql
-- Check if Forge tables exist (should return empty)
SELECT name FROM sys.tables WHERE name LIKE 'forge%';

-- Check if archived tables exist (should show archived tables)
SELECT name FROM sys.tables WHERE name LIKE 'forge%_archived_%';
```

### Check API State
```bash
# Check that Forge routers are removed
ls api/routers/forge*     # Should show "No such file"

# Check that Forge services are removed  
ls api/services/forge*    # Should show "No such file"

# Verify main.py has no Forge references
grep -i forge api/main.py # Should show no results
```

### Test API Endpoints
```bash
# These should return 404 (endpoints removed)
curl -X GET http://localhost:8000/forge/search
curl -X GET http://localhost:8000/forge/categories
```

## Impact Assessment

### Systems Affected
- ✅ **API Service**: Forge endpoints removed, no breaking changes to other endpoints
- ✅ **Database**: Tables archived safely, foreign key dependencies handled
- ✅ **Documentation**: OpenAPI spec updated, Forge endpoints removed

### Systems NOT Affected
- ✅ **Core Sigil Functionality**: Scanning, threat detection, reporting unchanged
- ✅ **Authentication**: User auth system unaffected
- ✅ **Other API Endpoints**: Registry, feeds, badges, etc. still functional
- ✅ **Dashboard**: Frontend should continue working (no Forge dependencies)

### Breaking Changes
- Any external systems calling `/forge/*` endpoints will receive 404 errors
- Any code depending on Forge service classes will need updates
- Database queries against Forge tables will fail

## Recovery Testing

Before deploying to production, test the archival:

1. **Development Environment**:
   - Run archive scripts against dev database
   - Start API server and verify it starts without errors
   - Test that non-Forge endpoints still work

2. **API Health Check**:
   ```bash
   curl -X GET http://localhost:8000/status
   curl -X GET http://localhost:8000/registry/search
   ```

3. **Database Verification**:
   ```sql
   -- Should work (non-Forge tables)
   SELECT COUNT(*) FROM scans;
   SELECT COUNT(*) FROM threats;
   ```

## Emergency Rollback

If immediate rollback is needed:

1. **Database**: Run restore_forge_database.sql
2. **Code**: 
   ```bash
   git revert <commit-hash>  # Revert the archival commit
   ```
3. **Deploy**: Redeploy with restored code
4. **Verify**: Test Forge endpoints work

## Contact & Support

For questions about this archival:
- Review this documentation first
- Check archive/ directory for all original files
- All migration files are preserved for complete restoration

---

**Archive Date**: March 13, 2026  
**Archive Reason**: Forge sunset per CLI discovery sunset feature request  
**Data Preservation**: All data archived safely, can be restored  
**Breaking Changes**: Yes - Forge API endpoints removed