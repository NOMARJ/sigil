# Registry Statistics Cache

## Problem

The `/registry/stats` endpoint was timing out due to expensive full-table scans on the `public_scans` table. The endpoint would fetch up to 100K rows and compute statistics in-memory on every request.

With the API search endpoint capping results at 1000, the dashboard was showing inaccurate counts (e.g., "1000+ LOW_RISK packages" when the real count is much higher).

## Solution

**Pre-computed statistics cache** updated by a background task:

1. **Cache Table** (`registry_stats_cache`):
   - Single-row table storing aggregated statistics
   - JSON columns for flexible ecosystem/verdict breakdowns
   - Tracks computation time and freshness

2. **Background Updater** (`registry_stats_updater.py`):
   - Runs every 15 minutes
   - Computes stats from `public_scans` table (limit 200K rows)
   - Updates cache atomically
   - Logs computation duration for monitoring

3. **Fast Endpoint**:
   - `/registry/stats` now reads from cache table (instant)
   - No more expensive table scans per request
   - Falls back to empty stats if cache unavailable

## Files

- `api/migrations/002_create_registry_stats_cache.sql` — Cache table schema
- `api/services/registry_stats_updater.py` — Background updater service
- `api/routers/registry.py` — Updated `/registry/stats` endpoint
- `api/main.py` — Lifecycle hooks (start/stop updater)

## Deployment

### 1. Apply Migration

```bash
# Connect to Azure SQL Database
sqlcmd -S sigil-sql-w2-46iy6y.database.windows.net -d sigil -U sigil_admin -P <password>

# Apply migration
:r api/migrations/002_create_registry_stats_cache.sql
GO
```

Or use the Azure Portal Query Editor to run the migration SQL.

### 2. Deploy Updated API

```bash
# Build and push new image
az acr build --registry sigilacr46iy6y --image sigil-api:latest --file Dockerfile .

# Force new revision with updated code
az containerapp update \
  --name sigil-api \
  --resource-group sigil-rg \
  --set-env-vars "DEPLOY_TIMESTAMP=$(date +%s)"
```

### 3. Verify Background Task

Check logs to confirm the background updater is running:

```bash
az containerapp logs show \
  --name sigil-api \
  --resource-group sigil-rg \
  --follow
```

Expected log entries:
```
Started registry stats updater (interval: 900 seconds)
Computing registry statistics...
Registry stats updated: 1234 packages, 5678 scans, 42 threats (took 3200ms)
```

### 4. Test Endpoint

```bash
curl https://sigil-api.azurecontainerapps.io/registry/stats
```

Should return accurate counts (not capped at 1000).

## Monitoring

### Check Cache Freshness

```sql
SELECT
    total_packages,
    total_scans,
    threats_found,
    computed_at,
    computation_duration_ms,
    DATEDIFF(MINUTE, computed_at, SYSDATETIMEOFFSET()) as age_minutes
FROM registry_stats_cache;
```

If `age_minutes` > 20, the background task may be stuck. Check container logs.

### Manual Refresh

If needed, you can force a stats refresh by restarting the API container:

```bash
az containerapp update \
  --name sigil-api \
  --resource-group sigil-rg \
  --set-env-vars "DEPLOY_TIMESTAMP=$(date +%s)"
```

The updater runs immediately on startup.

## Configuration

### Update Interval

Default: 15 minutes (900 seconds)

To change, edit `api/services/registry_stats_updater.py`:

```python
UPDATE_INTERVAL_SECONDS = 15 * 60  # 15 minutes
```

### Row Limit

Default: 200K rows

To change, edit `api/services/registry_stats_updater.py`:

```python
rows = await db.select(TABLE, None, limit=200_000)
```

Note: Higher limits increase computation time. Monitor `computation_duration_ms` in cache table.

## Troubleshooting

### Stats Not Updating

1. Check if background task is running:
   ```bash
   az containerapp logs show --name sigil-api --resource-group sigil-rg --tail 100
   ```

2. Look for errors in updater loop

3. Verify cache table exists:
   ```sql
   SELECT * FROM registry_stats_cache;
   ```

### Stale Stats

If stats are more than 30 minutes old:

1. Restart the API container to force immediate update
2. Check database connection issues
3. Verify `public_scans` table is accessible

### Incorrect Counts

The background task limits to 200K rows for performance. If your `public_scans` table grows beyond this, increase the limit or consider implementing pagination.

## Future Improvements

1. **Incremental Updates**: Track last processed scan_id and only process new scans
2. **Multiple Cache Rows**: Store historical stats for trending
3. **Trigger-Based Updates**: Use SQL triggers to update stats on INSERT/UPDATE
4. **Separate Stats Table**: Create a denormalized stats table instead of JSON columns
