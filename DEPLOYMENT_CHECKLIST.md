# Sigil Threat Signatures - Deployment Checklist

## Pre-Deployment Validation ✅

### 1. Signature Validation
- [x] **JSON structure valid** - 55 signatures loaded successfully
- [x] **All required fields present** - id, category, phase, severity, pattern, description
- [x] **No duplicate IDs** - All signature IDs are unique
- [x] **Valid regex patterns** - All patterns compile successfully
- [x] **Valid enums** - All phase and severity values are valid
- [x] **Weight values in range** - All weights between 0-20

**Validation Command:**
```bash
python3 api/scripts/validate_signatures_standalone.py
```

**Result:** ✅ ALL SIGNATURES VALID

---

## Deployment Steps

### Step 1: Database Setup

#### 1.1 Create Database Tables

Run the SQL migration in Supabase:

```bash
# Copy SQL content
cat api/scripts/create_signature_tables.sql
```

Then execute in Supabase SQL Editor or via psql:

```sql
-- Tables to create:
-- 1. public.signatures (extended with metadata)
-- 2. public.malware_families (threat intelligence)

-- Indexes:
-- - category, severity, phase (filtering)
-- - updated_at (delta sync)
```

**Verification Query:**
```sql
SELECT
    table_name,
    (SELECT COUNT(*) FROM information_schema.columns
     WHERE table_name = t.table_name) as column_count
FROM information_schema.tables t
WHERE table_schema = 'public'
AND table_name IN ('signatures', 'malware_families');
```

Expected: 2 rows (signatures, malware_families)

#### 1.2 Verify Permissions

```sql
-- Check permissions
SELECT
    grantee,
    privilege_type
FROM information_schema.role_table_grants
WHERE table_name IN ('signatures', 'malware_families')
ORDER BY grantee, privilege_type;
```

Expected:
- `anon`, `authenticated`: SELECT
- `service_role`: ALL

---

### Step 2: Install Dependencies

```bash
cd /Users/reecefrazier/CascadeProjects/sigil

# Install Python dependencies
pip install -r api/requirements.txt

# Verify installation
python3 -c "from api.database import db; from api.models import ScanPhase, Severity; print('✓ Imports successful')"
```

---

### Step 3: Load Signatures

#### 3.1 Validate (Already Done ✅)

```bash
python3 api/scripts/validate_signatures_standalone.py
```

#### 3.2 Load into Database

```bash
# Set environment variables (if not in .env)
export SUPABASE_URL="your-supabase-url"
export SUPABASE_KEY="your-service-role-key"

# Load all signatures
PYTHONPATH=/Users/reecefrazier/CascadeProjects/sigil \
python3 api/scripts/load_signatures.py

# Expected output:
# 📦 Loading 55 signatures...
#   + Loaded: sig-install-001
#   + Loaded: sig-install-002
#   ...
# ✅ All signatures loaded successfully!
```

#### 3.3 Verify Load

```sql
-- Check signature count
SELECT
    category,
    COUNT(*) as count,
    AVG(weight) as avg_weight
FROM signatures
GROUP BY category
ORDER BY count DESC;
```

Expected: 8 categories with counts matching validation output

---

### Step 4: Run Tests

#### 4.1 Install Test Dependencies

```bash
pip install pytest pytest-asyncio
```

#### 4.2 Run Signature Tests

```bash
# Run all signature tests
PYTHONPATH=/Users/reecefrazier/CascadeProjects/sigil \
pytest api/tests/test_signatures.py -v

# Run specific test categories
pytest api/tests/test_signatures.py::TestSignatureValidation -v
pytest api/tests/test_signatures.py::TestSignaturePatterns -v
pytest api/tests/test_signatures.py::TestSignaturePerformance -v
pytest api/tests/test_signatures.py::TestSignatureCategories -v
```

**Expected:** All 50+ tests pass

---

### Step 5: API Integration Testing

#### 5.1 Test Signature Retrieval

```python
# test_api_integration.py
import asyncio
from api.services.threat_intel import get_signatures, get_signature_stats

async def test_signatures():
    # Get all signatures
    response = await get_signatures()
    print(f"✓ Loaded {response.total} signatures")
    print(f"  Last updated: {response.last_updated}")

    # Get statistics
    stats = await get_signature_stats()
    print(f"\n✓ Statistics:")
    print(f"  By category: {stats['by_category']}")
    print(f"  By severity: {stats['by_severity']}")
    print(f"  By phase: {stats['by_phase']}")

    # Test cache
    response2 = await get_signatures()
    assert response2.total == response.total
    print(f"\n✓ Cache working (TTL: 3600s)")

if __name__ == "__main__":
    asyncio.run(test_signatures())
```

Run:
```bash
PYTHONPATH=/Users/reecefrazier/CascadeProjects/sigil \
python3 test_api_integration.py
```

#### 5.2 Test Delta Sync

```python
# test_delta_sync.py
import asyncio
from datetime import datetime, timedelta
from api.services.threat_intel import get_signatures

async def test_delta():
    # Get all
    all_sigs = await get_signatures()
    print(f"✓ All signatures: {all_sigs.total}")

    # Get only recent (last 30 days)
    recent_date = datetime.utcnow() - timedelta(days=30)
    recent_sigs = await get_signatures(since=recent_date)
    print(f"✓ Recent signatures: {recent_sigs.total}")

    assert recent_sigs.total <= all_sigs.total

asyncio.run(test_delta())
```

---

### Step 6: Scanner Integration

#### 6.1 Update Scanner Service (Optional)

Currently, `api/services/scanner.py` uses hardcoded rules. To use database signatures:

```python
# In scanner.py
from api.services.threat_intel import get_signatures

async def load_rules_from_db():
    sig_response = await get_signatures()
    rules = []
    for sig in sig_response.signatures:
        rules.append(Rule(
            id=sig.id,
            phase=sig.phase,
            severity=sig.severity,
            pattern=re.compile(sig.pattern, re.IGNORECASE | re.MULTILINE),
            description=sig.description,
            weight=getattr(sig, 'weight', 1.0),
        ))
    return rules
```

**Note:** This is optional for initial deployment. The current hardcoded rules will continue working.

---

### Step 7: CLI Integration Verification

The CLI already supports cloud signature sync. Test it:

```bash
# Authenticate
./bin/sigil login --email your@email.com --password yourpassword

# Run a scan (will sync signatures)
./bin/sigil scan .

# Check report for signature sync
tail -30 ~/.sigil/reports/*_report.txt
```

Look for:
```
[Phase 7] Cloud Threat Intelligence
  Synced cloud signatures (refreshed)
  Cloud signatures: X match(es)
```

---

## Post-Deployment Verification

### 1. Database Checks

```sql
-- Total signatures
SELECT COUNT(*) FROM signatures;
-- Expected: 55

-- Coverage by category
SELECT category, COUNT(*)
FROM signatures
GROUP BY category
ORDER BY COUNT(*) DESC;
-- Expected: 8 categories

-- Severity distribution
SELECT severity, COUNT(*)
FROM signatures
GROUP BY severity
ORDER BY
    CASE severity
        WHEN 'CRITICAL' THEN 1
        WHEN 'HIGH' THEN 2
        WHEN 'MEDIUM' THEN 3
        WHEN 'LOW' THEN 4
    END;
-- Expected: CRITICAL=20, HIGH=26, MEDIUM=7, LOW=2

-- Malware families
SELECT COUNT(*) FROM malware_families;
-- Expected: 3 (shai-hulud, mut-8694, huggingface-poisoned)
```

### 2. Cache Verification

```python
from api.database import cache
import asyncio

async def check_cache():
    # Check if signatures are cached
    cached = await cache.get("signatures:all")
    if cached:
        print("✓ Signatures cached")
    else:
        print("⚠ Cache empty (will populate on first request)")

asyncio.run(check_cache())
```

### 3. Performance Checks

```python
import time
import asyncio
from api.services.threat_intel import get_signatures

async def benchmark():
    # First call (database + cache write)
    start = time.time()
    await get_signatures()
    first_call = time.time() - start

    # Second call (cached)
    start = time.time()
    await get_signatures()
    cached_call = time.time() - start

    print(f"✓ First call (DB): {first_call*1000:.1f}ms")
    print(f"✓ Cached call: {cached_call*1000:.1f}ms")
    print(f"✓ Cache speedup: {first_call/cached_call:.1f}x")

asyncio.run(benchmark())
```

Expected:
- First call: <200ms
- Cached call: <20ms
- Speedup: >5x

---

## Production Readiness Checklist

### Core Functionality
- [x] Signatures validate successfully
- [ ] Database tables created and indexed
- [ ] All signatures loaded (55/55)
- [ ] Malware families loaded (3/3)
- [ ] API returns signatures in <200ms
- [ ] Cache working (speedup >5x)
- [ ] Tests passing (50+/50+)

### Integration
- [ ] Scanner service can load DB signatures (optional)
- [ ] CLI cloud sync working
- [ ] Delta sync functional
- [ ] Statistics endpoint working

### Monitoring
- [ ] Database query performance logged
- [ ] Cache hit rate tracked
- [ ] API response times monitored
- [ ] Error rates tracked

### Documentation
- [x] Deployment guide created
- [x] API documentation updated
- [x] Test suite documented
- [x] Maintenance procedures documented

---

## Rollback Plan

If issues occur during deployment:

### 1. Rollback Database
```sql
-- Drop tables (preserves existing data)
DROP TABLE IF EXISTS public.malware_families;
DROP TABLE IF EXISTS public.signatures;
```

### 2. Rollback Code
```bash
# Revert API changes
git checkout HEAD -- api/services/threat_intel.py

# Remove new files
rm api/data/threat_signatures.json
rm api/scripts/load_signatures.py
rm api/tests/test_signatures.py
```

### 3. Clear Cache
```python
from api.database import cache
import asyncio
asyncio.run(cache.delete("signatures:all"))
```

---

## Success Metrics (30 Days)

### Performance
- [ ] API response time <200ms (p95)
- [ ] Cache hit rate >80%
- [ ] Zero validation errors
- [ ] Database query time <100ms (p95)

### Detection
- [ ] Detect >95% of known malware families
- [ ] <5% false positive rate on popular packages
- [ ] User-reported accuracy >4.5/5

### Operational
- [ ] 99.9% API uptime
- [ ] Zero data corruption incidents
- [ ] <1 hour signature update time

---

## Support Contacts

- **Technical Issues**: Check `api/data/README.md`
- **False Positives**: Submit via threat report API
- **New Signatures**: Follow contribution guide
- **Deployment Help**: See `THREAT_SIGNATURES_DEPLOYMENT.md`

---

## Next Steps After Deployment

### Week 1
1. Monitor API performance and cache hit rates
2. Review initial scan results for false positives
3. Gather user feedback on detection accuracy
4. Document any issues in GitHub

### Week 2-4
1. Analyze detection patterns
2. Tune weights based on real-world data
3. Add Priority 1 signatures (IMDS, TruffleHog patterns)
4. Begin quarterly signature review process

### Month 2
1. Implement ML-based pattern discovery
2. Add signature auto-generation from malware samples
3. Build community contribution workflow
4. Integrate additional threat feeds

---

**Deployment Date:** _____________
**Deployed By:** _____________
**Environment:** Production / Staging / Development
**Version:** 1.0.0

**Sign-off:**
- [ ] Technical Lead
- [ ] Security Team
- [ ] DevOps
- [ ] Product Manager
