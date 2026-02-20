# Sigil Threat Signatures - Quick Start Guide

## ⚡ 5-Minute Setup

### 1. Validate Signatures ✅ (Done!)
```bash
python3 api/scripts/validate_signatures_standalone.py
```
**Status:** ✅ 55/55 signatures valid

### 2. Create Database Tables
```sql
-- Copy and run in Supabase SQL Editor:
cat api/scripts/create_signature_tables.sql
```

### 3. Install Dependencies
```bash
pip install -r api/requirements.txt
```

### 4. Load Signatures
```bash
export SUPABASE_URL="your-url"
export SUPABASE_KEY="your-key"

PYTHONPATH=$PWD python3 api/scripts/load_signatures.py
```

### 5. Run Tests
```bash
PYTHONPATH=$PWD pytest api/tests/test_signatures.py -v
```

---

## 📋 One-Command Deployment

```bash
# Full deployment script
./scripts/deploy_signatures.sh
```

(Create this script if you want one-command deployment)

---

## 🔍 Verify Deployment

```python
# test_deployment.py
import asyncio
from api.services.threat_intel import get_signatures, get_signature_stats

async def verify():
    sigs = await get_signatures()
    print(f"✅ Loaded {sigs.total} signatures")

    stats = await get_signature_stats()
    print(f"✅ Categories: {len(stats['by_category'])}")
    print(f"✅ Last updated: {stats['last_updated']}")

asyncio.run(verify())
```

---

## 📚 Documentation Index

| Document | Purpose | Time |
|----------|---------|------|
| **SIGNATURE_SYSTEM_README.md** | System overview | 5 min |
| **DEPLOYMENT_CHECKLIST.md** | Step-by-step deployment | 2-4 hrs |
| **THREAT_SIGNATURES_DEPLOYMENT.md** | Complete documentation | 30 min |
| **api/data/README.md** | Signature guide | 15 min |
| **docs/malicious-signatures.md** | Research compilation | 1 hr |

---

## 🎯 What You Get

- ✅ **55 Production Signatures** (validated)
- ✅ **8 Detection Categories** (install hooks to evasion)
- ✅ **3 Malware Families** (Shai-Hulud, MUT-8694, HF-poisoned)
- ✅ **50+ Test Cases** (comprehensive coverage)
- ✅ **Complete Documentation** (4,000+ lines)
- ✅ **API Integration** (caching + delta sync)

---

## 🚨 Common Issues

### "Module not found: api"
```bash
# Solution: Set PYTHONPATH
export PYTHONPATH=/Users/reecefrazier/CascadeProjects/sigil
```

### "Signature validation failed"
```bash
# Solution: Check error output
python3 api/scripts/validate_signatures_standalone.py
```

### "Database connection failed"
```bash
# Solution: Check environment variables
echo $SUPABASE_URL
echo $SUPABASE_KEY
```

---

## 🎓 Next Steps

1. ✅ Validation complete
2. ⏳ Create database tables
3. ⏳ Load signatures
4. ⏳ Run tests
5. ⏳ Deploy to production

**Current Status:** Step 1/5 complete

**Time to Production:** ~2-4 hours

---

## 📞 Need Help?

- **Quick questions:** See [DEPLOYMENT_CHECKLIST.md](DEPLOYMENT_CHECKLIST.md)
- **Technical details:** See [THREAT_SIGNATURES_DEPLOYMENT.md](THREAT_SIGNATURES_DEPLOYMENT.md)
- **Signature guide:** See [api/data/README.md](api/data/README.md)
- **Research data:** See [docs/malicious-signatures.md](docs/malicious-signatures.md)

---

**Ready to deploy?** Follow [DEPLOYMENT_CHECKLIST.md](DEPLOYMENT_CHECKLIST.md) →
