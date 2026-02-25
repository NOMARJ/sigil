# Phase 8: Security Review (Meta — Auditing the Auditor)

**Status: Trustworthy with Caveats (6/10)**

---

## Secrets Audit

| Check | Status | Notes |
|-------|--------|-------|
| API keys in git | ✅ Clean | No secrets committed |
| `.gitignore` coverage | ✅ Good | Covers .env, docs/internal/, *.docx |
| Hardcoded credentials | ⚠️ Default JWT | `config.py:49` has default secret |
| Deploy scripts | ⚠️ Project ID | Supabase project ID hardcoded in deploy scripts |
| Token storage | ✅ Good | `~/.sigil/token` with mode 0600 |

---

## Install Script Security

**File:** `install.sh`

| Check | Status |
|-------|--------|
| Downloads from HTTPS | ✅ |
| Verifies checksums (SHA256) | ❌ Missing |
| Verifies GPG signatures | ❌ Missing |
| Validates binary before installing | ✅ Runs `sigil --version` |
| Idempotent | ✅ |
| Platform detection | ✅ |

**Recommendation:** Add SHA256 checksum verification against published checksums file (which IS generated in release.yml).

---

## Telemetry & Privacy

**Assessment: Privacy-preserving ✅**

The threat intel service (`api/services/threat_intel.py`) only transmits:
- Package hash (SHA-256)
- Phase/rule triggers
- Risk scores

**Source code is NEVER transmitted.** All pattern matching runs locally.

---

## Scan Engine Bypass Analysis

### Can a sophisticated attacker evade all 6 phases?

**Yes.** Identified bypass vectors:

1. **Multi-stage attacks:** Stage 1 passes scan (benign), stage 2 downloads payload at runtime
   - Mitigation: This is a known limitation of static analysis. Document it.

2. **Non-text file payloads:** Binary files scanned only for provenance (filename/size), not contents
   - Mitigation: Add binary signature detection (PE headers, ELF magic)

3. **Comment-based evasion:** Patterns in comments will be flagged (good), but legitimate code with comments may cause false positives
   - Current behavior is actually correct for security — better to over-report

4. **Variable indirection:**
   ```python
   x = "ev" + "al"
   y = getattr(__builtins__, x)
   y("malicious_code")
   ```
   Not detected by regex-based scanner.
   - Mitigation: This requires taint analysis, beyond current scope

5. **Encoded payloads split across files:**
   ```python
   # file1.py: part1 = "aW1wb3J0IG"
   # file2.py: part2 = "9zCm9zLnN5c3RlbSgn..."
   # file3.py: exec(base64.b64decode(part1 + part2))
   ```
   Individual file scans may not correlate.
   - Mitigation: Cross-file analysis would help

6. **Dependency chain attacks:** Scanning `safe-pkg` doesn't scan its dependencies
   - Mitigation: Transitive dependency scanning (roadmap item)

---

## Test Coverage

**Good coverage for core functionality:**

| Test File | Coverage | Notes |
|-----------|----------|-------|
| `test_scanner_service.py` | All 6 phases | Comprehensive pattern testing |
| `test_openclaw_attack.py` | Real-world attack | OpenClaw/Atomic Stealer patterns |
| `test_auth.py` | Auth endpoints | Registration, login, token validation |
| `test_scoring.py` | Scoring system | Risk weighting, verdict assignment |
| `test_signatures.py` | Signature loading | Database integration |
| `test_threat.py` | Threat intel | Lookup and enrichment |
| `test_auth_dependency_injection.py` | Auth DI | Middleware testing |
| `conftest.py` | Test fixtures | Database mocking |

**Known malicious samples tested:**
- OpenClaw Campaign (Atomic Stealer / AMOS)
- Shai-Hulud Wave 1 & 2 (npm worm)
- MUT-8694 (cross-ecosystem attack)
- Hugging Face pickle poisoning

---

## Dependency Security

**API dependencies (`requirements.txt`):**

| Package | Version | Risk |
|---------|---------|------|
| fastapi | >=0.109.0 | ✅ Actively maintained |
| uvicorn | >=0.27.0 | ✅ Standard ASGI server |
| pydantic | >=2.5.0 | ✅ Type validation |
| httpx | >=0.26.0 | ✅ Async HTTP |
| python-jose[cryptography] | latest | ✅ JWT handling |
| passlib[bcrypt] | >=1.7.4 | ✅ Password hashing |
| stripe | >=7.0.0 | ✅ Payment processing |
| redis | >=5.0.0 | ⚠️ No upper bound |
| supabase | >=2.3.0 | ✅ Database client |
| asyncpg | >=0.29.0 | ✅ Async Postgres |

**Recommendation:** Pin upper bounds on redis (`<6.0.0`) and supabase (`<3.0.0`) to prevent breaking changes.

---

## Honest Assessment: Would I Trust This Tool?

### YES, for its intended purpose (supply-chain scanning)

**Strengths:**
1. Open source and auditable
2. Comprehensive pattern library (247+ signatures for real malware)
3. Privacy-preserving (no source code transmission)
4. Real-world attack detection verified (OpenClaw, Shai-Hulud)
5. Graceful offline degradation
6. Clean architecture, proper dependency injection
7. Multiple integration points (CLI, plugins, MCP, CI/CD)

### BUT with clear limitations:

1. **Static analysis only** — Cannot detect runtime attacks, obfuscated multi-stage payloads, or compiled malware
2. **Regex-based** — Sophisticated evasion via variable indirection is possible
3. **No transitive dependency scanning** — Only scans direct packages
4. **Install script needs hardening** — Binary download without signature verification
5. **Auth needs work** — Default JWT secret is a real risk if not overridden

### Recommendation:

Deploy Sigil as **part of a defense-in-depth strategy:**
- Sigil for pre-install quarantine and supply-chain scanning
- Semgrep/CodeQL for deep static analysis
- Snyk/Socket for CVE tracking
- Manual review for high-risk dependencies
- SigStore for provenance verification

Sigil fills a genuine gap (pre-install quarantine with supply-chain focus) that other tools don't address. It should be marketed as a **first-line defense**, not a complete solution.
