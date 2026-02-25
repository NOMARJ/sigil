# Phase 6: Documentation & Developer Experience

**Status: Good (8/10)**

---

## Documentation Inventory

27 public docs + 3 internal docs. Comprehensive coverage.

### README Accuracy

| Claim | Accurate? | Notes |
|-------|-----------|-------|
| 6-phase scan system | ✅ Yes | All phases implemented |
| `sigil clone <url>` | ✅ Yes | Works |
| `sigil pip <pkg>` | ✅ Yes | Works |
| `sigil npm <pkg>` | ✅ Yes | Works |
| `sigil scan <path>` | ✅ Yes | Works |
| `sigil approve/reject <id>` | ✅ Yes | Works |
| Homebrew install | ✅ Yes | Formula exists |
| npm install | ✅ Yes | Package configured |
| Docker support | ✅ Yes | Images built |
| Pro tier $29/mo | ⚠️ Partial | Stripe integrated but dashboard broken |
| Team tier $99/mo | ⚠️ Partial | Features built but dashboard broken |
| Web dashboard | ❌ Not working | Shows no data (P0 issues) |
| Comparison table (vs Snyk, Socket) | ✅ Accurate | Claims are defensible |

### Install Instructions

All installation methods documented in `docs/installation.md` are accurate:
- Homebrew, npm, cargo, curl, Docker, manual — all correct paths

### Pricing Table

Matches the API billing implementation. FREE (50 scans), PRO ($29, 500 scans), TEAM ($99, 5K scans), ENTERPRISE (custom).

---

## Documentation Gaps

### Critical

1. **API URL inconsistency** — Docs reference both `api.sigil.nomark.dev` and `api.sigilsec.ai`
   - CHANGELOG v0.9.0 mentions `api.sigil.nomark.dev`
   - api-reference.md uses `api.sigilsec.ai`
   - **Fix:** Standardize all docs to `api.sigilsec.ai`

2. **Dashboard getting-started incomplete** — No guide for "sign up → first dashboard view"
   - Getting-started covers CLI well but dashboard path is unclear

### Minor

3. **"Coming soon" inconsistencies** — Some docs say Homebrew is "coming soon" but it's ready
4. **ROADMAP vs CHANGELOG mismatch** — Dashboard listed as "working on now" in roadmap but already partially built
5. **No `.env.example` for dashboard** — Only API has one
6. **Config file format** — Docs mention `~/.sigil/config` but don't show complete example

---

## CLAUDE.md Review

The CLAUDE.md file is well-structured with:
- ✅ Accurate project overview
- ✅ Correct repo structure
- ✅ Proper scan phase documentation
- ✅ Good documentation guidelines (public vs internal)
- ✅ Useful quick start commands

**Suggestions:**
- Add note about API URL standardization
- Add note about current auth status (custom JWT vs Supabase)
- Update to reflect actual version (1.0.5 vs "0.1.0" in config)

---

## Recommendations

1. Standardize API URL to `api.sigilsec.ai` across all docs
2. Add dashboard `.env.example` with all required Supabase vars
3. Update "coming soon" labels to reflect current readiness
4. Add a "Dashboard Setup" section to getting-started guide
5. Sync ROADMAP with actual implementation status
