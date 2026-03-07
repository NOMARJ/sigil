# Sigil Repository Structure — First Principles Analysis

**Date**: March 7, 2026  
**Status**: Recommendation  
**Next**: Architecture review and migration planning

## Executive Summary

**Recommendation**: Consolidate into a single public repository with transparent pro features and separate secrets-only private repo.

**Current State**: Fragmented across 4 repositories (sigil monorepo, sigil-infra, sigilsec, sigil-skill)  
**Proposed State**: 2 repositories (sigil public, sigil-infra private) — **sigil-infra already exists**

## Problem Definition

**What we're solving:**
- Optimal organization of Sigil's codebase across repositories
- Balance between open source accessibility and commercial/infrastructure security  
- Developer experience for contributors vs. operational security

**Success criteria:**
- Clear separation of concerns between public and private code
- Easy contribution flow for open source developers
- Secure infrastructure management
- Minimal friction for feature development across tiers
- Clear licensing and commercial boundaries

## Current Assumptions Analysis

| Assumption | Classification | Rationale |
|------------|----------------|-----------|
| Monorepo for related code | **Convention** | Dev velocity vs. boundaries trade-off |
| No pro features in OSS | **Convention** | License compliance possible with gating |
| Private infrastructure | **Fundamental** | Contains actual secrets |
| Language boundaries | **Convention** | Modern tooling handles multi-language |
| Product separation | **Convention** | Unified distribution possible |
| Security through obscurity | **Convention** | Transparency enables community security |
| Multi-repo friction | **Convention** | Modern tooling eliminates friction |
| Coupled releases | **Convention** | Independent releases enable faster iteration |
| Skills separation | **Convention** | Integration benefits outweigh separation |

## Fundamental Constraints

**MUST preserve (Physics/Logic):**
- Secrets must not be in public repos (security)
- Different package ecosystems need different distribution (npm, PyPI, cargo)
- License boundaries must be clear (legal compliance)
- Access control requires authentication (technical limitation)

**CAN change (Convention):**
- Repository boundaries
- Feature visibility
- Infrastructure organization
- Development workflow

## Recommended Structure

### Core Repository: `sigil` (Public)

```
sigil/
├── cli/                   # Rust CLI (OSS + Pro gated features)
│   ├── src/
│   ├── Cargo.toml
│   └── README.md
├── api/                   # Python FastAPI (OSS + Pro gated features)  
│   ├── src/
│   ├── pyproject.toml
│   └── Dockerfile
├── dashboard/             # Next.js (OSS + Pro gated features)
│   ├── src/
│   ├── package.json
│   └── next.config.js
├── plugins/               # All IDE integrations
│   ├── vscode/
│   ├── jetbrains/
│   └── mcp-server/
├── skills/                # All agent skills/MCPs
│   ├── scan-repo/
│   ├── scan-package/
│   └── review-quarantine/
├── packages/              # Shared libraries
│   ├── shared-types/
│   ├── detection-engine/
│   └── quarantine-core/
├── examples/              # Infrastructure templates (no secrets)
│   ├── terraform/
│   ├── docker/
│   └── kubernetes/
├── docs/                  # All documentation
│   ├── getting-started.md
│   ├── api/
│   └── deployment/
├── .github/               # Unified CI/CD
│   └── workflows/
├── Makefile               # Unified build system
└── workspace.json         # Multi-language workspace config
```

**Key principles:**
- **Transparent Pro Features**: Visible but gated with clear upgrade prompts
- **Unified Build System**: Single Makefile orchestrating all languages
- **Shared Packages**: Common detection logic, types, and utilities
- **Examples Over Secrets**: Infrastructure templates with placeholder values

### Infrastructure Repository: `sigil-infra` (Private - Already Exists)

```
sigil-infra/              # ✅ ALREADY IN PLACE
├── azure/
│   ├── terraform/        # Azure Terraform with real secrets
│   ├── terraform.tfvars  # Production variables
│   └── outputs.tf
├── scripts/
│   ├── deploy.sh
│   └── cleanup.sh
└── docs/
    └── deployment/
```

**Contains only:**
- Actual production secrets and credentials  
- Azure subscription and resource configurations
- Deployment automation scripts
- Infrastructure documentation

**No changes needed** - this separation is already correct!

## Benefits of This Approach

### 1. Development Velocity
- **Single Clone**: `git clone sigil` gets everything
- **Atomic Changes**: Cross-component features in single PR
- **Unified Testing**: Integration tests across all components
- **Shared Tooling**: Single build system, linting, formatting

### 2. Community Growth
- **Lower Barrier**: One repo to understand and contribute to
- **Transparency**: Users see pro features, understand value proposition
- **Security Review**: More eyes on security-critical code
- **Documentation**: Single source of truth

### 3. Commercial Benefits
- **Clear Value Prop**: Users see what they're missing with pro tier
- **Easier Upsell**: Integrated upgrade prompts and feature discovery
- **Better Support**: Single codebase reduces support complexity
- **Faster Development**: No cross-repo synchronization delays

### 4. Security Advantages
- **Separation of Concerns**: Templates vs. secrets clearly separated
- **Community Audit**: Security researchers can review detection logic
- **Reproducible Deployments**: Public templates + secret injection
- **Reduced Attack Surface**: Fewer repos to secure and monitor

## Migration Strategy

### Phase 1: Consolidation (Week 1-2)
1. **Keep existing**: `sigil-infra` stays as-is (✅ already correct)
2. Migrate code into main `sigil` repo:
   - `sigil-skill` → `skills/` directory
   - `sigilsec` → appropriate component directories  
   - Current structure → reorganized structure
3. Create infrastructure templates in `examples/` (referencing `sigil-infra` patterns)

### Phase 2: Pro Feature Integration (Week 3-4)
1. Implement feature gating system
2. Add upgrade prompts and feature discovery
3. Update documentation and licensing
4. Create unified build and release system

### Phase 3: Community Transition (Week 5-6)
1. Update all external references
2. Archive old repositories
3. Communicate changes to community
4. Monitor for issues and feedback

## Validation

**Does this solve the original problem?** ✅
- Clearer organization with public/private separation
- Better developer experience through unification  
- Secure secrets management
- Commercial boundaries maintained through gating

**New assumptions introduced:**
- Feature gating system will be reliable
- Community will accept pro feature visibility
- Build system can handle multi-language complexity
- Migration won't disrupt existing users

**Implementation risks:**
- Build system complexity
- License compliance during transition
- Existing integrations may break temporarily
- Community perception of "commercialization"

**Mitigation strategies:**
- Gradual migration with fallbacks
- Clear communication about benefits
- Comprehensive testing during transition
- Community feedback integration

## Conclusion

The current multi-repo structure is based on conventions rather than fundamental constraints. Consolidating into a transparency-first single repository will:

1. **Accelerate development** through unified tooling and atomic changes
2. **Grow the community** through lower contribution barriers
3. **Improve security** through broader review and reproducible deployments
4. **Strengthen commercial position** through transparent value proposition

**Recommendation**: Proceed with consolidation, starting with the migration strategy outlined above.

---

**Next Steps:**
1. Architecture review with team
2. Detailed migration timeline
3. Community communication plan
4. Technical implementation of feature gating system