# Sigil Repository Consolidation Plan

**Date**: March 7, 2026  
**Status**: Implementation Plan  
**Next**: Execute migration strategy

## Current State Analysis

### Repository Structure ✅ ANALYZED

**Current repositories:**
1. **`sigil`** (main) - CLI, API, Dashboard, Plugins, MCP server
2. **`sigil-infra`** (private) - Azure Terraform with secrets ✅ **KEEP AS-IS**
3. **`sigilsec`** (marketing) - Next.js marketing website at sigilsec.ai
4. **`sigil/sigil-skill`** (subdirectory) - skills.sh integration for AI agents

### What Each Repository Contains

#### 1. Main `sigil` Repository
```
sigil/
├── cli/                    # Rust CLI (OSS + Pro features)
├── api/                    # Python FastAPI backend 
├── dashboard/              # Next.js web dashboard
├── plugins/                # IDE integrations
│   ├── vscode/             # VS Code extension
│   ├── jetbrains/          # JetBrains plugin
│   └── mcp-server/         # MCP server for Claude Code
├── sigil-skill/            # ← SHOULD MOVE TO skills/
├── skills/                 # Empty - should be consolidated location
├── docs/                   # Public documentation
└── bin/sigil               # Bash CLI wrapper
```

#### 2. `sigil-infra` Repository ✅ PERFECT SEPARATION
```
sigil-infra/                # ✅ KEEP - Contains actual secrets
├── azure/terraform/        # Production Azure configs
├── scripts/deploy.sh       # Deployment automation
└── docs/deployment/        # Infrastructure docs
```

#### 3. `sigilsec` Repository (Marketing Site)
```
sigilsec/
├── src/app/                # Next.js marketing pages
│   ├── page.tsx            # Landing page
│   ├── docs/               # Public docs (7 pages)
│   ├── blog/               # Blog via cakewalk.ai
│   └── api/                # Revalidation webhook
├── components/             # Marketing UI components
├── public/                 # Static assets (favicon, install.sh)
└── docs/                   # Internal marketing docs
```

#### 4. `sigil-skill` (Currently in sigil/ subdirectory)
```
sigil-skill/
├── sigil-scan/             # skills.sh integration
├── tests/                  # Skill tests
└── README.md               # Installation guide
```

## Consolidation Strategy

### ✅ KEEP SEPARATE: `sigil-infra`
**Rationale**: Contains actual Azure secrets, connection strings, production configs.  
**Action**: No changes needed - perfect first principles separation.

### 🎯 CONSOLIDATE: Everything else into single `sigil` repo

## Proposed Final Structure

```
sigil/                      # ← Single unified public repository
├── cli/                    # Rust CLI (OSS + Pro gated features)
├── api/                    # Python FastAPI (OSS + Pro gated features)
├── dashboard/              # Next.js dashboard (OSS + Pro gated features)
├── marketing/              # ← FROM sigilsec (Next.js marketing site)
│   ├── src/app/            # Marketing pages
│   ├── components/         # Marketing components
│   ├── public/             # Marketing assets
│   └── package.json        # Separate build target
├── skills/                 # ← FROM sigil-skill (AI agent integrations)
│   ├── sigil-scan/         # skills.sh integration
│   ├── mcp-server/         # ← MOVED from plugins/
│   └── tests/              # Skill integration tests
├── plugins/                # IDE-specific integrations
│   ├── vscode/             # VS Code extension
│   └── jetbrains/          # JetBrains plugin
├── packages/               # ← NEW: Shared libraries
│   ├── shared-types/       # Common TypeScript types
│   ├── detection-engine/   # Core scanning logic
│   ├── quarantine-core/    # Quarantine workflow
│   └── brand/              # Design system & brand assets
├── examples/               # ← NEW: Infrastructure templates
│   ├── terraform/          # Public Terraform templates (no secrets)
│   ├── docker/             # Docker examples
│   └── github-actions/     # CI/CD examples
├── docs/                   # ← CONSOLIDATED: All documentation
│   ├── getting-started.md  # User onboarding
│   ├── cli/                # CLI reference
│   ├── api/                # API documentation
│   ├── deployment/         # Public deployment guides
│   ├── security/           # Security model
│   ├── architecture/       # System design
│   ├── marketing/          # ← Internal marketing docs from sigilsec
│   └── brand/              # ← Brand guidelines from sigilsec
├── scripts/                # ← NEW: Unified build scripts
│   ├── build-all.sh        # Build all components
│   ├── test-all.sh         # Run all tests
│   └── deploy-preview.sh   # Preview deployments
├── .github/                # ← CONSOLIDATED: Unified CI/CD
│   └── workflows/
│       ├── cli-release.yml
│       ├── api-deploy.yml
│       ├── dashboard-deploy.yml
│       ├── marketing-deploy.yml
│       └── skills-publish.yml
├── Makefile                # ← ENHANCED: Multi-component orchestration
├── workspace.json          # ← NEW: Multi-language workspace
├── package.json            # ← ROOT: Workspace management
└── README.md               # ← UNIFIED: Single entry point
```

### Infrastructure Repository (UNCHANGED)

```
sigil-infra/                # ✅ NO CHANGES - Perfect separation
├── azure/terraform/        # Production secrets & configs
├── scripts/deploy.sh       # Deployment automation  
└── docs/deployment/        # Internal infrastructure docs
```

## Migration Benefits

### 1. **Developer Experience** 
- **Single Clone**: `git clone sigil` gets everything
- **Unified Build**: Single Makefile orchestrates all components
- **Shared Dependencies**: Common packages reduce duplication
- **Cross-Component Features**: Atomic PRs for features spanning CLI + Dashboard + Marketing

### 2. **Community Growth**
- **Lower Barrier**: One repo to understand and contribute to
- **Transparent Pro Features**: Users see what they get with upgrades
- **Comprehensive Examples**: Templates for all deployment scenarios
- **Unified Documentation**: Single source of truth

### 3. **Commercial Benefits** 
- **Clear Value Prop**: Pro features visible but gated with upgrade prompts
- **Integrated Marketing**: Install flows link to marketing site seamlessly
- **Faster Development**: No cross-repo synchronization delays
- **Better Analytics**: Unified tracking across all touchpoints

### 4. **Operational Benefits**
- **Single Release Pipeline**: Coordinated releases across all components
- **Shared CI/CD**: Common build patterns and security scanning
- **Unified Branding**: Consistent design system across all interfaces
- **Simplified Maintenance**: One repo to monitor, update, and secure

## What Stays Private vs. Public

### 🔒 STAYS PRIVATE: `sigil-infra`
- Azure subscription IDs
- Database connection strings 
- Production secrets and keys
- Internal deployment automation
- Infrastructure runbooks

### 🌍 BECOMES PUBLIC: Everything in unified `sigil`
- **Marketing site code** (builds sigilsec.ai) - ✅ No sensitive data
- **Pro features** (gated but visible) - ✅ Transparent value proposition
- **Infrastructure templates** (placeholder values) - ✅ Community benefit
- **Skills integrations** - ✅ Open ecosystem
- **Documentation** - ✅ Better community onboarding

## Risk Mitigation

### Potential Concerns
1. **"Commercial code in open source"** → Pro features are gated, not hidden
2. **"Marketing site should be private"** → Contains no secrets, benefits from transparency
3. **"Complex build system"** → Modern workspace tools handle this well
4. **"License conflicts"** → Clear separation with feature gating

### Mitigation Strategies
1. **Feature Gating System**: Pro features require authentication
2. **Clear Licensing**: Apache 2.0 for OSS features, commercial license for Pro
3. **Gradual Migration**: Phase rollout with fallbacks
4. **Community Communication**: Clear messaging about benefits
5. **Documentation**: Comprehensive migration and usage guides

## Success Metrics

### Development Velocity
- [ ] Reduced context switching (single repo)
- [ ] Faster CI/CD pipelines (parallel builds)
- [ ] Improved code sharing (shared packages)
- [ ] Atomic feature development (cross-component PRs)

### Community Growth  
- [ ] Increased GitHub stars and forks
- [ ] More community contributions
- [ ] Reduced support burden (better docs)
- [ ] Higher conversion to Pro (transparent features)

### Commercial Success
- [ ] Improved trial-to-paid conversion
- [ ] Reduced customer acquisition cost
- [ ] Faster feature development cycles
- [ ] Better user experience consistency

---

**Next**: Execute migration strategy in phases to minimize risk and disruption.