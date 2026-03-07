# Sigil Repository Migration Strategy

**Date**: March 7, 2026  
**Status**: Implementation Guide  
**Timeline**: 3-4 weeks  
**Risk**: Low (incremental with fallbacks)

## Migration Overview

**Goal**: Consolidate 3 public repositories into 1 unified repository while keeping `sigil-infra` private.

**Current → Target:**
- `sigil` + `sigilsec` + `sigil-skill` → **unified `sigil`**
- `sigil-infra` → **unchanged** ✅

## Pre-Migration Checklist

### Week 0: Preparation (2-3 days)
- [ ] **Audit Dependencies**: Document all external references to current repos
- [ ] **Backup Strategy**: Create complete backups of all 4 repositories
- [ ] **Access Review**: Ensure team has necessary permissions
- [ ] **Communication Plan**: Draft announcement for community
- [ ] **Rollback Plan**: Document how to revert if migration fails

### Dependencies to Audit
```bash
# Find all external references to current repo structure
grep -r "github.com/NOMARJ/sigilsec" .
grep -r "github.com/NOMARJ/sigil-skill" .
grep -r "sigilsec.ai" .
```

**Known dependencies:**
- Package manager references (npm, skills.sh)
- CI/CD webhooks and integrations  
- Documentation links
- Marketing site redirects
- API endpoints and domains

## Phase 1: Infrastructure Setup (Week 1)

### 1.1 Create New Repository Structure
```bash
# Create backup of current main repo
cd /Users/reecefrazier/CascadeProjects
cp -r sigil sigil-backup-$(date +%Y%m%d)

# Create new unified structure in sigil repo
cd sigil
mkdir -p marketing packages/shared-types packages/detection-engine packages/quarantine-core packages/brand examples/terraform examples/docker examples/github-actions scripts
```

### 1.2 Migrate sigil-skill
```bash
# Move sigil-skill to skills/ directory
cd /Users/reecefrazier/CascadeProjects/sigil
mv sigil-skill skills-temp
mkdir -p skills
mv skills-temp/* skills/
rmdir skills-temp

# Move MCP server from plugins to skills
mv plugins/mcp-server skills/
```

### 1.3 Migrate sigilsec Marketing Site
```bash
# Copy sigilsec content to marketing/ directory
cd /Users/reecefrazier/CascadeProjects/sigil
cp -r ../sigilsec/src marketing/
cp -r ../sigilsec/components marketing/
cp -r ../sigilsec/public marketing/
cp ../sigilsec/package.json marketing/
cp ../sigilsec/next.config.js marketing/
cp ../sigilsec/tailwind.config.ts marketing/
cp ../sigilsec/tsconfig.json marketing/

# Extract internal docs
mkdir -p docs/marketing docs/brand
cp -r ../sigilsec/docs/* docs/marketing/
cp ../sigilsec/*.md docs/marketing/
```

### 1.4 Create Shared Packages Structure
```bash
# Extract common types
mkdir -p packages/shared-types/src
echo '{
  "name": "@sigil/shared-types",
  "version": "0.1.0",
  "type": "module",
  "exports": {
    ".": "./src/index.ts"
  }
}' > packages/shared-types/package.json

# Create detection engine package
mkdir -p packages/detection-engine/src
echo '{
  "name": "@sigil/detection-engine", 
  "version": "0.1.0",
  "type": "module",
  "exports": {
    ".": "./src/index.ts"
  }
}' > packages/detection-engine/package.json

# Create quarantine core package
mkdir -p packages/quarantine-core/src
echo '{
  "name": "@sigil/quarantine-core",
  "version": "0.1.0", 
  "type": "module",
  "exports": {
    ".": "./src/index.ts"
  }
}' > packages/quarantine-core/package.json

# Create brand package
mkdir -p packages/brand/src
echo '{
  "name": "@sigil/brand",
  "version": "0.1.0",
  "type": "module",
  "exports": {
    ".": "./src/index.ts"
  }
}' > packages/brand/package.json
```

### 1.5 Create Infrastructure Templates
```bash
# Create public Terraform templates (no secrets)
mkdir -p examples/terraform
cat > examples/terraform/main.tf << 'EOF'
# Sigil Infrastructure Template
# This is a template - replace placeholder values with actual configs
# For production secrets, see private sigil-infra repository

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~>3.0"
    }
  }
}

# Example Container App Environment
resource "azurerm_container_app_environment" "sigil" {
  name                = "sigil-env-${var.environment}"
  location            = var.location
  resource_group_name = var.resource_group_name
  
  tags = {
    Environment = var.environment
    Project     = "sigil"
  }
}

# Variables (replace with actual values)
variable "environment" {
  description = "Environment name (dev/staging/prod)"
  type        = string
  default     = "dev"
}

variable "location" {
  description = "Azure region"
  type        = string
  default     = "East US"
}

variable "resource_group_name" {
  description = "Resource group name"
  type        = string
}
EOF

# Docker examples
mkdir -p examples/docker
cat > examples/docker/Dockerfile.api << 'EOF'
# Example Dockerfile for Sigil API
FROM python:3.11-slim

WORKDIR /app
COPY api/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY api/ .
EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
EOF

# GitHub Actions examples  
mkdir -p examples/github-actions
cat > examples/github-actions/deploy-api.yml << 'EOF'
# Example GitHub Actions workflow for API deployment
name: Deploy API

on:
  push:
    branches: [main]
    paths: ['api/**']

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - run: pip install -r api/requirements.txt
      - run: pytest api/tests/
      # Add actual deployment steps here
EOF
```

## Phase 2: Build System Integration (Week 1-2)

### 2.1 Create Unified Workspace
```bash
# Root package.json for workspace management
cat > package.json << 'EOF'
{
  "name": "@sigil/monorepo",
  "private": true,
  "scripts": {
    "build": "npm run build:all",
    "build:all": "./scripts/build-all.sh",
    "test": "./scripts/test-all.sh",
    "lint": "npm run lint:all",
    "lint:all": "eslint --ext .ts,.tsx,.js,.jsx --max-warnings 0 dashboard marketing skills",
    "format": "prettier --write .",
    "dev:dashboard": "cd dashboard && npm run dev",
    "dev:marketing": "cd marketing && npm run dev",
    "build:dashboard": "cd dashboard && npm run build",
    "build:marketing": "cd marketing && npm run build",
    "build:cli": "cd cli && cargo build --release",
    "test:dashboard": "cd dashboard && npm test",
    "test:marketing": "cd marketing && npm test", 
    "test:cli": "cd cli && cargo test",
    "test:api": "cd api && pytest",
    "deploy:preview": "./scripts/deploy-preview.sh"
  },
  "workspaces": [
    "dashboard",
    "marketing", 
    "packages/*",
    "skills/*",
    "plugins/*"
  ],
  "devDependencies": {
    "@typescript-eslint/eslint-plugin": "^6.0.0",
    "@typescript-eslint/parser": "^6.0.0",
    "eslint": "^8.0.0",
    "prettier": "^3.0.0",
    "typescript": "^5.0.0"
  }
}
EOF

# Enhanced Makefile
cat > Makefile << 'EOF'
.PHONY: help dev build test lint format clean install

help:
	@echo "Sigil Unified Repository Commands"
	@echo ""
	@echo "Development:"
	@echo "  make dev          Start all development servers"
	@echo "  make install      Install all dependencies"
	@echo ""
	@echo "Building:"
	@echo "  make build        Build all components"
	@echo "  make build-cli    Build Rust CLI only"
	@echo "  make build-web    Build web components only"
	@echo ""
	@echo "Testing:"
	@echo "  make test         Run all tests"
	@echo "  make test-unit    Unit tests only"
	@echo "  make test-integration Integration tests"
	@echo ""
	@echo "Quality:"
	@echo "  make lint         Lint all code"
	@echo "  make format       Format all code"
	@echo ""
	@echo "Deployment:"
	@echo "  make preview      Deploy preview environment"
	@echo "  make build-push   Build and push containers"

dev:
	@echo "Starting Sigil development environment..."
	npm run dev:dashboard &
	npm run dev:marketing &
	cd api && python -m uvicorn main:app --reload --port 8001 &
	wait

build: build-cli build-web

build-cli:
	cd cli && cargo build --release

build-web:
	npm run build:dashboard
	npm run build:marketing

test:
	npm run test

lint:
	npm run lint

format:
	npm run format

clean:
	rm -rf dashboard/.next dashboard/dist
	rm -rf marketing/.next marketing/dist  
	cd cli && cargo clean
	find . -name "node_modules" -type d -exec rm -rf {} +
	find . -name "*.pyc" -delete

install:
	npm install
	cd cli && cargo fetch
	cd api && pip install -r requirements.txt
EOF
```

### 2.2 Create Build Scripts
```bash
# Unified build script
cat > scripts/build-all.sh << 'EOF'
#!/bin/bash
set -e

echo "🏗️  Building Sigil Components..."

# Build Rust CLI
echo "📦 Building CLI..."
cd cli && cargo build --release && cd ..

# Build Python API
echo "🐍 Building API..."
cd api && python -m py_compile *.py && cd ..

# Build Next.js Dashboard
echo "📊 Building Dashboard..."
cd dashboard && npm run build && cd ..

# Build Marketing Site
echo "🌐 Building Marketing Site..."
cd marketing && npm run build && cd ..

# Build Skills
echo "🔧 Building Skills..."
cd skills && npm test && cd ..

echo "✅ All components built successfully!"
EOF

chmod +x scripts/build-all.sh

# Unified test script
cat > scripts/test-all.sh << 'EOF'
#!/bin/bash
set -e

echo "🧪 Running Sigil Tests..."

# Test Rust CLI
echo "📦 Testing CLI..."
cd cli && cargo test && cd ..

# Test Python API
echo "🐍 Testing API..."
cd api && python -m pytest && cd ..

# Test Next.js Dashboard  
echo "📊 Testing Dashboard..."
cd dashboard && npm test -- --watchAll=false && cd ..

# Test Marketing Site
echo "🌐 Testing Marketing..."
cd marketing && npm test -- --watchAll=false && cd ..

# Test Skills
echo "🔧 Testing Skills..."
cd skills && npm test && cd ..

echo "✅ All tests passed!"
EOF

chmod +x scripts/test-all.sh
```

## Phase 3: CI/CD Migration (Week 2)

### 3.1 Unified GitHub Actions
```bash
mkdir -p .github/workflows

# Main workflow
cat > .github/workflows/main.yml << 'EOF'
name: Sigil CI/CD

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '18'
          cache: 'npm'
          
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
          
      - name: Setup Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
          
      - name: Install dependencies
        run: make install
        
      - name: Run linting
        run: make lint
        
      - name: Run tests
        run: make test
        
      - name: Build all components
        run: make build

  deploy-preview:
    runs-on: ubuntu-latest
    if: github.event_name == 'pull_request'
    needs: test
    steps:
      - uses: actions/checkout@v4
      - name: Deploy preview
        run: make preview
        env:
          VERCEL_TOKEN: ${{ secrets.VERCEL_TOKEN }}

  deploy-production:
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    needs: test
    steps:
      - uses: actions/checkout@v4
      - name: Deploy production
        run: ./scripts/deploy-production.sh
        env:
          VERCEL_TOKEN: ${{ secrets.VERCEL_TOKEN }}
          AZURE_CREDENTIALS: ${{ secrets.AZURE_CREDENTIALS }}
EOF

# Component-specific workflows
cat > .github/workflows/cli-release.yml << 'EOF'
name: CLI Release

on:
  push:
    tags:
      - 'v*'
    paths:
      - 'cli/**'

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
      - name: Build CLI
        run: cd cli && cargo build --release
      - name: Create release
        uses: actions/create-release@v1
        with:
          tag_name: ${{ github.ref }}
          release_name: Sigil CLI ${{ github.ref }}
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
EOF
```

## Phase 4: Documentation & External References (Week 2-3)

### 4.1 Update All Documentation
```bash
# Create unified README
cat > README.md << 'EOF'
# Sigil

Automated security auditing for AI agent code. Scan repos, packages, and agent tooling for malicious patterns using a quarantine-first workflow.

## 🚀 Quick Start

```bash
# Install CLI
curl -sSL https://sigilsec.ai/install.sh | sh

# Scan a repository
sigil scan .

# Quarantine and scan before clone
sigil clone https://github.com/suspicious/repo

# Scan package before install
sigil pip package-name
```

## 📁 Repository Structure

This is a unified repository containing all Sigil components:

- **`cli/`** - Rust CLI tool for local security scanning
- **`api/`** - Python FastAPI backend service  
- **`dashboard/`** - Next.js web dashboard for teams
- **`marketing/`** - Marketing website (sigilsec.ai)
- **`skills/`** - AI agent integrations (MCP, skills.sh)
- **`plugins/`** - IDE extensions (VS Code, JetBrains)
- **`packages/`** - Shared libraries and utilities
- **`examples/`** - Infrastructure templates and examples
- **`docs/`** - Comprehensive documentation

## 🏗️ Development

```bash
# Install all dependencies
make install

# Start development environment
make dev

# Run all tests
make test

# Build all components
make build
```

## 🔒 Security

This repository contains **open source code only**. Infrastructure secrets and production configurations are maintained in a separate private repository.

## 📖 Documentation

- [Getting Started](docs/getting-started.md)
- [CLI Reference](docs/cli/)
- [API Documentation](docs/api/)
- [Deployment Guide](docs/deployment/)
- [Security Model](docs/security/)

## 🤝 Contributing

We welcome contributions! See our [Contributing Guide](CONTRIBUTING.md).

## 📄 License

Apache-2.0 License - see [LICENSE](LICENSE) file.

---

**Sigil by NOMARK** - A protective mark for every line of code.
EOF

# Update documentation links throughout
find docs/ -name "*.md" -exec sed -i.bak 's|github.com/NOMARJ/sigilsec|github.com/NOMARJ/sigil/tree/main/marketing|g' {} \;
find docs/ -name "*.md" -exec sed -i.bak 's|github.com/NOMARJ/sigil-skill|github.com/NOMARJ/sigil/tree/main/skills|g' {} \;
```

### 4.2 Update External References

**Package managers:**
```bash
# Update skills.sh package reference
# (Done in skills/package.json and npm publish)

# Update npm packages
# (Update package.json files with new repository URLs)

# Update Rust crate
# (Update Cargo.toml with new repository URL)
```

**Domain redirects:**
```bash
# Configure sigilsec.ai to serve from marketing/ subdirectory
# Update Vercel config to point to unified repo
```

## Phase 5: Deployment & Validation (Week 3-4)

### 5.1 Deploy Unified Repository
```bash
# Deploy marketing site from new location
cd marketing && vercel --prod

# Deploy dashboard from new location  
cd dashboard && vercel --prod

# Deploy API from new location
# (Use existing Azure Container Apps with updated source)

# Publish updated packages
cd skills && npm publish
cd plugins/vscode && vsce publish
```

### 5.2 Validation Checklist
- [ ] **All URLs resolve correctly**
  - sigilsec.ai serves from marketing/ 
  - API endpoints functional
  - Dashboard accessible
- [ ] **Package managers work**
  - `npx skills add sigil-scan` works
  - VS Code extension installs
  - CLI downloads correctly
- [ ] **CI/CD functional**
  - Tests pass on unified repo
  - Deployments work from single source
  - Releases publish correctly
- [ ] **Community migration**
  - GitHub stars/forks transferred
  - Issues migrated
  - Contributors notified

### 5.3 Archive Old Repositories
```bash
# Archive process (after validation)
# 1. Add deprecation notices to old repos
# 2. Redirect to new unified repo
# 3. Archive repositories (don't delete - preserve history)
# 4. Update all external links
```

## Rollback Plan

If migration fails:
1. **Restore from backup**: Copy backup repositories back
2. **Revert DNS**: Point domains back to original repos
3. **Republish packages**: Revert package.json changes
4. **Update references**: Restore external links
5. **Communicate**: Notify community of temporary rollback

## Risk Assessment

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| Broken external links | Medium | Medium | Comprehensive link audit + redirects |
| CI/CD failures | High | Low | Thorough testing + gradual rollout |
| Package conflicts | Medium | Low | Version management + testing |
| Community confusion | Low | Medium | Clear communication + documentation |
| Performance degradation | Medium | Low | Load testing + monitoring |

## Success Metrics

- [ ] **Zero downtime** during migration
- [ ] **All external integrations working** within 48 hours
- [ ] **Community acceptance** (positive feedback, no major issues)
- [ ] **Development velocity improved** (faster builds, easier contributions)
- [ ] **Documentation consolidated** (single source of truth)

---

**Timeline**: 3-4 weeks  
**Next**: Begin Phase 1 implementation