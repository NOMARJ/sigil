# Software Bill of Materials (SBOM)

## Sigil — Automated Security Auditing for AI Agent Code

| Field | Value |
|-------|-------|
| **Product** | Sigil |
| **Version** | 1.0.5 |
| **Supplier** | NOMARK (team@sigilsec.ai) |
| **License** | Apache-2.0 |
| **Repository** | https://github.com/NOMARJ/sigil |
| **Website** | https://sigilsec.ai |
| **SBOM Format** | Custom Markdown (CycloneDX-inspired) |
| **SBOM Generated** | 2026-02-28 |
| **Commit** | c7ad46ab836dcc1f0c7cfd62f1af9383cdc9ea3e |

---

## 1. Component Overview

Sigil is a multi-component system with the following top-level modules:

| Component | Type | Language/Runtime | Location |
|-----------|------|------------------|----------|
| CLI (Bash) | Application | Bash | `bin/sigil` |
| CLI (Rust) | Application | Rust 2021 Edition | `cli/` |
| API Service | Application | Python 3.11 | `api/` |
| Bot (Registry Monitor) | Application | Python 3.11 | `bot/` |
| Dashboard | Web Application | Node.js 20 / Next.js | `dashboard/` |
| VS Code Extension | IDE Plugin | TypeScript | `plugins/vscode/` |
| JetBrains Plugin | IDE Plugin | Kotlin/Java | `plugins/jetbrains/` |
| MCP Server | Service | TypeScript (Node.js) | `plugins/mcp-server/` |
| Claude Code Plugin | Agent Plugin | Markdown/JSON | `plugins/claude-code/` |
| GitHub Action | CI/CD | Bash (Composite) | `action.yml` |
| Homebrew Formula | Distribution | Ruby | `Formula/sigil.rb` |
| npm Package | Distribution | Node.js | `package.json` |

---

## 2. Rust CLI Dependencies (`cli/Cargo.toml`)

| Package | Version | Purpose | License |
|---------|---------|---------|---------|
| clap | 4.x (derive) | CLI argument parsing | MIT/Apache-2.0 |
| serde | 1.x (derive) | Serialization framework | MIT/Apache-2.0 |
| serde_json | 1.x | JSON serialization | MIT/Apache-2.0 |
| tokio | 1.x (full) | Async runtime | MIT |
| reqwest | 0.11 (json) | HTTP client | MIT/Apache-2.0 |
| regex | 1.x | Regular expressions | MIT/Apache-2.0 |
| walkdir | 2.x | Recursive directory traversal | MIT/Unlicense |
| sha2 | 0.10 | SHA-256 hashing | MIT/Apache-2.0 |
| hex | 0.4 | Hex encoding/decoding | MIT/Apache-2.0 |
| colored | 2.x | Terminal color output | MPL-2.0 |
| dirs | 5.x | Platform-specific directories | MIT/Apache-2.0 |
| chrono | 0.4 (serde) | Date/time handling | MIT/Apache-2.0 |
| uuid | 1.x (v4) | UUID generation | MIT/Apache-2.0 |
| zip | 0.6 | ZIP archive handling | MIT |
| flate2 | 1.x | Gzip compression | MIT/Apache-2.0 |
| tar | 0.4 | TAR archive handling | MIT/Apache-2.0 |

---

## 3. Python API Dependencies (`api/requirements.txt`)

| Package | Version Constraint | Purpose | License |
|---------|-------------------|---------|---------|
| fastapi | >=0.109.0 | Web framework | MIT |
| uvicorn | >=0.27.0 | ASGI server | BSD-3-Clause |
| pydantic | >=2.5.0 | Data validation | MIT |
| pydantic-settings | >=2.1.0 | Settings management | MIT |
| httpx | >=0.26.0 | Async HTTP client | BSD-3-Clause |
| python-jose[cryptography] | >=3.3.0 | JWT/JWS/JWE | MIT |
| passlib[bcrypt] | >=1.7.4 | Password hashing | BSD-3-Clause |
| bcrypt | >=4.1.0 | Bcrypt hashing | Apache-2.0 |
| python-multipart | >=0.0.6 | Multipart form parsing | Apache-2.0 |
| supabase | >=2.3.0 | Supabase client SDK | MIT |
| asyncpg | >=0.29.0 | PostgreSQL async driver | Apache-2.0 |
| redis | >=5.0.0 | Redis client | MIT |
| stripe | >=7.0.0 | Stripe payments SDK | MIT |
| eval_type_backport | >=0.3.0 | Python type eval backport | MIT |
| pytest | >=7.4.0 | Testing framework (dev) | MIT |
| pytest-asyncio | >=0.23.0 | Async test support (dev) | Apache-2.0 |

---

## 4. Python Bot Dependencies (`bot/requirements.txt`)

| Package | Version Constraint | Purpose | License |
|---------|-------------------|---------|---------|
| redis | >=5.0.0 | Redis client (job queue) | MIT |
| httpx | >=0.27.0 | Async HTTP client | BSD-3-Clause |
| pydantic | >=2.0 | Data validation | MIT |
| pydantic-settings | >=2.0 | Settings management | MIT |

---

## 5. Next.js Dashboard Dependencies (`dashboard/package.json`)

### Production

| Package | Version | Purpose | License |
|---------|---------|---------|---------|
| next | 14.2.5 | React framework | MIT |
| react | ^18.3.1 | UI library | MIT |
| react-dom | ^18.3.1 | React DOM renderer | MIT |
| @supabase/supabase-js | ^2.97.0 | Supabase client SDK | MIT |

### Development

| Package | Version | Purpose | License |
|---------|---------|---------|---------|
| typescript | ^5.5.3 | TypeScript compiler | Apache-2.0 |
| @types/node | ^20.14.10 | Node.js type definitions | MIT |
| @types/react | ^18.3.3 | React type definitions | MIT |
| @types/react-dom | ^18.3.0 | React DOM type definitions | MIT |
| eslint | ^8.57.1 | JavaScript linter | MIT |
| eslint-config-next | ^14.2.5 | Next.js ESLint config | MIT |
| autoprefixer | ^10.4.19 | CSS vendor prefixer | MIT |
| postcss | ^8.4.39 | CSS transformer | MIT |
| tailwindcss | ^3.4.4 | Utility CSS framework | MIT |

---

## 6. VS Code Extension Dependencies (`plugins/vscode/package.json`)

### Development Only (no production dependencies)

| Package | Version | Purpose | License |
|---------|---------|---------|---------|
| typescript | ^5.5.0 | TypeScript compiler | Apache-2.0 |
| @types/node | ^20.14.0 | Node.js type definitions | MIT |
| @types/vscode | ^1.85.0 | VS Code API types | MIT |
| @typescript-eslint/eslint-plugin | ^7.0.0 | TS ESLint rules | MIT |
| @typescript-eslint/parser | ^7.0.0 | TS ESLint parser | BSD-2-Clause |
| @vscode/vsce | ^2.26.0 | VS Code extension packager | MIT |
| eslint | ^8.57.0 | JavaScript linter | MIT |

### Runtime Requirements

- VS Code Engine: ^1.85.0
- External: `sigil` CLI binary on PATH

---

## 7. MCP Server Dependencies (`plugins/mcp-server/package.json`)

### Production

| Package | Version | Purpose | License |
|---------|---------|---------|---------|
| @modelcontextprotocol/sdk | ^1.0.0 | MCP protocol SDK | MIT |
| zod | ^3.22.0 | Schema validation | MIT |

### Development

| Package | Version | Purpose | License |
|---------|---------|---------|---------|
| typescript | ^5.5.0 | TypeScript compiler | Apache-2.0 |
| @types/node | ^20.14.0 | Node.js type definitions | MIT |
| @typescript-eslint/eslint-plugin | ^7.0.0 | TS ESLint rules | MIT |
| @typescript-eslint/parser | ^7.0.0 | TS ESLint parser | BSD-2-Clause |
| eslint | ^8.57.0 | JavaScript linter | MIT |

---

## 8. JetBrains Plugin Dependencies (`plugins/jetbrains/build.gradle.kts`)

| Package | Version | Purpose | License |
|---------|---------|---------|---------|
| org.jetbrains.kotlin.jvm | 1.9.25 | Kotlin compiler plugin | Apache-2.0 |
| org.jetbrains.intellij.platform | 2.2.1 | IntelliJ plugin SDK | Apache-2.0 |
| com.google.code.gson:gson | 2.11.0 | JSON parsing | Apache-2.0 |
| IntelliJ IDEA Community | 2024.1 | Platform dependency | Apache-2.0 |

### Runtime Requirements

- JDK: 17+
- IntelliJ Platform: 241 — 252.*

---

## 9. Bash CLI System Dependencies (`bin/sigil`)

The Bash CLI uses standard POSIX utilities plus optional security scanners:

### Required

| Tool | Purpose |
|------|---------|
| bash | Shell interpreter |
| grep | Pattern matching |
| find | File discovery |
| file | File type detection |
| git | Repository operations |
| curl | HTTP requests |
| sha256sum | Hash computation |
| tar | Archive extraction |
| unzip | ZIP extraction |
| python3 | JSON processing helper |

### Optional Security Scanners

| Tool | Install Method | Purpose |
|------|---------------|---------|
| semgrep | `pip install semgrep` | Static analysis |
| bandit | `pip install bandit` | Python security linting |
| trufflehog | `brew install trufflehog` | Secret detection |
| safety | `pip install safety` | Python dependency vulnerability check |

---

## 10. Container / Infrastructure Dependencies

### Docker Base Images

| Image | Used In | Purpose |
|-------|---------|---------|
| rust:1.76-slim | Dockerfile (Stage 1) | Rust CLI build |
| rust:1.75-alpine | Dockerfile.cli (Build) | Rust CLI build (Alpine) |
| node:20-slim | Dockerfile (Stage 2), docker-compose | Dashboard build & dev |
| python:3.11-slim-bookworm | Dockerfile (Stage 3), Dockerfile.api | API/Bot runtime |
| alpine:3.19 | Dockerfile.cli (Runtime) | CLI runtime (minimal) |
| postgres:16-alpine | docker-compose | PostgreSQL database |
| redis:7-alpine | docker-compose | Redis cache/queue |

### Container Runtime Packages

| Package | Image | Purpose |
|---------|-------|---------|
| git | runtime, alpine | Repository operations |
| curl | runtime, alpine, api | HTTP requests / health check |
| file | runtime, alpine | File type detection |
| tini | runtime, api | PID 1 init process |
| nodejs + npm | runtime | Dashboard server |
| ca-certificates | alpine | TLS cert store |
| libgcc | alpine | C runtime |
| bash | alpine | Shell |
| grep | alpine | Pattern matching |
| python3 | alpine | JSON processing |
| musl-dev | builder (alpine) | C library (build) |
| openssl-dev | builder (alpine) | TLS (build) |
| pkgconfig | builder (alpine) | Build config |

---

## 11. CI/CD & Distribution

### GitHub Actions Workflows

| Workflow | File | Purpose |
|----------|------|---------|
| CI | `.github/workflows/ci.yml` | Tests, linting, build verification |
| Docker | `.github/workflows/docker.yml` | Container image build & push |
| Release | `.github/workflows/release.yml` | Binary releases & artifacts |
| Deploy Azure | `.github/workflows/deploy-azure.yml` | Azure deployment |
| Publish Plugin | `.github/workflows/publish-plugin.yml` | Plugin publishing |
| Update Homebrew | `.github/workflows/update-homebrew.yml` | Homebrew formula update |

### Distribution Channels

| Channel | Identifier | Format |
|---------|-----------|--------|
| npm | `@nomarj/sigil` | npm package |
| Homebrew | `nomarj/tap/sigil` | Formula |
| GitHub Releases | `NOMARJ/sigil` | Binary tarballs |
| Docker Hub / GHCR | `sigil` | Container images |
| VS Code Marketplace | `nomark.sigil-security` | VSIX extension |
| JetBrains Marketplace | `dev.nomark.sigil` | ZIP plugin |
| GitHub Action | `NOMARJ/sigil@v1` | Composite action |

---

## 12. License Summary

| License | Count | Packages |
|---------|-------|----------|
| MIT | ~30 | fastapi, react, next, redis, stripe, pydantic, serde, tokio, etc. |
| Apache-2.0 | ~12 | Sigil itself, bcrypt, asyncpg, Kotlin, IntelliJ, TypeScript, etc. |
| BSD-3-Clause | 3 | uvicorn, httpx, passlib |
| BSD-2-Clause | 1 | @typescript-eslint/parser |
| MPL-2.0 | 1 | colored (Rust) |
| MIT/Unlicense | 1 | walkdir (Rust) |

**Primary project license:** Apache-2.0

---

## 13. Security Considerations

- **No vendored binaries** in source (Rust CLI built from source)
- **Pinned base images** in Dockerfiles with specific tags
- **Non-root container user** (`sigil:1001`) in all Dockerfiles
- **Health checks** on all containerized services
- **Signal handling** via `tini` init process
- **Input validation** on CLI arguments (URL, package name, quarantine ID format)
- **Path traversal protection** on approve/reject commands
- **Token storage** with `chmod 600` permissions

---

*Generated for Sigil v1.0.5 on 2026-02-28.*
