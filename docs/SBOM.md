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
| **SBOM Formats** | CycloneDX 1.5 JSON, SPDX JSON, Markdown |
| **CycloneDX SBOM** | [`docs/sbom.cdx.json`](sbom.cdx.json) (machine-readable) |
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
| SBOM & Attestation | `.github/workflows/sbom.yml` | Automated SBOM generation & Cosign signing |

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

## 13. Security Posture

### Supply Chain Integrity

| Control | Status | Detail |
|---------|--------|--------|
| Source builds (no vendored binaries) | Strong | Rust CLI compiled from source; no prebuilt binaries in repo |
| Release checksums | Strong | SHA-256 checksums published with every GitHub Release |
| SBOM attestation | Strong | Cosign keyless signing on all SBOMs via Sigstore OIDC |
| Python dependency pinning | Strong | `requirements.lock` files with exact pinned versions for `api/` and `bot/`; Dockerfiles use lock files |
| npm dependency pinning | Partial | `next` pinned exactly; all others use `^` caret ranges |
| Docker base image pinning | Strong | All base images pinned to `@sha256:` digest hashes in Dockerfiles and docker-compose |
| GitHub Actions pinning | Strong | All 67 action references across 7 workflows pinned to full commit SHAs |
| `.dockerignore` | Strong | Excludes `.git`, `.github`, `docs/`, `node_modules/`, `__pycache__/`, `.env` files |

### Authentication & Authorization

| Control | Status | Detail |
|---------|--------|--------|
| Password hashing | Strong | bcrypt (preferred) with PBKDF2-SHA256 fallback (100k iterations) |
| JWT signing | Strong | HS256 via `python-jose`; startup warning if default secret detected |
| Constant-time comparison | Strong | `hmac.compare_digest()` used for all token/password verification |
| Login rate limiting | Strong | 10 attempts / 5 minutes per IP via Redis INCR with TTL; distributed across instances, survives restarts |
| API rate limiting | Strong | Global per-IP middleware (200 req/min) + per-endpoint limits on auth, scan, and billing routes |
| Token revocation | Strong | Redis-backed blocklist with auto-expiry matching JWT lifetime; no memory caps needed |
| CORS | Strong | Configurable origins; defaults to localhost in dev |

### Cryptographic Practices

| Control | Status | Detail |
|---------|--------|--------|
| JWT algorithm | Strong | HS256 (HMAC-SHA256) |
| Password storage | Strong | bcrypt / PBKDF2-SHA256 — no plaintext or reversible encryption |
| Token generation | Strong | SHA-256 hashed reset tokens |
| TLS enforcement | Strong | HSTS header (`max-age=31536000`) set in production mode |
| Database TLS | Strong | `ssl="require"` on asyncpg connections |
| Deprecated crypto | None found | No MD5, SHA1, DES, or RC4 in use |

### Container Hardening

| Control | Status | Detail |
|---------|--------|--------|
| Non-root user | Strong | `sigil:1001` in all Dockerfiles; `USER sigil` before `ENTRYPOINT` |
| Init process | Strong | `tini` for PID 1 signal handling and zombie reaping |
| Privileged mode | Strong | No `--privileged`, `cap_add`, or host network in compose |
| Health checks | Strong | All services have `HEALTHCHECK` with interval/timeout/retries |
| Layer cleanup | Strong | `rm -rf /var/lib/apt/lists/*` after package installs |
| Secrets in image | Strong | No hardcoded secrets; all via environment variables |

### Data Handling

| Control | Status | Detail |
|---------|--------|--------|
| Telemetry | None | No analytics SDKs; Next.js telemetry explicitly disabled |
| Local-first scanning | Strong | CLI scans process entirely locally; cloud API opt-in only |
| Credential storage | Strong | CLI token stored at `~/.sigil/token` with `chmod 600` |
| Cloud data flow | Transparent | Authenticated scans send hash lookups + receive threat intel signatures |

### Input Validation & Hardening

| Control | Status | Detail |
|---------|--------|--------|
| CLI URL validation | Strong | Regex validation before `git clone`, `curl` |
| Package name validation | Strong | Alphanumeric + hyphen/underscore/dot regex; rejects injection chars |
| Quarantine ID validation | Strong | Alphanumeric + underscore only; `realpath` traversal check |
| `eval`/`exec` in API | None found | No dynamic code execution in production Python code |
| `shell=True` subprocess | None found | No unsafe subprocess invocations |

### Vulnerability Disclosure

Sigil maintains a security policy at `SECURITY.md` with:
- Reporting: `security@sigilsec.ai`
- 48-hour acknowledgment SLA
- 7-day patch SLA for critical vulnerabilities

### Resolved Gaps (Hardening Log)

All previously identified gaps have been addressed:

| Gap | Original Risk | Resolution |
|-----|--------------|------------|
| Python deps unpinned (`>=`) | Medium — supply chain | `api/requirements.lock` and `bot/requirements.lock` with exact pinned versions; Dockerfiles updated |
| Docker images use tags, not digests | Medium — image mutability | All base images in Dockerfiles and docker-compose pinned to `@sha256:` digests |
| GitHub Actions use version tags | Medium — action supply chain | All 67 references across 7 workflows pinned to full commit SHAs |
| No `.dockerignore` | Low — image bloat / info leak | `.dockerignore` added excluding `.git`, `.github`, `docs/`, `node_modules/`, `.env` |
| In-memory rate limiter | Medium — bypass on restart | Redis-backed sliding window via `cache.incr()` with TTL; distributed, survives restarts |
| In-memory token revocation | Medium — bypass on restart | Redis-backed blocklist with auto-expiry matching JWT lifetime |
| No per-endpoint API rate limits | Medium — abuse | `RateLimitMiddleware` (200 req/min global) + `RateLimiter` dependency on auth, scan, billing endpoints |

### Remaining Considerations

| Area | Risk | Notes |
|------|------|-------|
| npm dependency pinning | Low | `next` pinned exactly; others use `^` caret — standard npm practice, mitigated by `package-lock.json` |
| Redis availability | Low | All Redis-backed features (rate limiting, token revocation) gracefully fall back to in-memory when Redis is unavailable |

---

## 14. SBOM Generation & Attestation

### Machine-Readable Formats

This document is the human-readable companion to machine-readable SBOMs:

| Format | Standard | File | Use Case |
|--------|----------|------|----------|
| CycloneDX 1.5 JSON | OWASP | `docs/sbom.cdx.json` | CI/CD integration, vulnerability scanning |
| SPDX JSON | ISO/IEC 5962:2021 | Generated at release time | Regulatory compliance, license audits |

### Automated Generation (CI/CD)

SBOMs are automatically generated on every tagged release via `.github/workflows/sbom.yml`:

1. **Source SBOMs** — Generated by [Syft](https://github.com/anchore/syft) scanning the repository (CycloneDX + SPDX)
2. **Container SBOMs** — Generated by Syft scanning the `nomark/sigil` and `nomark/sigil-full` Docker images (CycloneDX + SPDX)
3. **Attestation** — All 6 SBOM files are cryptographically signed with [Cosign](https://github.com/sigstore/cosign) keyless signing (Sigstore OIDC)
4. **Publication** — SBOMs, attestations, and checksums are attached to the GitHub Release

### Verification

```bash
# Verify SBOM checksums
sha256sum -c SBOM-SHA256SUMS.txt

# Verify Cosign attestation
cosign verify-blob-attestation \
  --signature sbom-source.cdx.json.att \
  --insecure-ignore-tlog \
  sbom-source.cdx.json
```

### Limitations

SBOMs provide inventory visibility but **cannot detect malicious behavior** such as backdoors, data exfiltration, or obfuscated payloads. For behavioral threat detection, use Sigil's scanning engine (`sigil scan`) alongside SBOM-based vulnerability tracking.

---

*Generated for Sigil v1.0.5 on 2026-02-28.*
