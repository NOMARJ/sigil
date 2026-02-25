# Phase 4: Infrastructure & Deployment

**Status: Solid (8/10)**

---

## Docker

### Dockerfiles — Security Best Practices ✅

| File | Base Image | Non-root | Health Check | Ports | Status |
|------|-----------|----------|-------------|-------|--------|
| `Dockerfile` (full stack) | python:3.11-slim-bookworm | ✅ sigil:1001 | ✅ All services | 8000, 3000 | ✅ |
| `Dockerfile.api` | python:3.11-slim-bookworm | ✅ sigil:sigil | ✅ /health | 8000 | ✅ |
| `Dockerfile.cli` | rust:1.77 → alpine:3.19 | ✅ | N/A (CLI) | N/A | ✅ |

All Dockerfiles use:
- Multi-stage builds for minimal image size
- Non-root users
- `tini` as PID 1 init process
- Proper signal handling
- No credentials baked in

### Docker Compose ✅

Services: API, Dashboard, PostgreSQL, Redis, api-prod (optional profile)

```yaml
# All services have health checks
# Proper dependency ordering (depends_on with condition: service_healthy)
# Volumes for persistence
# Bridge network for service communication
```

**Issue:** Dev JWT secret default exists (`dev-secret-change-in-production`) — acceptable for dev, but prod profile should fail without it.

---

## CI/CD Workflows

| Workflow | Trigger | Status | Notes |
|----------|---------|--------|-------|
| `ci.yml` | push/PR to main | ✅ Complete | ShellCheck, ruff, clippy, pytest, cargo test, self-scan |
| `release.yml` | git tags (v*) | ✅ Complete | Multi-platform builds, npm/cargo/GitHub publish |
| `docker.yml` | git tags + manual | ✅ Complete | Multi-arch (amd64/arm64), Docker Hub push |
| `update-homebrew.yml` | release published | ✅ Complete | Auto-updates homebrew-tap repo |
| `publish-plugin.yml` | manual/release | ✅ Complete | VS Code, JetBrains, Claude Code marketplace |

All workflows use:
- Concurrency controls (cancel previous runs)
- Proper secret handling (GitHub Secrets)
- `continue-on-error` for optional publish steps
- Multi-platform matrices

---

## Complete Environment Variable Inventory

### Required for Production

| Variable | Service | Purpose |
|----------|---------|---------|
| `SIGIL_JWT_SECRET` | API | JWT signing (min 32 chars) |
| `SIGIL_DATABASE_URL` | API | PostgreSQL connection string |
| `SIGIL_SUPABASE_URL` | API | Supabase project URL |
| `SIGIL_SUPABASE_KEY` | API | Supabase service role key |
| `SIGIL_CORS_ORIGINS` | API | Allowed CORS origins (JSON array) |
| `NEXT_PUBLIC_API_URL` | Dashboard | API endpoint URL |
| `NEXT_PUBLIC_SUPABASE_URL` | Dashboard | Supabase URL (client-side) |
| `NEXT_PUBLIC_SUPABASE_ANON_KEY` | Dashboard | Supabase anon key (public) |

### Optional

| Variable | Service | Default | Purpose |
|----------|---------|---------|---------|
| `SIGIL_DEBUG` | API | false | Debug mode |
| `SIGIL_LOG_LEVEL` | API | INFO | Log level |
| `SIGIL_REDIS_URL` | API | None | Redis cache |
| `SIGIL_SMTP_HOST` | API | None | Email notifications |
| `SIGIL_SMTP_PORT` | API | 587 | SMTP port |
| `SIGIL_SMTP_USER` | API | None | SMTP user |
| `SIGIL_SMTP_PASSWORD` | API | None | SMTP password |
| `SIGIL_STRIPE_SECRET_KEY` | API | None | Stripe billing |
| `SIGIL_STRIPE_WEBHOOK_SECRET` | API | None | Stripe webhooks |
| `SIGIL_STRIPE_PRICE_PRO` | API | placeholder | Stripe Pro price ID |
| `SIGIL_STRIPE_PRICE_TEAM` | API | placeholder | Stripe Team price ID |
| `SIGIL_THREAT_INTEL_TTL` | API | 3600 | Threat intel cache TTL |
| `SIGIL_API_URL` | CLI | api.sigil.nomark.dev | API endpoint |

---

## Security Concerns

1. **Supabase project ID hardcoded** in `scripts/deploy-api-supabase.sh` — should use env var
2. **Dev JWT secret** in docker-compose.yml — acceptable for dev, prod profile should fail without it
3. **No secrets scanning** in CI — should add `trufflehog` or similar

---

## Deployment Checklist

- [ ] Generate production JWT secret: `python3 -c "import secrets; print(secrets.token_hex(32))"`
- [ ] Configure Supabase project (URL, keys, JWT secret)
- [ ] Set CORS origins for production domain
- [ ] Configure Stripe keys for billing
- [ ] Set up PostgreSQL (or use Supabase Postgres)
- [ ] Optional: Configure Redis for caching
- [ ] Optional: Configure SMTP for email notifications
- [ ] Deploy API container with health check monitoring
- [ ] Deploy Dashboard with correct env vars
- [ ] Verify OAuth callback URLs in GitHub OAuth app settings
- [ ] Run smoke test: signup → scan → view dashboard
