# Sigil -- Deployment Guide

This document covers deploying and operating the Sigil security auditing platform in various environments: standalone Docker, Docker Compose stacks, production hardening, GitHub Actions, and GitLab CI.

---

## Table of Contents

1. [Docker Deployment](#docker-deployment)
2. [Environment Variables](#environment-variables)
3. [Production Configuration](#production-configuration)
4. [GitHub Action](#github-action)
5. [GitLab CI](#gitlab-ci)
6. [CLI Installation](#cli-installation)
7. [Health Checks and Monitoring](#health-checks-and-monitoring)
8. [Production Checklist](#production-checklist)

---

## Docker Deployment

### Single Container

Build and run the Sigil API service as a single Docker container:

```bash
# Build the image (includes Rust CLI, Python API, and Next.js dashboard)
docker build -t sigil:latest .

# Run with minimal configuration
docker run -d \
  --name sigil \
  -p 8000:8000 \
  -p 3000:3000 \
  -e SIGIL_JWT_SECRET="$(openssl rand -hex 32)" \
  -e NEXT_PUBLIC_API_URL="https://api.yourdomain.com" \
  sigil:latest
```

The Dockerfile is a multi-stage build with three stages:

| Stage | Base Image | Purpose |
|-------|-----------|---------|
| `rust-builder` | `rust:1.77-slim-bookworm` | Compiles the Rust CLI binary |
| `dashboard-builder` | `node:20-slim` | Builds the Next.js dashboard |
| `runtime` | `python:3.11-slim-bookworm` | Final image with API, CLI, and dashboard |

The runtime image:
- Runs as a non-root `sigil` user (UID 1001)
- Uses `tini` as PID 1 for proper signal handling
- Exposes ports 8000 (API) and 3000 (dashboard)
- Includes a built-in health check at `GET /health`

### Docker Compose (Development)

Start the full development stack with hot-reloading:

```bash
docker compose up -d
```

This starts four services:

| Service | Port | Description |
|---------|------|-------------|
| `api` | 8000 | FastAPI backend with `--reload` enabled |
| `dashboard` | 3000 | Next.js dev server |
| `postgres` | 5432 | PostgreSQL 16 database |
| `redis` | 6379 | Redis 7 cache |

The API service mounts `./api` as a volume for live reloading during development. The dashboard mounts `./dashboard` similarly.

Useful commands:

```bash
# View API logs
docker compose logs -f api

# Restart just the API
docker compose restart api

# Tear down everything (preserves volumes)
docker compose down

# Tear down including volumes (full reset)
docker compose down -v
```

### Docker Compose (Production)

Start the production profile, which disables debug mode and hot-reloading:

```bash
# Create a .env file first (see "Production Configuration" section below)
docker compose --profile prod up -d
```

In production mode, the `api-prod` service replaces the development `api` service. It:
- Sets `SIGIL_DEBUG=false`
- Sets `SIGIL_LOG_LEVEL=WARNING`
- Uses longer health check intervals (30s instead of 15s)
- Does not mount source volumes

### Database Setup

```bash
# Initialize schema (first run)
docker compose exec api python -c "
from api.database import db
import asyncio
asyncio.run(db.connect())
"

# Or manually with psql
psql -h localhost -U sigil -d sigil -f api/schema.sql

# Seed with threat intelligence data
python api/seed.py
```

---

## Environment Variables

All configuration is managed through environment variables prefixed with `SIGIL_`. The API uses Pydantic Settings, which reads from environment variables and `.env` files.

### Core Application

| Variable | Default | Description |
|----------|---------|-------------|
| `SIGIL_APP_NAME` | `Sigil API` | Application display name |
| `SIGIL_APP_VERSION` | `0.1.0` | Application version string |
| `SIGIL_DEBUG` | `false` | Enable debug mode |
| `SIGIL_LOG_LEVEL` | `INFO` | Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |

### Server

| Variable | Default | Description |
|----------|---------|-------------|
| `SIGIL_HOST` | `0.0.0.0` | Listen address |
| `SIGIL_PORT` | `8000` | Listen port |
| `SIGIL_CORS_ORIGINS` | `["http://localhost:3000"]` | JSON array of allowed CORS origins |

### Authentication (JWT)

| Variable | Default | Description |
|----------|---------|-------------|
| `SIGIL_JWT_SECRET` | `changeme-generate-a-real-secret` | **Required in production.** Secret key for signing JWTs |
| `SIGIL_JWT_ALGORITHM` | `HS256` | JWT signing algorithm |
| `SIGIL_JWT_EXPIRE_MINUTES` | `60` | Access token lifetime in minutes |

### Database (Supabase)

| Variable | Default | Description |
|----------|---------|-------------|
| `SIGIL_SUPABASE_URL` | `None` | Supabase project URL |
| `SIGIL_SUPABASE_KEY` | `None` | Supabase service role key (anon key for client-side) |

When Supabase is not configured, the API falls back to an in-memory database that is suitable for development but does not persist data across restarts.

### Cache (Redis)

| Variable | Default | Description |
|----------|---------|-------------|
| `SIGIL_REDIS_URL` | `None` | Redis connection URL (e.g., `redis://localhost:6379/0`) |

When Redis is not configured, the API falls back to an in-memory cache.

### Threat Intelligence

| Variable | Default | Description |
|----------|---------|-------------|
| `SIGIL_THREAT_INTEL_TTL` | `3600` | Threat intel cache TTL in seconds |

### Email (SMTP)

| Variable | Default | Description |
|----------|---------|-------------|
| `SIGIL_SMTP_HOST` | `None` | SMTP server hostname |
| `SIGIL_SMTP_PORT` | `587` | SMTP server port |
| `SIGIL_SMTP_USER` | `None` | SMTP username |
| `SIGIL_SMTP_PASSWORD` | `None` | SMTP password |
| `SIGIL_SMTP_FROM_EMAIL` | `alerts@sigil.dev` | Sender email address for alert notifications |

### Billing (Stripe)

| Variable | Default | Description |
|----------|---------|-------------|
| `SIGIL_STRIPE_SECRET_KEY` | `None` | Stripe secret API key |
| `SIGIL_STRIPE_WEBHOOK_SECRET` | `None` | Stripe webhook signing secret |
| `SIGIL_STRIPE_PRICE_PRO` | `price_pro_placeholder` | Stripe Price ID for the Pro plan |
| `SIGIL_STRIPE_PRICE_TEAM` | `price_team_placeholder` | Stripe Price ID for the Team plan |

When Stripe is not configured, the billing endpoints return stub responses. No real charges are made.

### Docker Compose Variables

These variables are used by `docker-compose.yml` but are not part of the API settings:

| Variable | Default | Description |
|----------|---------|-------------|
| `SIGIL_API_PORT` | `8000` | Host port for the API service |
| `SIGIL_DASHBOARD_PORT` | `3000` | Host port for the dashboard |
| `SIGIL_PG_PORT` | `5432` | Host port for PostgreSQL |
| `SIGIL_PG_DB` | `sigil` | PostgreSQL database name |
| `SIGIL_PG_USER` | `sigil` | PostgreSQL username |
| `SIGIL_PG_PASSWORD` | `sigil_dev_password` | PostgreSQL password |
| `SIGIL_REDIS_PORT` | `6379` | Host port for Redis |
| `NEXT_PUBLIC_API_URL` | `http://localhost:8000` | API URL for the dashboard frontend |

---

## Production Configuration

### Mandatory Settings

Before deploying to production, you **must** configure:

1. **JWT Secret** -- Generate a cryptographically random secret:

   ```bash
   openssl rand -hex 32
   # or
   python3 -c "import secrets; print(secrets.token_urlsafe(64))"
   ```

   Set it via `SIGIL_JWT_SECRET`.

2. **Database** -- Provide Supabase credentials:

   ```bash
   export SIGIL_SUPABASE_URL="https://your-project.supabase.co"
   export SIGIL_SUPABASE_KEY="your-service-role-key"
   ```

3. **CORS Origins** -- Restrict to your actual domain:

   ```bash
   export SIGIL_CORS_ORIGINS='["https://sigil.yourdomain.com"]'
   ```

### Recommended Settings

- **Redis** -- Enable Redis for production caching:

  ```bash
  export SIGIL_REDIS_URL="redis://your-redis-host:6379/0"
  ```

- **Log Level** -- Set to `WARNING` or `ERROR` in production:

  ```bash
  export SIGIL_LOG_LEVEL="WARNING"
  export SIGIL_DEBUG="false"
  ```

- **SMTP** -- Configure email for alert notifications:

  ```bash
  export SIGIL_SMTP_HOST="smtp.your-provider.com"
  export SIGIL_SMTP_PORT="587"
  export SIGIL_SMTP_USER="your-smtp-user"
  export SIGIL_SMTP_PASSWORD="your-smtp-password"
  export SIGIL_SMTP_FROM_EMAIL="alerts@yourdomain.com"
  ```

- **Stripe** -- Configure billing if you need paid plans:

  ```bash
  export SIGIL_STRIPE_SECRET_KEY="sk_live_..."
  export SIGIL_STRIPE_WEBHOOK_SECRET="whsec_..."
  export SIGIL_STRIPE_PRICE_PRO="price_..."
  export SIGIL_STRIPE_PRICE_TEAM="price_..."
  ```

### Example `.env` File

Create a `.env` file in the project root (do not commit to version control):

```bash
# Core
SIGIL_DEBUG=false
SIGIL_LOG_LEVEL=WARNING

# Auth
SIGIL_JWT_SECRET=your-64-char-random-secret-here
SIGIL_JWT_EXPIRE_MINUTES=30

# Database
SIGIL_SUPABASE_URL=https://your-project.supabase.co
SIGIL_SUPABASE_KEY=your-service-role-key

# Cache
SIGIL_REDIS_URL=redis://redis:6379/0

# CORS
SIGIL_CORS_ORIGINS=["https://sigil.yourdomain.com"]

# Dashboard
NEXT_PUBLIC_API_URL=https://api.yourdomain.com

# SMTP (optional)
SIGIL_SMTP_HOST=smtp.your-provider.com
SIGIL_SMTP_USER=your-smtp-user
SIGIL_SMTP_PASSWORD=your-smtp-password

# Stripe (optional)
SIGIL_STRIPE_SECRET_KEY=sk_live_...
SIGIL_STRIPE_WEBHOOK_SECRET=whsec_...
```

### Reverse Proxy

In production, place Sigil behind a reverse proxy (nginx, Caddy, or a cloud load balancer) that handles TLS termination:

```nginx
# Example nginx configuration
server {
    listen 443 ssl http2;
    server_name sigil.yourdomain.com;

    ssl_certificate     /etc/ssl/certs/sigil.pem;
    ssl_certificate_key /etc/ssl/private/sigil.key;

    # API
    location /v1/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Dashboard and non-prefixed API routes
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## GitHub Action

Sigil provides a composite GitHub Action for running security scans as part of your CI pipeline.

### Quick Start

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  sigil:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Sigil scan
        uses: nomark/sigil@main
        with:
          path: '.'
          threshold: 'medium'
```

### Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `path` | No | `.` | Path to scan (relative to repository root) |
| `threshold` | No | `medium` | Minimum verdict level to fail the action. One of: `low`, `medium`, `high`, `critical` |
| `api-key` | No | `""` | Sigil cloud API key for threat intel enrichment. When provided, scan results are also submitted to the cloud for tracking |
| `fail-on-findings` | No | `true` | Whether to fail the workflow when findings meet or exceed the threshold |
| `phases` | No | `all` | Comma-separated list of scan phases to run. Options: `all`, `install-hooks`, `code-patterns`, `network`, `credentials`, `obfuscation`, `provenance` |
| `exclude` | No | `""` | Glob patterns to exclude from scanning (comma-separated) |

### Outputs

| Output | Description |
|--------|-------------|
| `verdict` | Scan verdict: `CLEAN`, `LOW_RISK`, `MEDIUM_RISK`, `HIGH_RISK`, or `CRITICAL` |
| `risk-score` | Numeric risk score from the scan |
| `findings-count` | Total number of findings detected |

### Threshold Scoring

The threshold maps to a numeric score:

| Threshold | Minimum Score to Fail |
|-----------|----------------------|
| `low` | 1 |
| `medium` | 10 |
| `high` | 25 |
| `critical` | 50 |

If `fail-on-findings` is `true` and the scan's risk score meets or exceeds the threshold score, the action exits with a non-zero code, failing the workflow.

### Examples

**Basic scan with default settings:**

```yaml
- uses: nomark/sigil@main
```

**Scan a subdirectory with a strict threshold:**

```yaml
- uses: nomark/sigil@main
  with:
    path: 'packages/agent-core'
    threshold: 'low'
```

**Scan with cloud enrichment (threat intel lookup):**

```yaml
- uses: nomark/sigil@main
  with:
    threshold: 'high'
    api-key: ${{ secrets.SIGIL_API_KEY }}
```

**Run specific phases only:**

```yaml
- uses: nomark/sigil@main
  with:
    phases: 'install-hooks,code-patterns,network'
    threshold: 'medium'
```

**Non-blocking scan (report only, don't fail):**

```yaml
- uses: nomark/sigil@main
  with:
    fail-on-findings: 'false'
```

**Use outputs in subsequent steps:**

```yaml
- name: Sigil scan
  id: scan
  uses: nomark/sigil@main
  with:
    threshold: 'medium'

- name: Comment on PR
  if: github.event_name == 'pull_request'
  uses: actions/github-script@v7
  with:
    script: |
      const verdict = '${{ steps.scan.outputs.verdict }}';
      const score = '${{ steps.scan.outputs.risk-score }}';
      const findings = '${{ steps.scan.outputs.findings-count }}';
      await github.rest.issues.createComment({
        issue_number: context.issue.number,
        owner: context.repo.owner,
        repo: context.repo.repo,
        body: `## Sigil Scan Results\n| Verdict | Score | Findings |\n|---------|-------|----------|\n| ${verdict} | ${score} | ${findings} |`
      });
```

**Full CI workflow with scan, test, and deploy:**

```yaml
name: CI Pipeline
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Security scan
        uses: nomark/sigil@main
        with:
          threshold: 'medium'
          api-key: ${{ secrets.SIGIL_API_KEY }}

  test:
    needs: security
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm test

  deploy:
    needs: [security, test]
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo "Deploying..."
```

### Job Summary

The action automatically writes a GitHub Actions Job Summary with:
- A results table showing verdict, risk score, findings count, and threshold
- An expandable section with detailed findings (when findings are present)
- A phase-by-phase breakdown table

---

## GitLab CI

Sigil provides a reusable GitLab CI template for running security scans in your pipeline.

### Including the Template

**From the remote repository:**

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/nomark/sigil/main/.gitlab-ci-template.yml'
```

**From a local copy:**

```yaml
include:
  - local: '.gitlab-ci-template.yml'
```

### Variables

Override these variables in your `.gitlab-ci.yml`:

| Variable | Default | Description |
|----------|---------|-------------|
| `SIGIL_VERSION` | `latest` | Version of Sigil to install |
| `SIGIL_SCAN_PATH` | `.` | Path to scan |
| `SIGIL_THRESHOLD` | `medium` | Minimum verdict level to fail (`low`, `medium`, `high`, `critical`) |
| `SIGIL_FAIL_ON_FINDINGS` | `true` | Whether to fail the pipeline on findings |
| `SIGIL_PHASES` | `all` | Comma-separated list of scan phases |
| `SIGIL_EXCLUDE` | `""` | Glob patterns to exclude |
| `SIGIL_API_KEY` | `""` | Sigil cloud API key |

### Example

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/nomark/sigil/main/.gitlab-ci-template.yml'

variables:
  SIGIL_SCAN_PATH: "."
  SIGIL_THRESHOLD: "high"
  SIGIL_FAIL_ON_FINDINGS: "true"
```

### Behavior

The GitLab CI template:

1. Installs the Sigil CLI (from GitHub releases or falls back to the bash script)
2. Runs the scan on `$SIGIL_SCAN_PATH`
3. Parses the results and extracts risk score, verdict, and findings count
4. Generates a `metrics.txt` file with Prometheus-compatible metrics
5. Generates a `sigil-results.json` with machine-readable results
6. Compares the risk score against the threshold and fails if exceeded

### Artifacts

The template stores scan artifacts for 30 days:

| Artifact | Description |
|----------|-------------|
| `.sigil-reports/scan_output.txt` | Full scan output |
| `.sigil-reports/metrics.txt` | Prometheus metrics (`sigil_risk_score`, `sigil_findings_count`) |
| `.sigil-reports/sigil-results.json` | Machine-readable JSON report |

### Pipeline Rules

The scan runs automatically on:
- Merge request events
- Pushes to the default branch
- Manual triggers (with `allow_failure: true`)

---

## CLI Installation

### From Release

```bash
# macOS (ARM)
curl -sL https://github.com/nomark/sigil/releases/latest/download/sigil-macos-arm64 -o sigil
chmod +x sigil && sudo mv sigil /usr/local/bin/

# Linux (x64)
curl -sL https://github.com/nomark/sigil/releases/latest/download/sigil-linux-x64 -o sigil
chmod +x sigil && sudo mv sigil /usr/local/bin/

# Or use the bash fallback (no build required)
curl -sL https://raw.githubusercontent.com/nomark/sigil/main/bin/sigil -o sigil
chmod +x sigil && sudo mv sigil /usr/local/bin/
```

### From Source

```bash
git clone https://github.com/nomark/sigil.git
cd sigil

# Rust CLI
cd cli && cargo build --release
sudo cp target/release/sigil /usr/local/bin/

# Or bash CLI
sudo cp bin/sigil /usr/local/bin/
```

---

## Health Checks and Monitoring

### Health Endpoint

The API exposes `GET /health` which returns:

```json
{
  "status": "ok",
  "version": "0.1.0",
  "supabase_connected": true,
  "redis_connected": true
}
```

Use this endpoint for:
- Docker health checks (configured in the Dockerfile and docker-compose.yml)
- Load balancer health probes
- Uptime monitoring

### Docker Health Check Configuration

The Dockerfile includes a built-in health check:

```dockerfile
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1
```

The docker-compose development stack uses a more frequent interval:

```yaml
healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
  interval: 15s
  timeout: 5s
  start_period: 10s
  retries: 3
```

---

## Production Checklist

- [ ] Set `SIGIL_JWT_SECRET` to a strong random value (min 32 chars)
- [ ] Set `SIGIL_DEBUG=false`
- [ ] Configure Supabase or PostgreSQL with proper credentials
- [ ] Set `NEXT_PUBLIC_API_URL` to your public API endpoint
- [ ] Configure CORS origins for your domain
- [ ] Set up Redis for caching (recommended)
- [ ] Configure SMTP for email alerts (optional)
- [ ] Set up Stripe keys for billing (optional)
- [ ] Enable HTTPS via reverse proxy (nginx, Caddy, etc.)
- [ ] Initialize database schema
- [ ] Seed threat intelligence data
- [ ] Verify health check at `GET /health`
