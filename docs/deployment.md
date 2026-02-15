# Sigil — Deployment Guide

## Quick Start (Docker Compose)

```bash
# Development mode
docker compose up -d

# Production mode
SIGIL_JWT_SECRET=$(openssl rand -hex 32) docker compose --profile prod up -d
```

## Environment Variables

### Required for Production

| Variable | Description | Example |
|----------|-------------|---------|
| `SIGIL_JWT_SECRET` | JWT signing secret (min 32 chars) | `openssl rand -hex 32` |
| `SIGIL_DATABASE_URL` | PostgreSQL connection URL | `postgresql://user:pass@host:5432/sigil` |

### Optional

| Variable | Default | Description |
|----------|---------|-------------|
| `SIGIL_DEBUG` | `true` | Enable debug mode |
| `SIGIL_LOG_LEVEL` | `INFO` | Logging level (DEBUG, INFO, WARNING, ERROR) |
| `SIGIL_CORS_ORIGINS` | `["http://localhost:3000"]` | Allowed CORS origins (JSON array) |
| `SIGIL_REDIS_URL` | — | Redis connection URL for caching |
| `SIGIL_SMTP_HOST` | — | SMTP server for email alerts |
| `SIGIL_SMTP_PORT` | `587` | SMTP port |
| `SIGIL_SMTP_USER` | — | SMTP username |
| `SIGIL_SMTP_PASSWORD` | — | SMTP password |
| `SIGIL_SMTP_FROM` | `noreply@sigil.dev` | Email sender address |
| `SIGIL_STRIPE_SECRET_KEY` | — | Stripe secret key for billing |
| `SIGIL_STRIPE_WEBHOOK_SECRET` | — | Stripe webhook signing secret |
| `NEXT_PUBLIC_API_URL` | `http://localhost:8000` | API URL for dashboard |

## Docker Deployment

### Single Container

```bash
# Build
docker build -t sigil:latest .

# Run with environment variables
docker run -d \
  --name sigil \
  -p 8000:8000 \
  -p 3000:3000 \
  -e SIGIL_JWT_SECRET="$(openssl rand -hex 32)" \
  -e SIGIL_DATABASE_URL="postgresql://user:pass@db:5432/sigil" \
  -e NEXT_PUBLIC_API_URL="https://api.yourdomain.com" \
  sigil:latest
```

### Docker Compose (Production)

```bash
# Create .env file
cat > .env <<EOF
SIGIL_JWT_SECRET=$(openssl rand -hex 32)
SIGIL_DEBUG=false
SIGIL_DATABASE_URL=postgresql://sigil:secure_password@postgres:5432/sigil
SIGIL_REDIS_URL=redis://redis:6379/0
NEXT_PUBLIC_API_URL=https://api.yourdomain.com
EOF

# Start production stack
docker compose --profile prod up -d
```

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

## GitHub Action

Add to your workflow:

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  sigil-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Sigil Security Scan
        uses: nomark/sigil@v1
        with:
          path: '.'
          threshold: 'medium'
          api-key: ${{ secrets.SIGIL_API_KEY }}
          fail-on-findings: 'true'
```

### Action Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `path` | `.` | Directory to scan |
| `threshold` | `medium` | Minimum severity to fail: `low`, `medium`, `high`, `critical` |
| `api-key` | — | Sigil API key for cloud features |
| `fail-on-findings` | `true` | Fail the workflow if findings exceed threshold |
| `phases` | `all` | Comma-separated phases to run |
| `exclude` | — | Comma-separated paths to exclude |

### Action Outputs

| Output | Description |
|--------|-------------|
| `verdict` | Scan verdict (CLEAN, LOW, MEDIUM, HIGH, CRITICAL) |
| `risk-score` | Numeric risk score |
| `findings-count` | Total number of findings |

### Advanced Usage

```yaml
- name: Sigil Scan
  id: scan
  uses: nomark/sigil@v1
  with:
    path: 'src/'
    threshold: 'high'
    phases: 'install-hooks,code-patterns,credentials'
    exclude: 'tests/,docs/,fixtures/'

- name: Comment on PR
  if: failure()
  uses: actions/github-script@v7
  with:
    script: |
      github.rest.issues.createComment({
        issue_number: context.issue.number,
        owner: context.repo.owner,
        repo: context.repo.repo,
        body: `## Sigil Security Scan Failed\n- Verdict: ${{ steps.scan.outputs.verdict }}\n- Score: ${{ steps.scan.outputs.risk-score }}\n- Findings: ${{ steps.scan.outputs.findings-count }}`
      })
```

## GitLab CI

Add to your `.gitlab-ci.yml`:

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/nomark/sigil/main/.gitlab-ci-template.yml'
```

Or copy `.gitlab-ci-template.yml` into your project and customize.

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

## Production Checklist

- [ ] Set `SIGIL_JWT_SECRET` to a strong random value (min 32 chars)
- [ ] Set `SIGIL_DEBUG=false`
- [ ] Configure PostgreSQL with proper credentials
- [ ] Set `NEXT_PUBLIC_API_URL` to your public API endpoint
- [ ] Configure CORS origins for your domain
- [ ] Set up Redis for caching (recommended)
- [ ] Configure SMTP for email alerts (optional)
- [ ] Set up Stripe keys for billing (optional)
- [ ] Enable HTTPS via reverse proxy (nginx, Caddy, etc.)
- [ ] Run `api/schema.sql` to initialize database
- [ ] Run `api/seed.py` to seed threat intelligence data
