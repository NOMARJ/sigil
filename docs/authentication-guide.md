# Sigil Authentication Guide

**Connecting the CLI to Sigil Pro**

This guide explains how to authenticate the Sigil CLI with your Sigil Pro account to unlock cloud-powered threat intelligence features.

---

## Overview

Sigil works in two modes:

- **Free (Offline)** — Local pattern scanning, no account required
- **Pro (Cloud-Connected)** — Enhanced threat detection with cloud intelligence

Authentication is **optional** but recommended for production use. The CLI gracefully degrades when not authenticated, so all core features work offline.

---

## Quick Start

### 1. Login

```bash
sigil login
```

You'll be prompted for your email and password:

```
Email: user@example.com
Password: ********
✓ Logged in successfully!
  Name:  John Doe
  Email: user@example.com
  Token stored in /Users/you/.sigil/token
```

**Non-interactive login** (for CI/CD):

```bash
sigil login --email user@example.com --password "$SIGIL_PASSWORD"
```

### 2. Verify Authentication

Check your connection status:

```bash
sigil config
```

Look for the authentication section showing your stored token location.

### 3. Run Scans

All scans now automatically use Pro features:

```bash
sigil clone https://github.com/suspicious/repo
sigil scan ./my-project
safepip untrusted-package
```

### 4. Logout

Remove your stored credentials:

```bash
sigil logout
```

---

## How It Works

### Architecture

```
┌─────────────┐         ┌──────────────────┐         ┌────────────┐
│  Sigil CLI  │ ◄────► │  Sigil API       │ ◄────► │  Supabase  │
│  (bash/rust)│  HTTPS  │  FastAPI Backend │   DB    │  Database  │
└─────────────┘         └──────────────────┘         └────────────┘
      │
      └─ Token: ~/.sigil/token
```

### Authentication Flow

1. **User Login**
   ```bash
   sigil login --email user@example.com
   ```

2. **CLI → API Request**
   ```http
   POST https://api.sigil.nomark.dev/v1/auth/login
   Content-Type: application/json

   {
     "email": "user@example.com",
     "password": "secretpass"
   }
   ```

3. **API Validates Credentials**
   - Checks email/password against Supabase database
   - Uses bcrypt password hashing (or PBKDF2 fallback)
   - Generates JWT token if valid

4. **API Response**
   ```json
   {
     "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
     "token_type": "bearer",
     "expires_in": 3600,
     "user": {
       "id": "abc123",
       "email": "user@example.com",
       "name": "John Doe"
     }
   }
   ```

5. **CLI Stores Token**
   - Saved to `~/.sigil/token`
   - File permissions: `600` (owner read/write only)
   - Token valid for 60 minutes

6. **Authenticated Requests**
   All subsequent API calls include the token:
   ```bash
   Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
   ```

---

## Pro Features (Cloud-Connected)

When authenticated, the CLI automatically enables:

### 1. Hash-Based Threat Lookup

Every scan computes a hash of the scanned directory and checks it against known malware:

```bash
[Phase 7] Cloud Threat Intelligence
  ✓ No known threats for hash a3f2b1c9d...
```

If a match is found:

```bash
[Phase 7] Cloud Threat Intelligence
  ✗ THREAT MATCH: openclaw-backdoor (CRITICAL)
  Description: Malicious AI agent with credential exfiltration
```

### 2. Cloud Signature Sync

Automatically downloads the latest threat signatures from the Sigil community:

```bash
[Phase 7] Cloud Threat Intelligence
  Synced cloud signatures (refreshed)
```

Signatures are cached locally for 24 hours to reduce API calls.

### 3. Community Threat Patterns

Applies advanced detection patterns maintained by security researchers:

```bash
[cloud-sig] Pattern match in: ./src/agent.py
```

These patterns catch:
- Zero-day AI agent exploits
- Novel obfuscation techniques
- Emerging supply chain attacks
- Community-reported threats

---

## Free vs Pro Comparison

| Feature | Free (Offline) | Pro (Cloud) |
|---------|----------------|-------------|
| **Local Pattern Scanning** | ✅ | ✅ |
| Install Hook Detection | ✅ | ✅ |
| Code Pattern Analysis | ✅ | ✅ |
| Network/Exfiltration Detection | ✅ | ✅ |
| Credential Scanning | ✅ | ✅ |
| Obfuscation Detection | ✅ | ✅ |
| Provenance Analysis | ✅ | ✅ |
| **Cloud Features** | | |
| Known Malware Database | ❌ | ✅ |
| Hash-Based Threat Lookup | ❌ | ✅ |
| Auto-Updating Signatures | ❌ | ✅ |
| Community Threat Reports | ❌ | ✅ |
| Advanced Detection Patterns | ❌ | ✅ |

---

## Security & Privacy

### Token Storage

- **Location**: `~/.sigil/token` (configurable via `$SIGIL_TOKEN`)
- **Permissions**: `600` (owner read/write only)
- **Format**: JWT (JSON Web Token)
- **Expiry**: 60 minutes

### What Gets Sent to the API

When authenticated, the CLI sends:

1. **Directory Hash** (SHA-256 of file paths + sizes)
   - Used for threat lookups
   - Does NOT include file contents
   - Cannot be reversed to recover source code

2. **Authentication Token** (in Authorization header)
   - Standard Bearer token
   - Identifies your account
   - Auto-expires after 60 minutes

### What Does NOT Get Sent

- ❌ Source code contents
- ❌ File contents
- ❌ Environment variables
- ❌ Credentials/secrets
- ❌ Personal information

The CLI is designed for **privacy-first** threat detection. Only metadata (hashes, file patterns) is shared with the API.

---

## Configuration

### API Endpoint

Default: `https://api.sigil.nomark.dev`

Override with environment variable:

```bash
export SIGIL_API_URL=https://api.custom.example.com
sigil login
```

### Token Location

Default: `~/.sigil/token`

Override with environment variable:

```bash
export SIGIL_TOKEN=/secure/path/sigil-token
sigil login
```

### Self-Hosted API

To use a self-hosted Sigil API:

1. Deploy the Sigil API service (see [api/README.md](../api/README.md))
2. Point your CLI to it:
   ```bash
   export SIGIL_API_URL=https://api.yourcompany.com
   sigil login
   ```

---

## Troubleshooting

### "Invalid email or password"

- Double-check your credentials
- Ensure you have an account at the API endpoint
- Register: `sigil register` (if available)

### "Login failed (HTTP 401)"

- Check your network connection
- Verify the API endpoint is accessible:
  ```bash
  curl https://api.sigil.nomark.dev/health
  ```
- Try again with `--verbose` flag (if supported)

### Token Not Working

Check if your token has expired:

```bash
cat ~/.sigil/token
```

JWT tokens expire after 60 minutes. Re-login:

```bash
sigil logout
sigil login
```

### Network Issues

The CLI works fully offline. If the API is unreachable:

```bash
[Phase 7] Cloud Threat Intelligence
  (skipped — not authenticated)
```

The scan continues with local-only detection.

---

## CI/CD Integration

### GitHub Actions

```yaml
- name: Authenticate Sigil
  env:
    SIGIL_EMAIL: ${{ secrets.SIGIL_EMAIL }}
    SIGIL_PASSWORD: ${{ secrets.SIGIL_PASSWORD }}
  run: |
    sigil login --email "$SIGIL_EMAIL" --password "$SIGIL_PASSWORD"

- name: Scan Dependencies
  run: |
    sigil scan ./
```

### GitLab CI

```yaml
sigil_scan:
  script:
    - sigil login --email "$SIGIL_EMAIL" --password "$SIGIL_PASSWORD"
    - sigil scan ./
  variables:
    SIGIL_EMAIL: $CI_SIGIL_EMAIL
    SIGIL_PASSWORD: $CI_SIGIL_PASSWORD
```

### Docker

Mount the token as a secret:

```dockerfile
# Build with auth
RUN --mount=type=secret,id=sigil_token \
    cp /run/secrets/sigil_token /root/.sigil/token && \
    sigil scan ./app
```

---

## Best Practices

### ✅ Do

- **Logout on shared machines**
  ```bash
  sigil logout
  ```

- **Use environment variables in CI/CD**
  ```bash
  export SIGIL_EMAIL="$SECRET_EMAIL"
  export SIGIL_PASSWORD="$SECRET_PASSWORD"
  ```

- **Rotate credentials regularly**
  - Change your password every 90 days
  - Use unique passwords (don't reuse)

- **Verify cloud features are active**
  ```bash
  sigil scan test-repo | grep "Cloud Threat Intelligence"
  ```

### ❌ Don't

- **Don't hardcode credentials in scripts**
  ```bash
  # BAD:
  sigil login --email user@example.com --password secretpass

  # GOOD:
  sigil login --email "$SIGIL_EMAIL" --password "$SIGIL_PASSWORD"
  ```

- **Don't commit the token to git**
  - Already gitignored: `~/.sigil/token`
  - Never copy to project directories

- **Don't share tokens between users**
  - Each developer should have their own account
  - Use team features for shared threat intelligence

---

## API Reference

### Endpoints Used by CLI

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1/auth/login` | POST | Authenticate user |
| `/v1/auth/logout` | POST | End session |
| `/v1/threat/{hash}` | GET | Lookup package threat |
| `/v1/signatures` | GET | Fetch threat signatures |

### Response Codes

- `200 OK` — Success
- `201 Created` — Account created
- `401 Unauthorized` — Invalid credentials or expired token
- `403 Forbidden` — Feature requires higher plan
- `409 Conflict` — Email already exists (registration)
- `500 Internal Server Error` — Server issue

---

## Support

- **Documentation**: [https://github.com/NOMARJ/sigil/docs](https://github.com/NOMARJ/sigil/tree/main/docs)
- **Issues**: [https://github.com/NOMARJ/sigil/issues](https://github.com/NOMARJ/sigil/issues)
- **Security**: security@nomark.dev

---

## Next Steps

- [CLI Usage Guide](./cli-usage.md) — Learn all CLI commands
- [Detection Patterns](./detection-patterns.md) — Understand what Sigil looks for
- [Self-Hosting Guide](./self-hosting.md) — Run your own Sigil API
- [Contributing](../CONTRIBUTING.md) — Add your own threat signatures
