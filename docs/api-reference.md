# Sigil API Reference

**Base URL:** `https://api.sigilsec.ai` (production) or `http://localhost:8000` (local development)

**API Version:** v1

**Authentication:** Bearer token (JWT) in the `Authorization` header. Obtain a token via `POST /v1/auth/login`.

**Content-Type:** All request and response bodies use `application/json`.

---

## Table of Contents

- [Authentication](#authentication)
  - [POST /v1/auth/register](#post-v1authregister)
  - [POST /v1/auth/login](#post-v1authlogin)
  - [GET /v1/auth/me](#get-v1authme)
- [Scanning](#scanning)
  - [POST /v1/scan](#post-v1scan)
- [Threat Intelligence](#threat-intelligence)
  - [GET /v1/threat/{hash}](#get-v1threathash)
  - [GET /v1/publisher/{id}](#get-v1publisherid)
  - [POST /v1/report](#post-v1report)
- [Signatures](#signatures)
  - [GET /v1/signatures](#get-v1signatures)
- [Marketplace](#marketplace)
  - [POST /v1/verify](#post-v1verify)
- [Error Handling](#error-handling)

---

## Authentication

### POST /v1/auth/register

Create a new Sigil account.

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `email` | string | Yes | User email address |
| `password` | string | Yes | Password (min 8 characters) |
| `name` | string | No | Display name |

**Response (201 Created):**

```json
{
  "id": "usr_a1b2c3d4e5f6",
  "email": "dev@example.com",
  "name": "Jane Dev",
  "created_at": "2026-02-15T10:30:00Z",
  "tier": "free"
}
```

**Error Responses:**

| Status | Description |
|--------|-------------|
| 400 | Invalid email format or password too short |
| 409 | Email already registered |
| 422 | Missing required fields |

**Example:**

```bash
curl -X POST https://api.sigilsec.ai/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "dev@example.com",
    "password": "s3cure-passw0rd",
    "name": "Jane Dev"
  }'
```

---

### POST /v1/auth/login

Authenticate and receive a JWT token.

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `email` | string | Yes | Registered email address |
| `password` | string | Yes | Account password |

**Response (200 OK):**

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "bearer",
  "expires_in": 3600,
  "user": {
    "id": "usr_a1b2c3d4e5f6",
    "email": "dev@example.com",
    "name": "Jane Dev",
    "tier": "pro"
  }
}
```

**Error Responses:**

| Status | Description |
|--------|-------------|
| 401 | Invalid email or password |
| 422 | Missing required fields |
| 429 | Too many login attempts (rate limited) |

**Example:**

```bash
curl -X POST https://api.sigilsec.ai/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "dev@example.com",
    "password": "s3cure-passw0rd"
  }'
```

---

### GET /v1/auth/me

Retrieve the authenticated user's profile.

**Headers:**

| Header | Value |
|--------|-------|
| `Authorization` | `Bearer <token>` |

**Response (200 OK):**

```json
{
  "id": "usr_a1b2c3d4e5f6",
  "email": "dev@example.com",
  "name": "Jane Dev",
  "tier": "pro",
  "created_at": "2026-02-15T10:30:00Z",
  "scan_count": 142,
  "last_scan_at": "2026-02-15T14:22:00Z"
}
```

**Error Responses:**

| Status | Description |
|--------|-------------|
| 401 | Missing or invalid token |
| 403 | Token expired |

**Example:**

```bash
curl https://api.sigilsec.ai/v1/auth/me \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIs..."
```

---

## Scanning

### POST /v1/scan

Submit scan results from the CLI. The CLI sends only metadata -- never source code. This endpoint stores the scan for history, enriches it with threat intelligence, and returns any known threats matching the scanned content.

**Headers:**

| Header | Value |
|--------|-------|
| `Authorization` | `Bearer <token>` |

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `quarantine_id` | string | Yes | Unique scan identifier from the CLI |
| `source_type` | string | Yes | One of: `git`, `pip`, `npm`, `url`, `local` |
| `source_ref` | string | Yes | URL, package name, or path that was scanned |
| `source_hash` | string | No | SHA-256 hash of the scanned content |
| `score` | integer | Yes | Cumulative risk score from all phases |
| `verdict` | string | Yes | One of: `clean`, `low`, `medium`, `high`, `critical` |
| `phases` | array | Yes | Per-phase results (see below) |
| `file_stats` | object | No | File type counts and total size |
| `cli_version` | string | No | Version of the CLI that performed the scan |

**Phase Object:**

| Field | Type | Description |
|-------|------|-------------|
| `phase` | integer | Phase number (1-6) |
| `name` | string | Phase name |
| `score` | integer | Score contribution from this phase |
| `findings` | array | List of finding strings |

**Response (201 Created):**

```json
{
  "scan_id": "scn_x7y8z9a0b1c2",
  "quarantine_id": "20260215_143000_example_repo",
  "score": 15,
  "verdict": "medium",
  "threats": [
    {
      "hash": "sha256:abc123...",
      "severity": "high",
      "description": "Known credential exfiltration pattern",
      "reported_at": "2026-02-10T08:00:00Z",
      "reports_count": 23
    }
  ],
  "publisher": {
    "id": "pub_d4e5f6",
    "name": "suspicious-author",
    "reputation": 12,
    "total_packages": 3,
    "flagged_packages": 2
  },
  "created_at": "2026-02-15T14:30:00Z"
}
```

**Error Responses:**

| Status | Description |
|--------|-------------|
| 400 | Invalid scan data or unknown verdict value |
| 401 | Missing or invalid token |
| 413 | Payload too large (max 1MB) |
| 422 | Missing required fields |
| 429 | Rate limited |

**Example:**

```bash
curl -X POST https://api.sigilsec.ai/v1/scan \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIs..." \
  -H "Content-Type: application/json" \
  -d '{
    "quarantine_id": "20260215_143000_example_repo",
    "source_type": "git",
    "source_ref": "https://github.com/someone/example-repo",
    "source_hash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "score": 15,
    "verdict": "medium",
    "phases": [
      {"phase": 1, "name": "install_hooks", "score": 0, "findings": []},
      {"phase": 2, "name": "code_patterns", "score": 10, "findings": ["eval() in src/utils.py:42"]},
      {"phase": 3, "name": "network_exfil", "score": 3, "findings": ["requests.post in src/api.py:18"]},
      {"phase": 4, "name": "credentials", "score": 2, "findings": ["os.environ in src/config.py:5"]},
      {"phase": 5, "name": "obfuscation", "score": 0, "findings": []},
      {"phase": 6, "name": "provenance", "score": 0, "findings": []}
    ],
    "file_stats": {
      "total_files": 24,
      "python": 12,
      "javascript": 8,
      "other": 4,
      "total_size_bytes": 145920
    },
    "cli_version": "0.1.0"
  }'
```

---

## Threat Intelligence

### GET /v1/threat/{hash}

Look up a content hash against the threat intelligence database. Returns known threats, community reports, and recommended actions.

**Headers:**

| Header | Value |
|--------|-------|
| `Authorization` | `Bearer <token>` |

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `hash` | string | SHA-256 hash of the content (prefixed with `sha256:`) |

**Response (200 OK):**

```json
{
  "hash": "sha256:abc123def456...",
  "known_threat": true,
  "severity": "critical",
  "category": "credential_exfiltration",
  "description": "Package uploads .aws/credentials and .env files to remote server via obfuscated postinstall script",
  "first_seen": "2026-01-20T12:00:00Z",
  "last_seen": "2026-02-14T18:30:00Z",
  "reports_count": 47,
  "affected_packages": [
    {"ecosystem": "npm", "name": "aws-helper-utils", "version": "1.2.3"},
    {"ecosystem": "npm", "name": "aws-helper-utilz", "version": "1.0.0"}
  ],
  "references": [
    "https://sigilsec.ai/threats/THR-2026-0142"
  ],
  "recommended_action": "reject"
}
```

**Response (200 OK -- no threat found):**

```json
{
  "hash": "sha256:abc123def456...",
  "known_threat": false,
  "severity": null,
  "category": null,
  "description": null
}
```

**Error Responses:**

| Status | Description |
|--------|-------------|
| 400 | Invalid hash format |
| 401 | Missing or invalid token |
| 429 | Rate limited |

**Example:**

```bash
curl https://api.sigilsec.ai/v1/threat/sha256:e3b0c44298fc1c149afbf4c8996fb924 \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIs..."
```

---

### GET /v1/publisher/{id}

Look up the reputation of a package publisher/author. Reputation is computed from community scan data, report history, and package behavior over time.

**Headers:**

| Header | Value |
|--------|-------|
| `Authorization` | `Bearer <token>` |

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Publisher identifier (npm username, PyPI username, or GitHub handle) |

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `ecosystem` | string | No | Filter by ecosystem: `npm`, `pypi`, `github` |

**Response (200 OK):**

```json
{
  "id": "pub_d4e5f6",
  "name": "suspicious-author",
  "ecosystem": "npm",
  "reputation_score": 12,
  "reputation_label": "low",
  "total_packages": 3,
  "flagged_packages": 2,
  "total_scans": 89,
  "average_risk_score": 38.5,
  "first_seen": "2026-01-15T00:00:00Z",
  "flags": [
    "multiple_flagged_packages",
    "typosquat_pattern",
    "new_account"
  ],
  "packages": [
    {"name": "aws-helper-utils", "version": "1.2.3", "verdict": "critical", "scans": 47},
    {"name": "aws-helper-utilz", "version": "1.0.0", "verdict": "critical", "scans": 31},
    {"name": "string-utils-fast", "version": "2.0.1", "verdict": "clean", "scans": 11}
  ]
}
```

**Response (404 Not Found):**

```json
{
  "detail": "Publisher not found"
}
```

**Error Responses:**

| Status | Description |
|--------|-------------|
| 401 | Missing or invalid token |
| 404 | Publisher not found in database |
| 429 | Rate limited |

**Example:**

```bash
curl "https://api.sigilsec.ai/v1/publisher/suspicious-author?ecosystem=npm" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIs..."
```

---

### POST /v1/report

Submit a threat report for a package or repository. Reports contribute to community threat intelligence and, once verified, generate new detection signatures.

**Headers:**

| Header | Value |
|--------|-------|
| `Authorization` | `Bearer <token>` |

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `source_type` | string | Yes | One of: `git`, `pip`, `npm`, `url` |
| `source_ref` | string | Yes | Package name, URL, or repository |
| `source_hash` | string | No | SHA-256 hash of the content |
| `category` | string | Yes | Threat category (see below) |
| `severity` | string | Yes | One of: `low`, `medium`, `high`, `critical` |
| `description` | string | Yes | Human-readable description of the threat |
| `evidence` | array | No | List of evidence strings (rule matches, file paths) |
| `scan_id` | string | No | Associated scan ID if submitted after a scan |

**Threat Categories:**

| Category | Description |
|----------|-------------|
| `credential_exfiltration` | Code that steals secrets, API keys, or credentials |
| `backdoor` | Code that establishes unauthorized remote access |
| `install_hook_abuse` | Malicious code in install lifecycle scripts |
| `typosquat` | Package name designed to impersonate a legitimate package |
| `obfuscated_payload` | Intentionally obfuscated malicious code |
| `cryptominer` | Unauthorized cryptocurrency mining |
| `data_exfiltration` | Code that sends non-credential data to external servers |
| `other` | Other malicious behavior |

**Response (201 Created):**

```json
{
  "report_id": "rpt_m1n2o3p4q5r6",
  "status": "submitted",
  "source_ref": "aws-helper-utils",
  "category": "credential_exfiltration",
  "severity": "critical",
  "created_at": "2026-02-15T15:00:00Z",
  "message": "Thank you. This report will be reviewed and may generate new detection signatures."
}
```

**Error Responses:**

| Status | Description |
|--------|-------------|
| 400 | Invalid category or severity value |
| 401 | Missing or invalid token |
| 422 | Missing required fields |
| 429 | Rate limited (max 10 reports per hour) |

**Example:**

```bash
curl -X POST https://api.sigilsec.ai/v1/report \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIs..." \
  -H "Content-Type: application/json" \
  -d '{
    "source_type": "npm",
    "source_ref": "aws-helper-utils",
    "source_hash": "sha256:abc123...",
    "category": "credential_exfiltration",
    "severity": "critical",
    "description": "Package postinstall script reads ~/.aws/credentials and sends to remote webhook",
    "evidence": [
      "postinstall in package.json",
      "fs.readFileSync(.aws/credentials) in install.js:14",
      "fetch(https://evil.example.com/collect) in install.js:22"
    ]
  }'
```

---

## Signatures

### GET /v1/signatures

Fetch pattern detection signatures. Supports delta sync so the CLI only downloads new or updated signatures since the last sync.

**Headers:**

| Header | Value |
|--------|-------|
| `Authorization` | `Bearer <token>` |

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `since` | string (ISO 8601) | No | Return only signatures created/updated after this timestamp |
| `phase` | integer | No | Filter by scan phase (1-6) |
| `severity` | string | No | Filter by minimum severity: `low`, `medium`, `high`, `critical` |

**Response (200 OK):**

```json
{
  "signatures": [
    {
      "id": "sig_001",
      "phase": 1,
      "name": "npm_postinstall_exec",
      "description": "npm postinstall script that executes arbitrary commands",
      "pattern": "\"postinstall\"\\s*:\\s*\".*\\b(curl|wget|bash|sh|node -e|eval)\\b",
      "severity": "critical",
      "weight": 10,
      "ecosystem": "npm",
      "created_at": "2026-01-01T00:00:00Z",
      "updated_at": "2026-02-10T12:00:00Z"
    },
    {
      "id": "sig_002",
      "phase": 2,
      "name": "python_pickle_rce",
      "description": "Python pickle deserialization (potential remote code execution)",
      "pattern": "pickle\\.(loads|load)\\s*\\(",
      "severity": "high",
      "weight": 5,
      "ecosystem": "pypi",
      "created_at": "2026-01-01T00:00:00Z",
      "updated_at": "2026-01-15T00:00:00Z"
    }
  ],
  "total": 2,
  "since": "2026-02-01T00:00:00Z",
  "next_sync_token": "2026-02-15T15:00:00Z"
}
```

**Error Responses:**

| Status | Description |
|--------|-------------|
| 400 | Invalid `since` timestamp format |
| 401 | Missing or invalid token |
| 429 | Rate limited |

**Example:**

```bash
# Full sync (first time)
curl https://api.sigilsec.ai/v1/signatures \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIs..."

# Delta sync (subsequent)
curl "https://api.sigilsec.ai/v1/signatures?since=2026-02-14T00:00:00Z" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIs..."

# Filter by phase and severity
curl "https://api.sigilsec.ai/v1/signatures?phase=1&severity=critical" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIs..."
```

---

## Marketplace

### POST /v1/verify

Verify a package or tool for marketplace listing. This endpoint runs an enhanced scan and returns a verification result that can be displayed as a trust badge. Intended for marketplace operators and CI/CD pipelines.

**Headers:**

| Header | Value |
|--------|-------|
| `Authorization` | `Bearer <token>` |

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `source_type` | string | Yes | One of: `git`, `pip`, `npm`, `url` |
| `source_ref` | string | Yes | Package name, URL, or repository |
| `source_version` | string | No | Specific version to verify |
| `source_hash` | string | No | SHA-256 hash for integrity check |
| `callback_url` | string | No | Webhook URL for async result notification |

**Response (200 OK):**

```json
{
  "verification_id": "ver_s1t2u3v4w5x6",
  "status": "verified",
  "source_ref": "langchain-community",
  "source_version": "0.2.1",
  "score": 3,
  "verdict": "low",
  "badge_url": "https://sigilsec.ai/badge/ver_s1t2u3v4w5x6.svg",
  "verified_at": "2026-02-15T15:30:00Z",
  "expires_at": "2026-03-15T15:30:00Z",
  "details": {
    "phases_clean": [1, 5, 6],
    "phases_flagged": [
      {"phase": 2, "score": 2, "note": "eval() in config parser (likely benign)"},
      {"phase": 3, "score": 1, "note": "HTTP client for API calls (expected)"}
    ],
    "publisher_reputation": 87,
    "known_threats": 0
  }
}
```

**Response (200 OK -- verification failed):**

```json
{
  "verification_id": "ver_y6z7a8b9c0d1",
  "status": "failed",
  "source_ref": "evil-package",
  "score": 62,
  "verdict": "critical",
  "badge_url": null,
  "verified_at": "2026-02-15T15:35:00Z",
  "details": {
    "phases_flagged": [
      {"phase": 1, "score": 10, "note": "Malicious postinstall hook"},
      {"phase": 3, "score": 30, "note": "Data exfiltration to external webhook"},
      {"phase": 5, "score": 20, "note": "Obfuscated payload"},
      {"phase": 4, "score": 2, "note": "Reads .aws/credentials"}
    ],
    "known_threats": 1,
    "publisher_reputation": 5
  }
}
```

**Error Responses:**

| Status | Description |
|--------|-------------|
| 400 | Invalid source type or reference |
| 401 | Missing or invalid token |
| 403 | Verification requires Pro or Team tier |
| 404 | Package or version not found |
| 422 | Missing required fields |
| 429 | Rate limited |

**Example:**

```bash
curl -X POST https://api.sigilsec.ai/v1/verify \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIs..." \
  -H "Content-Type: application/json" \
  -d '{
    "source_type": "npm",
    "source_ref": "langchain-community",
    "source_version": "0.2.1"
  }'
```

---

## Error Handling

All error responses follow a consistent format:

```json
{
  "detail": "Human-readable error message",
  "code": "MACHINE_READABLE_CODE",
  "status": 400
}
```

### Common Error Codes

| HTTP Status | Code | Description |
|-------------|------|-------------|
| 400 | `BAD_REQUEST` | Malformed request body or invalid parameters |
| 401 | `UNAUTHORIZED` | Missing or invalid authentication token |
| 403 | `FORBIDDEN` | Valid token but insufficient permissions or tier |
| 404 | `NOT_FOUND` | Requested resource does not exist |
| 409 | `CONFLICT` | Resource already exists (e.g., duplicate registration) |
| 413 | `PAYLOAD_TOO_LARGE` | Request body exceeds maximum size (1MB) |
| 422 | `VALIDATION_ERROR` | Request body fails schema validation |
| 429 | `RATE_LIMITED` | Too many requests; retry after `Retry-After` header |
| 500 | `INTERNAL_ERROR` | Unexpected server error |

### Rate Limits

| Tier | Requests per minute | Scans per day |
|------|-------------------|---------------|
| Free | 30 | 50 |
| Pro | 120 | 500 |
| Team | 600 | 5000 |

Rate limit status is returned in response headers:

```
X-RateLimit-Limit: 120
X-RateLimit-Remaining: 118
X-RateLimit-Reset: 1708012800
Retry-After: 42
```
