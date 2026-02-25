# Sigil API Reference

**Base URL:** `https://api.sigilsec.ai` (production) or `http://localhost:8000` (local development)

**API Version:** v1

**Authentication:** Bearer token (JWT) in the `Authorization` header. Obtain a token via `POST /v1/auth/login`.

**Content-Type:** All request and response bodies use `application/json`.

**Path Compatibility:** Most endpoints are available at both `/v1/<path>` (for CLI clients) and `/<path>` (for the dashboard). Both forms call the same handler and return identical responses.

---

## Table of Contents

- [Authentication](#authentication)
- [Scanning](#scanning)
- [Dashboard](#dashboard)
- [Threat Intelligence](#threat-intelligence)
- [Publishers](#publishers)
- [Reports](#reports)
- [Verification](#verification)
- [Team Management](#team-management)
- [Policies](#policies)
- [Alerts](#alerts)
- [Billing](#billing)
- [System](#system)
- [Error Handling](#error-handling)

---

## Authentication

### POST /v1/auth/register

Create a new Sigil account and receive a JWT.

| Property | Value |
|----------|-------|
| **Auth required** | No |
| **Rate limit** | 10/min |

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `email` | string | Yes | User email address |
| `password` | string | Yes | Password (min 8 characters) |
| `name` | string | No | Display name |

**Response (201 Created):**

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "bearer",
  "expires_in": 3600,
  "user": {
    "id": "usr_a1b2c3d4e5f6",
    "email": "dev@example.com",
    "name": "Jane Dev",
    "created_at": "2026-02-15T10:30:00Z"
  }
}
```

**Status Codes:** 201 Created, 409 Email already registered, 422 Validation error

---

### POST /v1/auth/login

Authenticate and receive a JWT token.

| Property | Value |
|----------|-------|
| **Auth required** | No |
| **Rate limit** | 30/min |

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
    "created_at": "2026-02-15T10:30:00Z"
  }
}
```

**Status Codes:** 200 OK, 401 Invalid credentials, 429 Rate limited

---

### GET /v1/auth/me

Retrieve the authenticated user's profile.

| Property | Value |
|----------|-------|
| **Auth required** | Yes |

**Response (200 OK):**

```json
{
  "id": "usr_a1b2c3d4e5f6",
  "email": "dev@example.com",
  "name": "Jane Dev",
  "created_at": "2026-02-15T10:30:00Z"
}
```

**Status Codes:** 200 OK, 401 Unauthorized

---

### POST /auth/refresh

Exchange a refresh token for a new access token.

| Property | Value |
|----------|-------|
| **Auth required** | No (uses refresh token) |
| **Also available at** | `POST /v1/auth/refresh` |

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `refresh_token` | string | Yes | A valid refresh token (JWT) |

**Response (200 OK):**

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "bearer",
  "expires_in": 3600
}
```

**Status Codes:** 200 OK, 401 Invalid or expired refresh token

---

### POST /auth/logout

Log out the current user. The client should discard stored tokens.

| Property | Value |
|----------|-------|
| **Auth required** | Yes |
| **Also available at** | `POST /v1/auth/logout` |

**Response:** 204 No Content

**Status Codes:** 204 No Content, 401 Unauthorized

---

## Scanning

### POST /v1/scan

Submit scan results from the CLI for enrichment with threat intelligence. The CLI sends metadata and findings -- never source code.

| Property | Value |
|----------|-------|
| **Auth required** | No (public submission) |

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `target` | string | Yes | Package name, URL, or path that was scanned |
| `target_type` | string | Yes | One of: `git`, `pip`, `npm`, `url`, `directory` |
| `files_scanned` | integer | Yes | Number of files scanned |
| `findings` | array | Yes | List of Finding objects (see below) |
| `metadata` | object | No | Additional scan metadata (hashes, cli_version, etc.) |

**Finding Object:**

| Field | Type | Description |
|-------|------|-------------|
| `phase` | string | Scan phase (e.g. `install_hooks`, `code_patterns`) |
| `rule` | string | Rule identifier (e.g. `INSTALL-001`) |
| `severity` | string | One of: `low`, `medium`, `high`, `critical` |
| `file` | string | File path where finding was detected |
| `line` | integer | Line number (1-based), nullable |
| `snippet` | string | Code snippet or match description |

**Response (200 OK):**

```json
{
  "scan_id": "scn_x7y8z9a0b1c2",
  "target": "https://github.com/someone/example-repo",
  "target_type": "git",
  "files_scanned": 24,
  "findings": [...],
  "risk_score": 15.0,
  "verdict": "MEDIUM_RISK",
  "threat_intel_hits": [],
  "created_at": "2026-02-15T14:30:00Z"
}
```

**Status Codes:** 200 OK, 422 Validation error

---

### GET /scans

List scans with pagination and filtering.

| Property | Value |
|----------|-------|
| **Auth required** | Yes |

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | integer | 1 | Page number (>= 1) |
| `per_page` | integer | 20 | Items per page (1-100) |
| `verdict` | string | -- | Filter by verdict |
| `source` | string | -- | Filter by target_type |
| `search` | string | -- | Search in target name |

**Response (200 OK):**

```json
{
  "items": [
    {
      "id": "scn_x7y8z9a0b1c2",
      "target": "example-repo",
      "target_type": "git",
      "files_scanned": 24,
      "findings_count": 3,
      "risk_score": 15.0,
      "verdict": "MEDIUM_RISK",
      "threat_hits": 0,
      "metadata": {},
      "created_at": "2026-02-15T14:30:00Z"
    }
  ],
  "total": 142,
  "page": 1,
  "per_page": 20
}
```

**Status Codes:** 200 OK, 401 Unauthorized

---

### GET /scans/{id}

Get full details of a single scan.

| Property | Value |
|----------|-------|
| **Auth required** | Yes |

**Response (200 OK):** Full scan detail including `findings_json` and `metadata_json` arrays.

**Status Codes:** 200 OK, 401 Unauthorized, 404 Not found

---

### GET /scans/{id}/findings

Get findings for a specific scan.

| Property | Value |
|----------|-------|
| **Auth required** | Yes |

**Response (200 OK):** Array of finding objects from the scan.

**Status Codes:** 200 OK, 401 Unauthorized, 404 Not found

---

### POST /scans/{id}/approve

Approve a quarantined scan, marking it as safe.

| Property | Value |
|----------|-------|
| **Auth required** | Yes |

**Response (200 OK):**

```json
{
  "scan_id": "scn_x7y8z9a0b1c2",
  "status": "approved",
  "approved_by": "usr_a1b2c3d4e5f6"
}
```

**Status Codes:** 200 OK, 401 Unauthorized, 404 Not found

---

### POST /scans/{id}/reject

Reject a quarantined scan, marking it as blocked.

| Property | Value |
|----------|-------|
| **Auth required** | Yes |

**Response (200 OK):**

```json
{
  "scan_id": "scn_x7y8z9a0b1c2",
  "status": "rejected",
  "rejected_by": "usr_a1b2c3d4e5f6"
}
```

**Status Codes:** 200 OK, 401 Unauthorized, 404 Not found

---

## Dashboard

### GET /dashboard/stats

Aggregate dashboard statistics for the team overview.

| Property | Value |
|----------|-------|
| **Auth required** | Yes |

**Response (200 OK):**

```json
{
  "total_scans": 1420,
  "threats_blocked": 23,
  "packages_approved": 890,
  "critical_findings": 5,
  "scans_trend": 12.5,
  "threats_trend": -3.2,
  "approved_trend": 8.1,
  "critical_trend": 0.0
}
```

**Status Codes:** 200 OK, 401 Unauthorized

---

## Threat Intelligence

### GET /v1/threat/{hash}

Look up a package hash against the threat intelligence database.

| Property | Value |
|----------|-------|
| **Auth required** | No |
| **Also available at** | `GET /threat/{hash}` |

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `hash` | string | SHA-256 hash of the package artifact |

**Response (200 OK):**

```json
{
  "hash": "sha256:abc123def456...",
  "known_threat": true,
  "severity": "critical",
  "category": "credential_exfiltration",
  "description": "Package uploads credentials to remote server",
  "first_seen": "2026-01-20T12:00:00Z",
  "reports_count": 47,
  "affected_packages": [
    {"ecosystem": "npm", "name": "aws-helper-utils", "version": "1.2.3"}
  ],
  "recommended_action": "reject"
}
```

**Status Codes:** 200 OK, 404 Hash not found

---

### GET /v1/signatures

Fetch pattern detection signatures. Supports delta sync via the `since` parameter.

| Property | Value |
|----------|-------|
| **Auth required** | No |
| **Also available at** | `GET /signatures` |

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `since` | string (ISO 8601) | No | Return only signatures updated after this timestamp |

**Response (200 OK):**

```json
{
  "signatures": [
    {
      "id": "sig_001",
      "phase": 1,
      "name": "npm_postinstall_exec",
      "pattern": "\"postinstall\"\\s*:\\s*\".*\\b(curl|wget|bash)\\b",
      "severity": "critical",
      "weight": 10,
      "ecosystem": "npm",
      "updated_at": "2026-02-10T12:00:00Z"
    }
  ],
  "total": 156,
  "since": "2026-02-01T00:00:00Z",
  "next_sync_token": "2026-02-15T15:00:00Z"
}
```

**Status Codes:** 200 OK, 400 Invalid `since` format

---

### GET /threats

Search threats. Dashboard alias for threat intelligence queries.

| Property | Value |
|----------|-------|
| **Auth required** | No |
| **Also available at** | `GET /v1/threat/{hash}` (single lookup) |

---

## Publishers

### GET /v1/publisher/{id}

Look up the reputation of a package publisher/author.

| Property | Value |
|----------|-------|
| **Auth required** | No |
| **Also available at** | `GET /publisher/{id}` |

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
  "packages": [
    {"name": "aws-helper-utils", "version": "1.2.3", "verdict": "CRITICAL", "scans": 47}
  ]
}
```

**Status Codes:** 200 OK, 404 Publisher not found

---

## Reports

### POST /v1/report

Submit a threat report for a package or repository. Reports contribute to community threat intelligence.

| Property | Value |
|----------|-------|
| **Auth required** | Yes |
| **Also available at** | `POST /report` |

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `source_type` | string | Yes | One of: `git`, `pip`, `npm`, `url` |
| `source_ref` | string | Yes | Package name, URL, or repository |
| `source_hash` | string | No | SHA-256 hash of the content |
| `category` | string | Yes | Threat category (see below) |
| `severity` | string | Yes | One of: `low`, `medium`, `high`, `critical` |
| `description` | string | Yes | Human-readable description |
| `evidence` | array | No | List of evidence strings |
| `scan_id` | string | No | Associated scan ID |

**Threat Categories:** `credential_exfiltration`, `backdoor`, `install_hook_abuse`, `typosquat`, `obfuscated_payload`, `cryptominer`, `data_exfiltration`, `other`

**Response (201 Created):**

```json
{
  "report_id": "rpt_m1n2o3p4q5r6",
  "status": "submitted",
  "source_ref": "aws-helper-utils",
  "category": "credential_exfiltration",
  "severity": "critical",
  "created_at": "2026-02-15T15:00:00Z"
}
```

**Status Codes:** 201 Created, 401 Unauthorized, 422 Validation error, 429 Rate limited (max 10/hour)

---

## Verification

### POST /v1/verify

Verify a package or tool for marketplace listing. Runs an enhanced scan and returns a verification result suitable for trust badges.

| Property | Value |
|----------|-------|
| **Auth required** | Yes |
| **Also available at** | `POST /verify` |

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `source_type` | string | Yes | One of: `git`, `pip`, `npm`, `url` |
| `source_ref` | string | Yes | Package name, URL, or repository |
| `source_version` | string | No | Specific version to verify |
| `source_hash` | string | No | SHA-256 hash for integrity check |
| `callback_url` | string | No | Webhook URL for async notification |

**Response (200 OK):**

```json
{
  "verification_id": "ver_s1t2u3v4w5x6",
  "status": "verified",
  "source_ref": "langchain-community",
  "source_version": "0.2.1",
  "score": 3,
  "verdict": "LOW_RISK",
  "badge_url": "https://sigilsec.ai/badge/ver_s1t2u3v4w5x6.svg",
  "verified_at": "2026-02-15T15:30:00Z",
  "expires_at": "2026-03-15T15:30:00Z"
}
```

**Status Codes:** 200 OK, 401 Unauthorized, 403 Requires Pro or Team tier, 404 Package not found, 422 Validation error

---

## Team Management

### GET /team

Get the current user's team with all members.

| Property | Value |
|----------|-------|
| **Auth required** | Yes |

**Response (200 OK):**

```json
{
  "id": "team_abc123",
  "name": "My Team",
  "owner_id": "usr_a1b2c3d4e5f6",
  "plan": "pro",
  "members": [
    {
      "id": "usr_a1b2c3d4e5f6",
      "email": "owner@example.com",
      "name": "Jane Dev",
      "role": "owner",
      "created_at": "2026-01-01T00:00:00Z"
    }
  ],
  "created_at": "2026-01-01T00:00:00Z"
}
```

**Status Codes:** 200 OK, 401 Unauthorized

---

### POST /team/invite

Invite a member to the team by email. Only admins and owners can invite.

| Property | Value |
|----------|-------|
| **Auth required** | Yes (admin/owner) |

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `email` | string | Yes | Email address to invite |
| `role` | string | Yes | One of: `member`, `admin`, `owner` |

**Response (200 OK):**

```json
{
  "success": true,
  "message": "Invitation sent to 'dev@example.com'",
  "email": "dev@example.com",
  "role": "member"
}
```

**Status Codes:** 200 OK, 401 Unauthorized, 403 Not admin/owner, 422 Invalid role

---

### DELETE /team/members/{id}

Remove a member from the team. Only admins and owners can remove members. The team owner cannot be removed.

| Property | Value |
|----------|-------|
| **Auth required** | Yes (admin/owner) |

**Response:** 204 No Content

**Status Codes:** 204 No Content, 400 Cannot remove yourself, 401 Unauthorized, 403 Not admin/owner or target is owner, 404 User not found

---

### PATCH /team/members/{id}/role

Update a team member's role. Only admins and owners can change roles. Only the current owner can assign the `owner` role.

| Property | Value |
|----------|-------|
| **Auth required** | Yes (admin/owner) |

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `role` | string | Yes | One of: `member`, `admin`, `owner` |

**Response (200 OK):**

```json
{
  "id": "usr_x1y2z3",
  "email": "dev@example.com",
  "name": "Dev User",
  "role": "admin",
  "created_at": "2026-01-15T00:00:00Z"
}
```

**Status Codes:** 200 OK, 401 Unauthorized, 403 Insufficient permissions, 404 User not found, 422 Invalid role

---

## Policies

### GET /v1/policies

List all policies for the authenticated user's team.

| Property | Value |
|----------|-------|
| **Auth required** | Yes |
| **Also available at** | `GET /policies`, `GET /settings/policy` |

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `enabled` | boolean | No | Filter by enabled state |

**Response (200 OK):**

```json
[
  {
    "id": "pol_abc123",
    "team_id": "team_xyz",
    "name": "Block known malware",
    "type": "blocklist",
    "config": {"packages": ["evil-package", "malware-pkg"]},
    "enabled": true,
    "created_at": "2026-02-01T00:00:00Z",
    "updated_at": "2026-02-10T00:00:00Z"
  }
]
```

**Status Codes:** 200 OK, 401 Unauthorized

---

### POST /v1/policies

Create a new scan policy for the team.

| Property | Value |
|----------|-------|
| **Auth required** | Yes |
| **Also available at** | `POST /policies`, `POST /settings/policy` |

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Policy name |
| `type` | string | Yes | One of: `allowlist`, `blocklist`, `auto_approve_threshold`, `required_phases` |
| `config` | object | Yes | Policy configuration (varies by type) |
| `enabled` | boolean | No | Whether the policy is active (default: true) |

**Response (201 Created):** PolicyResponse object.

**Status Codes:** 201 Created, 401 Unauthorized

---

### PUT /v1/policies/{id}

Update an existing policy. Only provided fields are updated.

| Property | Value |
|----------|-------|
| **Auth required** | Yes |
| **Also available at** | `PUT /policies/{id}`, `PUT /settings/policy/{id}` |

**Request Body:** Same as POST, all fields optional.

**Response (200 OK):** Updated PolicyResponse object.

**Status Codes:** 200 OK, 401 Unauthorized, 403 Policy not in your team, 404 Not found

---

### DELETE /v1/policies/{id}

Delete a policy by ID.

| Property | Value |
|----------|-------|
| **Auth required** | Yes |
| **Also available at** | `DELETE /policies/{id}`, `DELETE /settings/policy/{id}` |

**Response:** 204 No Content

**Status Codes:** 204 No Content, 401 Unauthorized, 403 Policy not in your team, 404 Not found

---

### POST /v1/policies/evaluate

Evaluate a scan result against all enabled team policies.

| Property | Value |
|----------|-------|
| **Auth required** | Yes |
| **Also available at** | `POST /policies/evaluate` |

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `target` | string | Yes | Package/target name |
| `risk_score` | number | Yes | Risk score from the scan |
| `findings` | array | Yes | Array of Finding objects |

**Response (200 OK):**

```json
{
  "allowed": true,
  "violations": [],
  "auto_approved": true,
  "evaluated_policies": 3
}
```

**Status Codes:** 200 OK, 401 Unauthorized

---

## Alerts

### GET /v1/alerts

List alert channel configurations for the team.

| Property | Value |
|----------|-------|
| **Auth required** | Yes |
| **Also available at** | `GET /alerts`, `GET /settings/alerts` |

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `enabled` | boolean | No | Filter by enabled state |

**Response (200 OK):**

```json
[
  {
    "id": "alt_abc123",
    "team_id": "team_xyz",
    "channel_type": "slack",
    "channel_config": {"webhook_url": "https://hooks.slack.com/..."},
    "enabled": true,
    "created_at": "2026-02-01T00:00:00Z"
  }
]
```

**Status Codes:** 200 OK, 401 Unauthorized

---

### POST /v1/alerts

Create a new alert channel.

| Property | Value |
|----------|-------|
| **Auth required** | Yes |
| **Also available at** | `POST /alerts`, `POST /settings/alerts` |

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `channel_type` | string | Yes | One of: `slack`, `email`, `webhook` |
| `channel_config` | object | Yes | Channel-specific configuration |
| `enabled` | boolean | No | Whether the channel is active (default: true) |

**Channel Config by Type:**
- **slack:** `{"webhook_url": "https://hooks.slack.com/..."}`
- **email:** `{"recipients": ["alerts@example.com"]}`
- **webhook:** `{"webhook_url": "https://...", "headers": {}}`

**Response (201 Created):** AlertResponse object.

**Status Codes:** 201 Created, 401 Unauthorized, 422 Invalid config

---

### PUT /v1/alerts/{id}

Update an alert channel configuration.

| Property | Value |
|----------|-------|
| **Auth required** | Yes |
| **Also available at** | `PUT /alerts/{id}`, `PUT /settings/alerts/{id}` |

**Request Body:** Same as POST, all fields optional.

**Response (200 OK):** Updated AlertResponse object.

**Status Codes:** 200 OK, 401 Unauthorized, 403 Not your team, 404 Not found

---

### DELETE /v1/alerts/{id}

Remove an alert channel.

| Property | Value |
|----------|-------|
| **Auth required** | Yes |
| **Also available at** | `DELETE /alerts/{id}`, `DELETE /settings/alerts/{id}` |

**Response:** 204 No Content

**Status Codes:** 204 No Content, 401 Unauthorized, 403 Not your team, 404 Not found

---

### POST /v1/alerts/test

Send a test notification through a channel configuration. Does not require the channel to be saved.

| Property | Value |
|----------|-------|
| **Auth required** | Yes |
| **Also available at** | `POST /alerts/test`, `POST /settings/alerts/test` |

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `channel_type` | string | Yes | One of: `slack`, `email`, `webhook` |
| `channel_config` | object | Yes | Channel configuration to test |

**Response (200 OK):**

```json
{
  "success": true,
  "message": "Test notification sent successfully"
}
```

**Status Codes:** 200 OK, 401 Unauthorized, 422 Invalid config

---

## Billing

### GET /v1/billing/plans

List available subscription plans.

| Property | Value |
|----------|-------|
| **Auth required** | No |
| **Also available at** | `GET /billing/plans` |

**Response (200 OK):**

```json
[
  {
    "tier": "free",
    "name": "Free",
    "price_monthly": 0.0,
    "scans_per_month": 50,
    "features": ["50 scans/month", "Community threat intelligence", "Basic scan reports", "Single user"]
  },
  {
    "tier": "pro",
    "name": "Pro",
    "price_monthly": 29.0,
    "scans_per_month": 500,
    "features": ["500 scans/month", "Full threat intelligence", "Advanced scan reports", "Priority support", "API access", "Custom policies"]
  },
  {
    "tier": "team",
    "name": "Team",
    "price_monthly": 99.0,
    "scans_per_month": 5000,
    "features": ["5,000 scans/month", "Full threat intelligence", "Team dashboard", "RBAC & audit log", "Slack/webhook alerts", "Custom policies", "Priority support", "SSO (SAML)"]
  },
  {
    "tier": "enterprise",
    "name": "Enterprise",
    "price_monthly": 0.0,
    "scans_per_month": 0,
    "features": ["Unlimited scans", "Custom contract"]
  }
]
```

---

### POST /v1/billing/subscribe

Create or change a subscription.

| Property | Value |
|----------|-------|
| **Auth required** | Yes |
| **Also available at** | `POST /billing/subscribe` |

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `plan` | string | Yes | One of: `free`, `pro`, `team` |

**Response (200 OK):** SubscriptionResponse with plan, status, period dates, and Stripe subscription ID (if applicable).

**Status Codes:** 200 OK, 400 Enterprise requires custom contract, 401 Unauthorized, 502 Payment provider error

---

### GET /v1/billing/subscription

Get the current subscription for the authenticated user.

| Property | Value |
|----------|-------|
| **Auth required** | Yes |
| **Also available at** | `GET /billing/subscription` |

**Response (200 OK):**

```json
{
  "plan": "pro",
  "status": "active",
  "current_period_start": "2026-02-01T00:00:00Z",
  "current_period_end": "2026-03-01T00:00:00Z",
  "cancel_at_period_end": false,
  "stripe_subscription_id": "sub_xxx"
}
```

**Status Codes:** 200 OK, 401 Unauthorized

---

### POST /v1/billing/portal

Create a Stripe Customer Portal session for managing subscription, payment methods, and invoices.

| Property | Value |
|----------|-------|
| **Auth required** | Yes |
| **Also available at** | `POST /billing/portal` |

**Response (200 OK):**

```json
{
  "url": "https://billing.stripe.com/session/..."
}
```

**Status Codes:** 200 OK, 400 No billing account, 401 Unauthorized, 502 Payment provider error

---

### POST /v1/billing/webhook

Stripe webhook handler. Called by Stripe directly to notify of subscription changes, payment events, etc.

| Property | Value |
|----------|-------|
| **Auth required** | No (verified via Stripe signature) |
| **Also available at** | `POST /billing/webhook` |

**Headers:**

| Header | Description |
|--------|-------------|
| `stripe-signature` | Stripe webhook signature for verification |

**Response (200 OK):**

```json
{
  "received": true,
  "event_type": "customer.subscription.updated"
}
```

**Status Codes:** 200 OK, 400 Invalid payload or signature

---

## System

### GET /health

Health check endpoint. Returns service status and backend connectivity.

| Property | Value |
|----------|-------|
| **Auth required** | No |

**Response (200 OK):**

```json
{
  "status": "ok",
  "version": "0.1.0",
  "supabase_connected": true,
  "redis_connected": true
}
```

---

### GET /

Root endpoint with API metadata.

| Property | Value |
|----------|-------|
| **Auth required** | No |

**Response (200 OK):**

```json
{
  "service": "Sigil API",
  "version": "0.1.0",
  "docs": "/docs"
}
```

---

## Error Handling

All error responses follow a consistent format:

```json
{
  "detail": "Human-readable error message"
}
```

### Common Status Codes

| HTTP Status | Description |
|-------------|-------------|
| 400 | Malformed request body or invalid parameters |
| 401 | Missing or invalid authentication token |
| 403 | Valid token but insufficient permissions |
| 404 | Requested resource does not exist |
| 409 | Resource already exists (e.g., duplicate registration) |
| 413 | Request body exceeds maximum size (1MB) |
| 422 | Request body fails schema validation |
| 429 | Too many requests; retry after `Retry-After` header |
| 500 | Unexpected server error |
| 502 | External service error (Stripe, etc.) |

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

### Interactive API Docs

The API provides interactive documentation at:
- **Swagger UI:** `GET /docs`
- **ReDoc:** `GET /redoc`
- **OpenAPI JSON:** `GET /openapi.json`
