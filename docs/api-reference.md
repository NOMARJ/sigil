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

Submit a scan's findings. The API scores them, looks up any package hashes in the request metadata, stores the scan for the account's scan history, and returns the result. `sigil scan --submit` and `sigil explain` call it. Each finding carries its flagged source line (`snippet`), so a submission includes excerpts of the scanned code, not only metadata (see [Data Handling](data-handling.md#2-scan-submission-sigil-scan---submit)).

| Property | Value |
|----------|-------|
| **Auth required** | Yes (Bearer token, any plan) |
| **Limits** | 30 requests per minute; each stored scan counts against the plan's monthly scan quota (HTTP 429 when it is used up) |

**Request Body** (`ScanRequest`, `api/models.py`):

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `target` | string | Yes | Name of what was scanned. `sigil scan --submit` sends the fixed name `cli-scan` and `sigil explain` sends `sigil-explain`, not the scanned path. A body without `target` is accepted only when it is the raw scan result CLI 1.3.7 posts (it has `score`, `verdict`, `duration_ms` and `findings`); it is filed under `cli-scan` |
| `target_type` | string | No | Default `directory`; for example `git`, `pip`, `npm` |
| `files_scanned` | integer | No | Default 0 |
| `findings` | array | No | Finding objects (below); default empty |
| `metadata` | object | No | Stored with the scan and returned by the detail endpoints `GET /v1/scans/{id}` and `GET /scans/{id}` (as `metadata_json`) and by the list endpoints `GET /scans` and `GET /v1/scans` (in each item's `metadata`, where their query reads it: the in-memory store does, the MSSQL list query leaves it out). The CLI sends `source`, `cli_score` and `cli_verdict` (its own score and verdict). `hash` or `hashes` are looked up in the threat database |

**Finding Object:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `phase` | string | Yes | `install_hooks`, `code_patterns`, `network_exfil`, `credentials`, `obfuscation`, `provenance`, `prompt_injection`, `skill_security`, `llm_analysis` or `inference_security`. Case and separators are ignored, so the CLI's `InstallHooks` is accepted; any other name is refused (422) |
| `rule` | string | Yes | Rule identifier (e.g. `INSTALL-001`) |
| `severity` | string | Yes | `INFO`, `LOW`, `MEDIUM`, `HIGH` or `CRITICAL`, in any case (`High` is accepted) |
| `file` | string | Yes | Path of the file, relative to the scanned directory |
| `line` | integer | No | Line number (1-based), or `null` |
| `snippet` | string | No | The flagged source line |
| `weight` | number | No | Weight multiplier (default 1.0) |
| `confidence` | string | No | `HIGH` (default), `MEDIUM` or `LOW` |
| `description`, `explanation` | string | No | Free text |

Other fields (the CLI's `fingerprint`, for example) are ignored.

**Response (200 OK)** (`ScanResponse`), a captured response for a five-finding scan (`tests/fixtures/api_contract/api-patched/scan_response.json`), shortened to one finding:

```json
{
  "scan_id": "5fdbc380-845b-4b86-a497-801fc1db34ed",
  "id": "5fdbc380-845b-4b86-a497-801fc1db34ed",
  "status": "completed",
  "target": "cli-scan",
  "target_type": "directory",
  "files_scanned": 5,
  "findings": [
    {
      "phase": "code_patterns",
      "rule": "CODE-001",
      "severity": "HIGH",
      "confidence": "HIGH",
      "file": "src/app.js",
      "line": 2,
      "snippet": "eval() call — arbitrary code execution: return eval(userInput);",
      "weight": 5.0,
      "description": "",
      "explanation": ""
    }
  ],
  "risk_score": 384.0,
  "verdict": "CRITICAL_RISK",
  "threat_intel_hits": [],
  "metadata": {
    "scanner_features": {
      "confidence_scoring": true,
      "context_aware_analysis": true,
      "false_positive_reduction": true
    }
  },
  "created_at": "2026-10-08T13:22:03.380855",
  "disclaimer": "Automated static analysis result. Not a security certification. Provided as-is without warranty. See sigilsec.ai/terms for full terms."
}
```

- `risk_score` and `verdict` are the API's own (`api/services/scoring.py`), computed from the submitted findings; scan history shows the API's. For a CLI submission they are typically higher than the score and verdict the CLI printed, which it sends as `metadata.cli_score` and `metadata.cli_verdict`. The API scores a finding as severity × phase weight × the finding's `weight`, and the CLI's `weight` already includes its phase weight, so the phase weight counts twice; the API also counts Low findings and caps nothing per rule and file, where the CLI's verdict ignores Low findings and counts at most three findings of one rule in one file. The five findings above are score 58, HIGH RISK, in the CLI and 384.0, `CRITICAL_RISK`, here. The formula is unchanged by the CLI contract fix.
- `threat_intel_hits` holds the threat entries that `metadata.hash` or `metadata.hashes` matched; each match adds 10 to `risk_score`. The entries read as in `GET /v1/threat/{hash}` below: control, format and separator characters replaced by spaces. A confirmed `sigil report <hash>` report is not a match for the hash it names: the threat entry is keyed by a hash of the report's package identity, so a scan that lists the reported hash gets no hit and no extra score.
- `id` is a copy of `scan_id` and `status` is always `completed`: CLI 1.3.7 reads them.
- `metadata` holds the API's notes about the scan, not the request's metadata.

**Status Codes:** 200 OK, 401 Missing or invalid token, 422 Validation error, 429 Rate limit or monthly scan quota exceeded

---

### POST /v1/scan-enhanced

`sigil scan --enhanced`: the `POST /v1/scan` request plus source files for LLM analysis, a Pro plan feature. The request is stored as a scan the same way, except that only the scan's own metadata keys are stored, not the uploaded files (an API without the update stored them with the scan record: see [API update rollout](cli.md#api-update-rollout) and [Data Handling](data-handling.md#3-pro-enhanced-scan-and-ai-investigation)). **The LLM step does not run for this endpoint yet**: on a Pro plan it fails and the API returns the static result; on a Free plan it returns the static result with an upgrade note. See [CLI LLM features](CLI_LLM_FEATURES.md) for what the CLI sends and prints.

| Property | Value |
|----------|-------|
| **Auth required** | Yes (Bearer token). Any plan is accepted: the plan is checked after the upload |
| **Limits** | 20 requests per minute; each stored scan counts against the monthly scan quota |

**Request Body:** as for `POST /v1/scan`, with the files in `metadata.file_contents`, an object mapping each relative path to the file's text (or one file as `metadata.filename` and `metadata.content`). The API passes them to its LLM step and leaves them out of the stored scan: of the request's `metadata` it stores only `source`, `cli_score`, `cli_verdict`, `hash`, `hashes`, `publisher` and `publisher_id`, and drops every other key (the CLI's `file_contents`, a single file's `content`, and whatever another client names its files).

**Response (200 OK):** the `POST /v1/scan` response, with `metadata` saying what happened to the LLM step:

| Outcome | `metadata` |
|---------|------------|
| LLM analysis ran | `llm_analysis_performed: true`, `enhanced_findings_count`, `original_risk_score`, `enhanced_risk_score`; LLM findings are added to `findings` with phase `llm_analysis` |
| Free plan | `upgrade_required: true`, `upgrade_message`, `upgrade_url`, `missing_features` |
| Pro plan, LLM step failed | `llm_analysis_performed: false`, `llm_error` (the exception type only), `fallback_to_static: true` |
| Pro plan, no files | `llm_analysis_performed: false`, `reason` |

`id` is included only when LLM analysis ran. CLI 1.3.7 reads `id` and prints `Enhanced LLM analysis completed` for any response that has it, so without analysis it reports a failed enhanced analysis instead.

**Status Codes:** 200 OK, 401 Missing or invalid token, 422 Validation error, 429 Rate limit or monthly scan quota exceeded

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

Look up a hash in the threat intelligence database. `sigil scan --enrich` calls it with a SHA-256 of the scanned directory's file paths and sizes.

| Property | Value |
|----------|-------|
| **Auth required** | Yes (Bearer token), Pro plan or higher |
| **Also available at** | `GET /threat/{hash}` |

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `hash` | string | The hash to look up. Entries are keyed by the SHA-256 of a package artifact; an entry made by confirming a report is keyed by a hash of the report's ecosystem, name and version |

**Response (200 OK)** (`ThreatLookupResponse`), as captured for a seeded entry (`tests/fixtures/api_contract/api-patched/threat_lookup_response.json`):

```json
{
  "hash": "0529ae7c5118983272f1fce4ca862408bdcf403b6a6d4483cb2b34e83a64d548",
  "package_name": "contract-test-pkg",
  "version": "0.0.1",
  "severity": "CRITICAL",
  "source": "internal",
  "confirmed_at": "2026-10-01T00:00:00",
  "description": "seeded contract-test threat entry",
  "known_malicious": true,
  "references": []
}
```

- Every 200 response is a match: an unknown hash returns 404. `known_malicious` is always `true` and `references` is always empty (none are recorded); CLI 1.3.7 needs both fields.
- A community entry (`source: "community"`, made when a reviewer confirms a report) has the reporter's text as its description.
- In the text fields, control characters (including terminal escapes), format characters (bidirectional overrides and isolates, zero-width characters) and the line and paragraph separators U+2028 and U+2029 are replaced with spaces. `POST /v1/verify` and the `threat_intel_hits` of `POST /v1/scan` show entries the same way.
- A confirmed `sigil report <hash>` report is **not findable by that hash**: confirming a report creates the entry keyed by the SHA-256 of `ecosystem:name:version` (for a hash report, `unknown:sha256:<hash>:`), as for every report, so a lookup of the hash given to `sigil report` returns 404, `POST /v1/verify` with that `artifact_hash` finds no threat, and `POST /v1/scan` with that hash in `metadata.hash` or `metadata.hashes` adds nothing to the risk score.

**Status Codes:** 200 OK, 401 Missing or invalid token, 403 Plan below Pro, 404 Hash not found

**403 body** (captured, `api-patched/threat_lookup_403_free_plan.json`):

```json
{
  "detail": "This feature requires the pro plan or higher.",
  "required_plan": "pro",
  "current_plan": "free",
  "upgrade_url": "https://app.sigilsec.ai/upgrade"
}
```

---

### GET /v1/signatures

Fetch pattern detection signatures. Supports delta sync via the `since` parameter.

| Property | Value |
|----------|-------|
| **Auth required** | Yes (Bearer token), Pro plan or higher |
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

Submit a threat report. Reports are queued for review; when a reviewer confirms one (`PATCH /v1/threat-reports/{id}`), it becomes a threat database entry with source `community`. `sigil report` and the dashboard call it.

| Property | Value |
|----------|-------|
| **Auth required** | No |
| **Also available at** | `POST /threats/report` and `POST /report` |

**Request Body** (`ThreatReport`, `api/models.py`):

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `package_name` | string | Yes | Name of the suspicious package. `sigil report <hash>` sends `sha256:<hash>` |
| `reason` | string | Yes | Why the reporter believes it is malicious |
| `package_version` | string | No | Version, if known |
| `ecosystem` | string | No | `npm`, `pip`, `cargo`, ...; default `unknown` |
| `evidence` | string | No | Supporting evidence. `sigil report` sends the threat type and the hash |
| `reporter_email` | string | No | Contact email |

The body CLI 1.3.7 sends, `{"hash": "<sha256>", "threat_type": "<type>", "description": "<text>"}`, is also accepted and stored the same way as the current CLI's report: package `sha256:<hash>`, the description as the reason, and `Threat type: <type>` and `SHA-256: <hash>` as evidence. Its `hash` must be a SHA-256 digest (64 hexadecimal characters, any case); anything else is refused (422).

A confirmed report is keyed in the threat database by a SHA-256 of its ecosystem, name and version, for a hash report too (`unknown:sha256:<hash>:`), never by the hash that was typed: a confirmed hash report is not findable by that hash (see `GET /v1/threat/{hash}`), and changes no `POST /v1/verify` verdict or `POST /v1/scan` score for it. A confirmed report with evidence also gets a detection signature built from that evidence. Confirming needs the reviewer role.

**Response (201 Created)** (`ThreatReportResponse`), captured (`tests/fixtures/api_contract/api-patched/report_response.json`):

```json
{
  "report_id": "36d5a8357323",
  "id": "36d5a8357323",
  "status": "received",
  "message": "Thank you for your report. Our team will review it."
}
```

`id` is a copy of `report_id`, which CLI 1.3.7 reads.

**Status Codes:** 201 Created, 422 Validation error

---

## Verification

### POST /v1/verify

Verify a package for a marketplace trust badge. It checks the artifact hash against the threat database and the publisher's reputation, and returns a verdict. Only a `LOW_RISK` verdict is `verified` and gets a badge URL.

| Property | Value |
|----------|-------|
| **Auth required** | No: the API does not check a token |
| **Also available at** | `POST /verify` |

**Request Body** (`VerifyRequest`, `api/models.py`):

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `package_name` | string | Yes | Fully qualified package name |
| `package_version` | string | Yes | Exact version to verify |
| `ecosystem` | string | Yes | `npm`, `pip`, `cargo`, ... |
| `publisher_id` | string | No | Publisher identifier; a publisher with flagged packages or a low trust score adds to the risk score |
| `artifact_hash` | string | No | SHA-256 hash of the distribution artifact, looked up in the threat database like `GET /v1/threat/{hash}` |

**Response (200 OK)** (`VerifyResponse`), as captured from the API in this tree (in-memory store) for an `artifact_hash` that a confirmed package report (`"package_name": "evil-pkg"`, reason `steals tokens`) is keyed by:

```json
{
  "package_name": "some-package",
  "package_version": "1.0.0",
  "verified": false,
  "verdict": "CRITICAL_RISK",
  "risk_score": 50.0,
  "badge_url": null,
  "findings_summary": "Known threat: steals tokens (severity=CRITICAL)",
  "verified_at": "2026-10-08T16:12:37.211559"
}
```

- A match on `artifact_hash` adds 50 to `risk_score`, which is `CRITICAL_RISK` on its own, and names the entry in `findings_summary` (its description, or the package name when it has none). Control, format and separator characters in the description are replaced with spaces (see `GET /v1/threat/{hash}`). A confirmed `sigil report <hash>` report is not a match for the hash it names, because its threat entry is keyed by a hash of the report's package identity: confirming it changes nothing here (a request with that hash gets `LOW_RISK`, risk score 0 and `No issues found.`, as before the report; a test pins this). The endpoint needs no token, so anyone can ask whether a hash is flagged.
- With no match and no publisher findings, `findings_summary` is `No issues found.`

**Status Codes:** 200 OK, 422 Validation error, 429 Rate limit exceeded

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
