# Sigil API — Complete Endpoint Reference

Quick-reference listing of every API endpoint. For detailed request/response schemas, see [api-reference.md](api-reference.md).

**Base URL:** `https://api.sigilsec.ai` | `http://localhost:8000` (local)

---

## Table of Contents

- [Core System](#core-system)
- [Authentication](#authentication)
- [Scan Management](#scan-management)
- [Threat Intelligence](#threat-intelligence)
- [Verification](#verification)
- [Threat Reporting](#threat-reporting)
- [Publisher Reputation](#publisher-reputation)
- [Billing](#billing)
- [Team Management](#team-management)
- [Alerts](#alerts)
- [Policies](#policies)
- [Public Feed](#public-feed)
- [Badge Generation](#badge-generation)
- [Public Registry](#public-registry)
- [MCP Permissions](#mcp-permissions)
- [Attestation](#attestation)
- [Email Newsletter](#email-newsletter)
- [GitHub App](#github-app)
- [Forge](#forge)
- [Forge Premium](#forge-premium)
- [Forge Secure](#forge-secure)
- [Forge Analytics](#forge-analytics)
- [Real-time Updates](#real-time-updates)

---

## Core System

Source: `api/main.py`

| Method | Path | Auth | Description |
|--------|------|:----:|-------------|
| GET | `/` | No | Root endpoint with API metadata |
| GET | `/health` | No | Basic health check |
| GET | `/health/detailed` | No | Detailed health check with dependency status |
| GET | `/health/ready` | No | Kubernetes readiness probe |
| GET | `/health/live` | No | Kubernetes liveness probe |
| GET | `/metrics` | No | Prometheus metrics export |
| GET | `/api/docs` | No | Public API documentation page |
| GET | `/api/test-email` | No | Test email configuration |

---

## Authentication

Source: `api/routers/auth.py` — Prefix: `/v1/auth`

| Method | Path | Auth | Rate Limit | Description |
|--------|------|:----:|:----------:|-------------|
| POST | `/v1/auth/register` | No | 10/min | Create new user account |
| POST | `/v1/auth/login` | No | 30/min | Authenticate and receive JWT |
| GET | `/v1/auth/me` | Yes | — | Get current user profile |
| POST | `/v1/auth/refresh` | No | — | Refresh access token |
| POST | `/v1/auth/logout` | Yes | — | Log out and revoke token |
| POST | `/v1/auth/forgot-password` | No | — | Request password reset email |
| POST | `/v1/auth/reset-password` | No | — | Reset password with token |

---

## Scan Management

Source: `api/routers/scan.py`

| Method | Path | Auth | Description |
|--------|------|:----:|-------------|
| POST | `/v1/scan` | No | Submit scan results for threat intel enrichment |
| POST | `/v1/scans` | No | Submit scan results (legacy v1 compat) |
| POST | `/scans` | No | Submit scan results (dashboard path) |
| GET | `/scans` | Yes | List scans with pagination and filtering |
| GET | `/v1/scans` | Yes | List scans (legacy v1 compat) |
| GET | `/scans/{scan_id}` | Yes | Get single scan details |
| GET | `/v1/scans/{scan_id}` | Yes | Get single scan (legacy v1 compat) |
| GET | `/scans/{scan_id}/findings` | Yes | Get findings for a scan |
| POST | `/scans/{scan_id}/approve` | Yes | Approve a quarantined scan |
| POST | `/scans/{scan_id}/reject` | Yes | Reject a quarantined scan |
| GET | `/dashboard/stats` | Yes | Aggregate dashboard statistics |

---

## Threat Intelligence

Source: `api/routers/threat.py` — Prefix: `/v1`

| Method | Path | Auth | Description |
|--------|------|:----:|-------------|
| GET | `/v1/threat/{package_hash}` | No | Look up package hash in threat database |
| GET | `/v1/threats` | No | List known threats with pagination/filters |
| GET | `/v1/signatures` | No | Download detection signatures (supports delta sync via `since`) |
| POST | `/v1/signatures` | Yes | Create or update a detection signature |
| DELETE | `/v1/signatures/{sig_id}` | Yes | Delete a detection signature |
| GET | `/v1/threat-reports` | Yes | List threat reports with status filtering |
| GET | `/v1/threat-reports/{report_id}` | Yes | Get single threat report details |
| PATCH | `/v1/threat-reports/{report_id}` | Yes | Update threat report status (review workflow) |

---

## Verification

Source: `api/routers/verify.py` — Prefix: `/v1`

| Method | Path | Auth | Description |
|--------|------|:----:|-------------|
| POST | `/v1/verify` | Yes | Verify package for marketplace badge |

---

## Threat Reporting

Source: `api/routers/report.py` — Prefix: `/v1`

| Method | Path | Auth | Description |
|--------|------|:----:|-------------|
| POST | `/v1/report` | Yes | Submit a threat report for community review |

---

## Publisher Reputation

Source: `api/routers/publisher.py` — Prefix: `/v1`

| Method | Path | Auth | Description |
|--------|------|:----:|-------------|
| GET | `/v1/publisher/{publisher_id}` | No | Get publisher reputation score and history |

---

## Billing

Source: `api/routers/billing.py` — Prefix: `/v1/billing`

| Method | Path | Auth | Description |
|--------|------|:----:|-------------|
| GET | `/v1/billing/plans` | No | List available subscription plans |
| POST | `/v1/billing/subscribe` | Yes | Create or change a subscription |
| GET | `/v1/billing/subscription` | Yes | Get current user subscription |
| POST | `/v1/billing/portal` | Yes | Create Stripe customer portal session |
| POST | `/v1/billing/webhook` | No* | Stripe webhook handler (*verified via Stripe signature) |

---

## Team Management

Source: `api/routers/team.py`

| Method | Path | Auth | Description |
|--------|------|:----:|-------------|
| GET | `/team` | Yes | Get current user's team with members |
| POST | `/team/invite` | Yes (admin) | Invite a member by email |
| DELETE | `/team/members/{user_id}` | Yes (admin) | Remove a member from the team |
| PATCH | `/team/members/{user_id}/role` | Yes (admin) | Update a member's role |

---

## Alerts

Source: `api/routers/alerts.py` — Prefix: `/v1`

| Method | Path | Auth | Description |
|--------|------|:----:|-------------|
| GET | `/v1/alerts` | Yes | List alert channel configurations |
| POST | `/v1/alerts` | Yes | Create a new alert channel |
| PUT | `/v1/alerts/{id}` | Yes | Update an alert channel |
| DELETE | `/v1/alerts/{id}` | Yes | Remove an alert channel |
| POST | `/v1/alerts/test` | Yes | Send a test notification |

---

## Policies

Source: `api/routers/policies.py` — Prefix: `/v1`

| Method | Path | Auth | Description |
|--------|------|:----:|-------------|
| GET | `/v1/policies` | Yes | List team scan policies |
| POST | `/v1/policies` | Yes | Create a new policy |
| PUT | `/v1/policies/{id}` | Yes | Update an existing policy |
| DELETE | `/v1/policies/{id}` | Yes | Delete a policy |
| POST | `/v1/policies/evaluate` | Yes | Evaluate scan results against team policies |

---

## Public Feed

Source: `api/routers/feed.py`

### RSS Feeds

| Method | Path | Auth | Description |
|--------|------|:----:|-------------|
| GET | `/feed.xml` | No | RSS 2.0 threat feed (all scans, filterable) |
| GET | `/feed/threats.xml` | No | RSS feed — HIGH_RISK and CRITICAL_RISK only |
| GET | `/feed/clawhub.xml` | No | RSS feed — ClawHub ecosystem |
| GET | `/feed/pypi.xml` | No | RSS feed — PyPI ecosystem |
| GET | `/feed/npm.xml` | No | RSS feed — npm ecosystem |
| GET | `/feed/github.xml` | No | RSS feed — GitHub ecosystem |
| GET | `/feed/mcp.xml` | No | RSS feed — MCP servers |
| GET | `/feed/watchdog.xml` | No | RSS feed — MCP Watchdog typosquat alerts |

### JSON Feed API

| Method | Path | Auth | Description |
|--------|------|:----:|-------------|
| GET | `/api/v1/feed` | No | JSON feed with filtering |
| GET | `/api/v1/feed/alerts` | No | Recent high-risk alerts |
| GET | `/api/v1/feed/stats` | No | Bot pipeline statistics |
| GET | `/api/v1/feed/mcp-servers` | No | Discovered MCP servers JSON feed |

---

## Badge Generation

Source: `api/routers/badge.py`

| Method | Path | Auth | Description |
|--------|------|:----:|-------------|
| GET | `/badge/{scan_id}` | No | SVG badge for a specific scan |
| GET | `/badge/{ecosystem}/{package_name}` | No | SVG badge for latest scan of a package |
| GET | `/badge/shield/{verdict}` | No | Generic verdict badge (shields.io style) |

---

## Public Registry

Source: `api/routers/registry.py`

| Method | Path | Auth | Description |
|--------|------|:----:|-------------|
| GET | `/registry/search` | No | Search public scan database |
| GET | `/registry/{ecosystem}` | No | List scanned packages in an ecosystem |
| GET | `/registry/{ecosystem}/{name}` | No | Latest scan for a package |
| GET | `/registry/{ecosystem}/{name}/{version}` | No | Scan for a specific package version |
| GET | `/registry/scan/{scan_id}` | No | Public scan detail by ID |
| POST | `/registry/submit` | API Key | Submit a public scan result |
| GET | `/registry/stats` | No | Public registry statistics |

---

## MCP Permissions

Source: `api/routers/permissions.py`

| Method | Path | Auth | Description |
|--------|------|:----:|-------------|
| GET | `/permissions` | No | Permissions directory (HTML) |
| GET | `/permissions/{mcp_name}` | No | Individual MCP server permissions page (HTML) |
| GET | `/api/v1/permissions/{mcp_name}` | No | JSON API for MCP permissions data |
| GET | `/api/v1/permissions/search` | No | Search MCP servers by permissions |

---

## Attestation

Source: `api/routers/attestation.py`

| Method | Path | Auth | Description |
|--------|------|:----:|-------------|
| GET | `/api/v1/attestation/{scan_id}` | No | Retrieve DSSE envelope for a scan |
| POST | `/api/v1/verify` | No | Verify an attestation signature |
| GET | `/.well-known/sigil-verify.json` | No | Public key and verification instructions |

---

## Email Newsletter

Source: `api/routers/email.py`

| Method | Path | Auth | Description |
|--------|------|:----:|-------------|
| POST | `/email/subscribe` | No | Subscribe to Forge Weekly newsletter |
| GET | `/email/unsubscribe/{token}` | No | Show unsubscribe confirmation page |
| POST | `/email/unsubscribe` | No | Process unsubscribe request |
| PUT | `/email/preferences` | Yes | Update email preferences |
| GET | `/email/preferences` | Yes | Get email preferences |
| POST | `/email/campaign` | Yes (admin) | Send email campaign |
| GET | `/email/stats` | Yes (admin) | Get email campaign statistics |
| POST | `/email/webhook/resend` | No* | Resend webhook handler (*verified via signature) |

---

## GitHub App

Source: `api/routers/github_app.py`

| Method | Path | Auth | Description |
|--------|------|:----:|-------------|
| POST | `/github/webhook` | No* | Receive GitHub webhook events (*verified via signature) |
| GET | `/github/install` | No | GitHub App installation redirect |
| POST | `/github/setup` | Yes | Complete GitHub App installation setup |

---

## Forge

Source: `api/routers/forge.py` — Prefix: `/forge`

### Search and Browse

| Method | Path | Auth | Description |
|--------|------|:----:|-------------|
| GET | `/forge/search` | No | Search Forge tools and MCPs |
| GET | `/forge/categories` | No | List available categories |
| GET | `/forge/browse/{category}` | No | Browse tools by category |
| GET | `/forge/tools/{ecosystem}/{name}` | No | Get tool/skill details |
| GET | `/forge/tool/{ecosystem}/{package_name}` | No | Get tool classification |

### Classifications

| Method | Path | Auth | Description |
|--------|------|:----:|-------------|
| GET | `/forge/classifications/skills` | No | Get skill classifications |
| GET | `/forge/classifications/mcps` | No | Get MCP classifications |
| POST | `/forge/classify` | Yes | Classify a tool/skill |

### Stacks

| Method | Path | Auth | Description |
|--------|------|:----:|-------------|
| GET | `/forge/stack` | No | Stack compatibility analysis |
| POST | `/forge/stack` | Yes | Create a tool stack |
| GET | `/forge/stacks` | No | List available stacks |

### MCP

| Method | Path | Auth | Description |
|--------|------|:----:|-------------|
| GET | `/forge/mcp/search` | No | Search MCP servers |
| GET | `/forge/mcp/stack` | No | Check MCP stack compatibility |
| GET | `/forge/mcp/check` | No | Check single MCP compatibility |

### Stats and Feeds

| Method | Path | Auth | Description |
|--------|------|:----:|-------------|
| GET | `/forge/stats` | No | Forge statistics |
| GET | `/forge/stats/detailed` | No | Detailed Forge statistics |
| GET | `/forge/jobs` | Yes | List background jobs |
| GET | `/forge/feed.json` | No | Forge JSON feed |

---

## Forge Premium

Source: `api/routers/forge_premium.py` — Prefix: `/v1/forge`

### Tool Tracking

| Method | Path | Auth | Plan | Description |
|--------|------|:----:|:----:|-------------|
| POST | `/v1/forge/tools/track` | Yes | PRO | Track a tool (compat) |
| GET | `/v1/forge/tools` | Yes | PRO | List tracked tools |
| DELETE | `/v1/forge/tools/{tool_id}` | Yes | PRO | Delete tracked tool |
| GET | `/v1/forge/my-tools` | Yes | PRO | Get my tracked tools |
| POST | `/v1/forge/my-tools/track` | Yes | PRO | Track a new tool |
| DELETE | `/v1/forge/my-tools/{tool_id}/untrack` | Yes | PRO | Untrack a tool |
| PATCH | `/v1/forge/my-tools/{tool_id}` | Yes | PRO | Update tracked tool metadata |

### Stacks

| Method | Path | Auth | Plan | Description |
|--------|------|:----:|:----:|-------------|
| GET | `/v1/forge/stacks` | Yes | PRO | List stacks |
| POST | `/v1/forge/stacks` | Yes | PRO | Create a stack |
| PUT | `/v1/forge/stacks/{stack_id}` | Yes | TEAM | Update a stack |
| DELETE | `/v1/forge/stacks/{stack_id}` | Yes | TEAM | Delete a stack |

### Analytics

| Method | Path | Auth | Plan | Description |
|--------|------|:----:|:----:|-------------|
| GET | `/v1/forge/analytics/personal` | Yes | PRO | Get personal analytics |
| GET | `/v1/forge/analytics/team` | Yes | TEAM | Get team analytics |

### Alerts

| Method | Path | Auth | Plan | Description |
|--------|------|:----:|:----:|-------------|
| GET | `/v1/forge/alerts` | Yes | TEAM | Get alert subscriptions |
| POST | `/v1/forge/alerts` | Yes | TEAM | Create alert subscription |
| PATCH | `/v1/forge/alerts/{subscription_id}` | Yes | TEAM | Update alert subscription |
| DELETE | `/v1/forge/alerts/{subscription_id}` | Yes | TEAM | Delete alert subscription |

### Settings

| Method | Path | Auth | Plan | Description |
|--------|------|:----:|:----:|-------------|
| GET | `/v1/forge/settings` | Yes | PRO | Get user/team settings |
| PUT | `/v1/forge/settings` | Yes | PRO | Update user/team settings |

---

## Forge Secure

Source: `api/routers/forge_secure.py` — Prefix: `/v1/forge`

| Method | Path | Auth | Description |
|--------|------|:----:|-------------|
| POST | `/v1/forge/track-tool` | Yes | Track tool with security audit |
| GET | `/v1/forge/my-tools` | Yes | Get tracked tools (secure) |
| DELETE | `/v1/forge/track-tool/{tool_id}` | Yes | Untrack tool (secure) |
| GET | `/v1/forge/analytics/personal` | Yes | Get personal analytics (secure) |
| GET | `/v1/forge/analytics/team` | Yes | Get team analytics (secure) |
| POST | `/v1/forge/stacks` | Yes | Create stack (secure) |
| GET | `/v1/forge/stacks` | Yes | Get stacks (secure) |
| POST | `/v1/forge/api-keys` | Yes | Create API key |
| GET | `/v1/forge/api-keys` | Yes | List API keys |
| DELETE | `/v1/forge/api-keys/{key_id}` | Yes | Delete API key |
| GET | `/v1/forge/audit-logs` | Yes | Get audit logs |
| GET | `/v1/forge/security/status` | Yes | Get security status |

---

## Forge Analytics

Source: `api/routers/forge_analytics.py` — Prefix: `/forge/analytics`

### Event Tracking

| Method | Path | Auth | Description |
|--------|------|:----:|-------------|
| POST | `/forge/analytics/events` | Yes | Track a single analytics event |
| POST | `/forge/analytics/events/batch` | Yes | Track multiple events in batch |

### Dashboards

| Method | Path | Auth | Description |
|--------|------|:----:|-------------|
| GET | `/forge/analytics/personal` | Yes | Personal analytics dashboard |
| POST | `/forge/analytics/personal/export` | Yes | Export personal analytics data |
| GET | `/forge/analytics/team` | Yes | Team-level analytics |
| GET | `/forge/analytics/team/{team_id}/members` | Yes | Team members analytics |
| GET | `/forge/analytics/organization` | Yes | Organization-level analytics |
| GET | `/forge/analytics/organization/departments` | Yes | Department analytics |

### Real-time

| Method | Path | Auth | Description |
|--------|------|:----:|-------------|
| GET | `/forge/analytics/realtime/dashboard` | Yes | Real-time dashboard data |
| POST | `/forge/analytics/realtime/invalidate` | Yes | Invalidate real-time cache |

### Configuration

| Method | Path | Auth | Description |
|--------|------|:----:|-------------|
| GET | `/forge/analytics/config` | Yes | Get analytics configuration |

---

## Real-time Updates

Source: `api/routers/realtime.py` — Prefix: `/realtime`

| Method | Path | Auth | Description |
|--------|------|:----:|-------------|
| WS | `/realtime/dashboard/{user_id}` | Yes | WebSocket for real-time dashboard updates |
| POST | `/realtime/trigger/dashboard-refresh` | Yes | Manually trigger dashboard refresh |
| POST | `/realtime/trigger/team-refresh` | Yes | Trigger team dashboard refresh |
| POST | `/realtime/notifications/send` | Yes | Send real-time notification |
| GET | `/realtime/analytics/stream` | Yes | Stream analytics data (SSE) |
| POST | `/realtime/cache/invalidate` | Yes | Invalidate cache |
| GET | `/realtime/status` | No | Real-time service status |

---

## Summary

| Module | Endpoints | Source File |
|--------|:---------:|-------------|
| Core System | 8 | `api/main.py` |
| Authentication | 7 | `api/routers/auth.py` |
| Scan Management | 11 | `api/routers/scan.py` |
| Threat Intelligence | 8 | `api/routers/threat.py` |
| Verification | 1 | `api/routers/verify.py` |
| Threat Reporting | 1 | `api/routers/report.py` |
| Publisher Reputation | 1 | `api/routers/publisher.py` |
| Billing | 5 | `api/routers/billing.py` |
| Team Management | 4 | `api/routers/team.py` |
| Alerts | 5 | `api/routers/alerts.py` |
| Policies | 5 | `api/routers/policies.py` |
| Public Feed | 12 | `api/routers/feed.py` |
| Badge Generation | 3 | `api/routers/badge.py` |
| Public Registry | 7 | `api/routers/registry.py` |
| MCP Permissions | 4 | `api/routers/permissions.py` |
| Attestation | 3 | `api/routers/attestation.py` |
| Email Newsletter | 8 | `api/routers/email.py` |
| GitHub App | 3 | `api/routers/github_app.py` |
| Forge | 18 | `api/routers/forge.py` |
| Forge Premium | 20 | `api/routers/forge_premium.py` |
| Forge Secure | 12 | `api/routers/forge_secure.py` |
| Forge Analytics | 11 | `api/routers/forge_analytics.py` |
| Real-time Updates | 7 | `api/routers/realtime.py` |
| **Total** | **~149** | |
