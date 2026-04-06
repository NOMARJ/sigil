# Architecture Patterns

> NOMARK Level 1 — Universal. Index of repeatable blueprints for common components.
> Pattern templates live in `templates/patterns/`. This file is the index.

---

## 1. Service Blueprint

**When:** Creating a new microservice for any venture.
**Produces:** API with health check, structured JSON logging, Dockerfile, Terraform module, GitHub Actions CI pipeline, README.
**Template:** `templates/patterns/service-blueprint/`

Standard scaffolding for a stateless service. Includes `/health` endpoint, request ID propagation, graceful shutdown, and environment-based config. Every new service starts here.

## 2. Data Pipeline Blueprint

**When:** Building ingestion, transformation, or analytics workflows.
**Produces:** Ingestion endpoint or trigger, validation layer, transform stage, storage writer, notification on completion/failure.
**Template:** `templates/patterns/data-pipeline-blueprint/`

Ingestion → validation → transform → store → notify. Each stage is independently testable. Failed records go to a dead letter store with the original payload and error context.

## 3. Auth Blueprint

**When:** Adding authentication or authorization to a service.
**Produces:** Token acquisition flow, refresh logic, scope validation middleware, secret rotation procedure.
**Template:** `templates/patterns/auth-blueprint/`

OAuth2/OIDC by default. Handles token lifecycle, scope-based access control, and secret rotation without downtime. Never roll custom auth without an ADR.

## 4. Agent Integration Blueprint

**When:** Connecting an AI agent to a service as a tool.
**Produces:** Standardized tool interface, error envelope, retry policy with exponential backoff, circuit breaker, structured logging of agent actions.
**Template:** `templates/patterns/agent-integration-blueprint/`

Defines how AI agents call services. Consistent error format, idempotency keys, rate limiting awareness, and audit trail of agent-initiated actions.

## 5. BPO-to-SaaS Migration Blueprint

**When:** Graduating a manual/BPO process into software.
**Produces:** Manual process documentation, dashboard for visibility, API for automation, self-serve interface for end users.
**Template:** `templates/patterns/bpo-to-saas-blueprint/`

Four-phase migration: manual process → dashboard (visibility) → API (automation) → self-serve (product). Each phase is a deployable increment. Captures the operational knowledge before automating it.

## 6. API Gateway Blueprint

**When:** Exposing multiple services through a unified entry point.
**Produces:** Rate limiting config, auth middleware, request validation, response envelope, routing rules, CORS policy.
**Template:** `templates/patterns/api-gateway-blueprint/`

Single entry point for external consumers. Handles cross-cutting concerns so individual services don't duplicate them. Routes to downstream services by path or header.

## 7. Event Bus Blueprint

**When:** Decoupling services through asynchronous messaging.
**Produces:** Topic/queue configuration, publisher interface, subscriber interface, dead letter handling, idempotency strategy, ordering guarantees documentation.
**Template:** `templates/patterns/event-bus-blueprint/`

Pub/sub pattern with explicit contracts. Every event has a schema, version, and correlation ID. Dead letters are monitored. Consumers are idempotent. Ordering is documented per topic.

---

## Pattern Promotion

Patterns start in one venture. If proven, they get extracted into `templates/patterns/` via the CHANGE-GOVERNANCE.md process and become available portfolio-wide. Bottom-up, not top-down.
