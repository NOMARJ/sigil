# Tech Radar

> NOMARK Level 1 — Universal. Agents use Tier 1 by default, Tier 2 with an ADR, never Tier 3.

---

## Tier 1 — Default

Agents pick these unless the owner specifies otherwise. No justification needed.

| Category | Choice |
|----------|--------|
| Languages | TypeScript (services, web), Rust (CLI, performance-critical), Python (data, ML, scripting), Swift (iOS) |
| Cloud | Azure or AWS. Per-venture choice. Never mixed within a venture. |
| IaC | Terraform |
| Containers | Docker → managed container services (ECS, Azure Container Apps, Cloud Run) |
| Relational DB | PostgreSQL |
| Embedded DB | SQLite |
| Queues/Events | Azure Service Bus or SQS/SNS (matches venture cloud choice) |
| Auth | OAuth2 / OIDC |
| CI/CD | GitHub Actions |
| Monitoring | Structured JSON logging → managed service (Azure Monitor, CloudWatch) |
| Frontend | React / Next.js, Tailwind CSS |

## Tier 2 — ADR Required

Allowed with an Architecture Decision Record approved by owner. Must document why Tier 1 doesn't fit.

| Category | Examples |
|----------|----------|
| Graph databases | Neptune, Neo4j |
| NoSQL | Redis, DynamoDB, CosmosDB |
| Alternative languages | Go, Kotlin, C# — for specific justified use cases |
| Third-party SaaS | Any external dependency not in Tier 1 |
| Non-standard auth | API keys, mTLS, custom token flows |
| Alternative CI/CD | CircleCI, GitLab CI, Buildkite |
| Mobile cross-platform | React Native, Flutter |

## Tier 3 — Prohibited

Never use. No exceptions. No ADR overrides this.

| Rule | Reason |
|------|--------|
| Vendor lock-in without abstraction | Cannot sell or migrate venture independently |
| Unmanaged Kubernetes | Operational overhead exceeds one-person model |
| Manual provisioning tools | Violates infrastructure-as-code principle |
| Cross-venture runtime coupling | Violates venture independence principle |
| Serverless-only without local dev parity | Breaks development workflow |

---

## Review

Tech Radar is reviewed quarterly. Changes follow CHANGE-GOVERNANCE.md process.
