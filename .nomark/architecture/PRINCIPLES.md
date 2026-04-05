# Architecture Principles

> NOMARK Level 1 — Universal. Applies to every venture. Violations are errors.
> Governed by CHARTER.md Article II.7 — agents propose, principals decide.

---

## Rules

1. **Microservices by default.** Monoliths require an ADR with owner approval. The default unit of deployment is a single-purpose service.

2. **Infrastructure as code only.** Nothing exists unless it's in a config file. No click-ops. No manual provisioning. If it can't be reproduced from code, it doesn't belong in production.

3. **Stateless compute, stateful storage.** Services do not hold state between requests. State lives in databases, caches, or object stores — never in application memory.

4. **API-first.** Every capability is an API before it's a UI. Internal services expose APIs. External products expose APIs. UIs consume APIs.

5. **Event-driven where possible.** Prefer asynchronous messaging over synchronous request chains. Decouple producers from consumers. Use queues and event buses.

6. **Zero-trust networking.** No implicit trust between services. Every request is authenticated and authorized. Network position grants nothing.

7. **Observability from day one.** Structured JSON logging, distributed tracing, and health check endpoints ship with every service. Not added later. Shipped at creation.

8. **Immutable deployments.** No SSH-and-fix. No hotpatching running containers. Redeploy or rollback. Every deployment is a new artifact.

9. **Venture independence.** Every venture must be independently deployable, sellable, and killable. No cross-venture runtime dependencies. No shared databases. No shared compute.

10. **Managed services over self-hosted.** One-person-company model. Minimize operational burden. Use the cloud provider's managed offering unless an ADR justifies otherwise.

11. **No unmanaged Kubernetes.** Operational overhead exceeds value for the operating model. Use managed container services (ECS, Azure Container Apps, Cloud Run).

12. **Tag everything.** Every cloud resource must be tagged with venture name and environment. No mystery spend. If a resource can't be attributed, it shouldn't exist.

---

## Enforcement

Agents treat these as hard constraints. A violation blocks the operation and requires owner escalation per CHARTER Article II.7. Exceptions require an ADR in `docs/adr/` with explicit owner approval.
