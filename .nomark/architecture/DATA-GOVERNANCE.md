# Data Governance

> NOMARK Level 1 — Universal. Rules for data flow across all ventures.
> Agents must enforce these rules when writing or modifying data-related code.

---

## Rules

1. **No direct database-to-database connections.** Data moves between services through APIs or event buses. Never connect one service's database to another service.

2. **Document every data flow.** Each venture maintains `docs/data-flow.md` showing how data enters, moves through, and leaves the system. Agents update this when modifying data paths.

3. **Tag PII and sensitive data at schema level.** Fields containing personal, financial, or classified data must be marked in the schema definition. Agents must respect classification when logging, caching, or exposing data.

4. **Encrypt everything.** Data at rest: encrypted. Data in transit: encrypted. No exceptions. Use cloud provider's default encryption at minimum.

5. **Venture data isolation.** Each venture owns its data exclusively. No shared databases across ventures. No cross-venture data access without an explicit API contract.

6. **Domain-owned canonical models.** Data models are defined per venture at the domain level. NOMARK does not define shared data models — each venture defines its own in `DATA-MODEL.md`.

7. **Explicit retention policies.** Every data store must have a documented retention period. No indefinite storage without owner-approved justification in an ADR.

8. **Backup and recovery.** Every venture documents its backup strategy and recovery procedure in `INFRASTRUCTURE.md`. Agents verify backup configuration exists before marking data infrastructure as complete.

---

## Enforcement

Agents check these rules when creating or modifying database schemas, API endpoints, event handlers, or data pipelines. Violations block the operation and require owner escalation.
