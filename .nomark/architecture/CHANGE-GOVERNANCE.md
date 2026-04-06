# Change Governance

> NOMARK Level 1 — Universal. How architecture decisions are made and evolved.
> Governs changes to Level 1 governance AND provides the process Level 2 must follow.

---

## Architecture Decision Records

ADRs are mandatory for:
- Any Tier 2 technology choice
- New pattern adoption
- Exception to any NOMARK principle
- Changes to data flow or security posture

**Format:** Context → Decision → Consequences. Under 30 lines. Use the template in `.nomark/architecture/adr/ADR-TEMPLATE.md`.

**Storage:** Venture-level ADRs in `docs/adr/`. NOMARK-level ADRs in `.nomark/architecture/adr/`.

## NOMARK-Level Changes

Changes to Level 1 governance (new principle, Tier 1 tech addition, pattern promotion) follow the Governance Board process:

1. **Propose** — Write the change as a draft ADR.
2. **Stress-test** — Run `/board` to evaluate through all five lenses.
3. **Ratify** — Owner approves. ADR status set to `accepted`.

No agent ratifies NOMARK-level changes autonomously. CHARTER Article II.7 applies.

## Pattern Promotion

1. A pattern starts in one venture as a local solution.
2. If proven effective, it gets extracted into `templates/patterns/`.
3. The extraction is a NOMARK-level change — requires Board review and owner ratification.
4. Once promoted, the pattern is available to all ventures.

Bottom-up only. No top-down pattern mandates.

## Deprecation

1. Mark the pattern, principle, or tech choice as `deprecated` in its source file.
2. Document the migration path and sunset date.
3. Agents warn when encountering deprecated items but do not block.
4. After sunset date, agents treat usage as an error.

No silent deprecation. No removing things without a migration path.

## Tech Radar Review

Quarterly. Single pass: what's working, what's not, what to trial. Changes follow the propose → stress-test → ratify flow above.
