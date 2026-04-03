# SOLUTION.md Patch: Part I.5 — Insight Registry

*Insert between Part I (Product Vision) and Part II (Solution Intent)
when the discovery pack is installed.*

```markdown
## Part I.5 — Insight Registry

*What we know about the people we're building for. Updated as evidence
surfaces — from DISCOVER runs, real conversations, analytics, support
data, or direct experience.*

*This section starts empty for new products. That's fine. It fills in
as you learn. The point is having a place for evidence to live so it
doesn't get lost in Slack threads and forgotten conversations.*

### Insight Statements

| ID | Insight | Source | Confidence | Linked Epics |
|----|---------|--------|------------|-------------|
| INS-001 | {{[Who] needs [what] because [why]}} | {{Direct experience / user interview / synthetic persona / analytics / support data}} | {{HIGH / MED / LOW}} | EP-001 |

**Confidence guide:**
- **HIGH** — Corroborated by multiple independent sources or direct experience
- **MED** — Single source or synthetic-only evidence. Working hypothesis.
- **LOW** — Inferred or assumed. Requires validation before high-stakes decisions.

*Synthetic-only evidence (from /discover) has a confidence ceiling
of MED. HIGH requires at least one real-world corroboration.*

### How Might We Questions

| ID | How Might We... | Source Insight | Consumer |
|----|----------------|---------------|----------|
| HMW-001 | {{Opportunity question}} | INS-001 | Human |
| HMW-002 | {{Opportunity question}} | INS-001 | AI Agent |

*HMW questions bridge understanding to opportunity. They are inputs
to brainstorming, not outputs of it.*

### DISCOVER Run Log

| Date | Scope | Method | Key Finding | Status |
|------|-------|--------|-------------|--------|
| {{Date}} | {{Epic or product-wide}} | {{Full DISCOVER / Quick review / Real user conversation}} | {{One-line}} | {{ACTIVE / STALE (>90 days)}} |

*If the most recent run is STALE and the product is still ACTIVE,
agents should flag this during session start.*
```

## Epic Registry Patch

*Update the existing Epic Registry to include an Evidence column:*

```markdown
| ID | Epic | Status | Target | Features | Evidence |
|----|------|--------|--------|----------|----------|
| EP-001 | {{Epic name}} | ACTIVE | {{Quarter}} | F-001, F-002 | INS-001, INS-003 |
| EP-002 | {{Epic name}} | HYPOTHESIS | {{Quarter}} | — | — (needs DISCOVER or direct experience) |
```

*Add HYPOTHESIS to Epic statuses:*

```markdown
- `HYPOTHESIS` — identified, evidence basis is assumption-only.
  Work can proceed, but Feature-level DONE requires at least one
  real-world validation data point.
```

## Traceability Rule Patch

*Update the existing traceability rule:*

```markdown
### Traceability Rule

```
Evidence → Insight (INS-XXX) → Epic (EP-XXX) → Feature (F-XXX) → Story (US-XXX) → Commit → Verification
```

Every story in progress.md must link to a Feature in SOLUTION.md.
Every Feature must link to an Epic.
Every Epic should link to at least one Insight or evidence source.
No work exists outside this hierarchy.

If an Epic has no evidence link, it is marked HYPOTHESIS.
Work can proceed, but Feature DONE criteria must include
real-world validation.
```

## Feature Acceptance Criteria Patch

*Add one line to the default Feature acceptance criteria:*

```markdown
- [ ] Evidence link exists (insight, direct experience, or HYPOTHESIS with validation plan)
```
