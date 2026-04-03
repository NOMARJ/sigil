---
name: data-context-extractor
description: >
  Generate or improve a project-specific data analysis skill by extracting tribal knowledge.
  Use when someone says "create a data context skill", "set up data analysis for our warehouse",
  "help me create a skill for our database", "generate a data skill", "add context about our data",
  "the skill needs more info about our tables", or wants Claude to understand their specific
  data warehouse, terminology, metrics, and common query patterns.
---

# Data Context Extractor

Build a project-specific data skill that teaches Claude your company's data warehouse, terminology, metrics definitions, and common query patterns. Two modes:

## Bootstrap Mode

Trigger: No existing data context skill for this project.

### Process

1. **Schema Discovery**
   - If database access available: query `information_schema` or equivalent
   - If not: ask user to paste/upload schema, ERD, or table descriptions
   - Discover: tables, columns, types, relationships, row counts

2. **Tribal Knowledge Interview** (ask these questions):
   - What are the 5 most common queries your analysts run?
   - What metrics does the business track? How are they calculated?
   - What's the grain of each major table? (one row = one what?)
   - Are there any gotchas? (deleted rows not actually deleted, timezone mismatches, denormalized fields)
   - What terminology does the team use that wouldn't be obvious? (internal names, abbreviations)
   - What's the data freshness? (real-time, hourly, daily, weekly)
   - Which tables join to which? What are the common join patterns?

3. **Generate the Skill**
   Write a `data-context/SKILL.md` in the project's `.claude/skills/` (or `.nomark/data/`) containing:
   - Schema summary (tables, key columns, grain, relationships)
   - Metrics dictionary (metric name → SQL definition)
   - Common query patterns (templated SQL for frequent questions)
   - Gotchas and caveats
   - Terminology glossary
   - Data freshness expectations

## Iteration Mode

Trigger: Existing data context skill needs updating.

### Process

1. Load existing skill
2. Ask targeted questions about the gap (new table, new metric, changed business logic)
3. Update the relevant section
4. Note the change in an amendment log

## Output Format

```markdown
# Data Context — [Project Name]

## Schema Overview
| Table | Grain | Key Columns | Freshness | Notes |
|-------|-------|-------------|-----------|-------|

## Metrics Dictionary
| Metric | Definition (SQL) | Business Context |
|--------|-----------------|-----------------|

## Common Query Patterns
### [Question type]
```sql
-- Template query
```

## Gotchas
- [Gotcha 1]
- [Gotcha 2]

## Terminology
| Term | Meaning |
|------|---------|

## Amendment Log
| Date | Change | Author |
|------|--------|--------|
```

## Integration

- Read SOLUTION.md for database connection details and fixed specs
- Save generated skill to `.nomark/data/context.md` or project `.claude/skills/`
- Cross-reference with existing SQL skills for dialect compatibility
